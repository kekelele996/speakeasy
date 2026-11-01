"""Load images and their dependencies, and track the DLLs whose initializers still have to run."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any, Literal

from speakeasy.profiler_events import ModuleLoadEvent, TracePosition
from speakeasy.windows.loaders import InitRoutine, LoadState, RuntimeModule

if TYPE_CHECKING:
    from speakeasy.profiler import GuestCallbackFrame, Run
    from speakeasy.windows.winemu import WindowsEmulator

logger = logging.getLogger(__name__)

PebModuleSnapshot = list[tuple[Any, dict[int, RuntimeModule]]]

# Only images loaded from a sample file get a lifecycle trail. Synthetic API
# modules and shellcode never initialize or unload, so tracking them would add
# noise without answering why a sample library failed.
GUEST_IMAGE_SOURCE = "guest_pe"

LifecycleAction = Literal["map", "peb_add", "peb_remove", "init", "unmap"]
CallbackKind = Literal["tls_callback", "dll_entry"]
InitStatus = Literal["success", "returned_false", "faulted", "canceled"]


class ModuleLoader:
    """
    Load images and their dependencies, and keep the data of the loader: the IAT
    entries that the loader bound, the DLLs that each process has in its PEB by
    default, and the DLLs whose DllMain and TLS callbacks must run. Record the
    result of each callback.

    WindowsEmulator._load_image maps one image, and the emulator keeps the module
    list. If a load fails, or a DllMain returns FALSE, this class removes what the
    load added.

    Beyond that, this class records the lifecycle of each guest image as
    ``module_load`` events in the timeline of the run that made the change:
    mapping, per-process PEB attach/detach, initializer results and unmapping.
    Events produced before the first run exists are flushed into that run when it
    is prepared.
    """

    def __init__(self, emu: WindowsEmulator) -> None:
        self.emu: WindowsEmulator = emu
        self.guest_dependencies: list[RuntimeModule] = []
        self.shared_peb_modules: set[int] = set()
        self.import_bindings: dict[int, int] = {}
        self._load_depth: int = 0
        # Modules currently inside _load_image: the innermost one is the parent
        # whose import table pulls a nested dependency.
        self._mapping_stack: list[RuntimeModule] = []
        # Trigger/requested_by of the load in progress, used when the map event
        # is emitted as soon as the image exists.
        self._current_trigger: tuple[str | None, str | None] | None = None
        # Lifecycle events waiting for the first run to attach them to.
        self._pending_lifecycle: list[ModuleLoadEvent] = []
        # Cause attributed to PEB removals performed by the rollback in progress.
        self._peb_remove_reason: str | None = None

    def _get_processes(self) -> list[Any]:
        # Do not call emu.get_processes(), because it can create the configured processes
        emu = self.emu
        processes = list(emu.processes)
        if emu.curr_process is not None and emu.curr_process not in processes:
            processes.append(emu.curr_process)
        return processes

    def _remove_from_active_pebs(self, module: RuntimeModule) -> None:
        for process in self._get_processes():
            if process.is_peb_active and self.emu.get_address_map(process.peb_ldr_data.address):
                process.remove_module_from_peb(module)

    # ------------------------------------------------------------------
    # Lifecycle telemetry
    # ------------------------------------------------------------------

    def begin_mapping(self, module: RuntimeModule) -> None:
        """Mark that an image is mapping, so nested loads attribute to its imports."""
        self._mapping_stack.append(module)

    def end_mapping(self) -> None:
        self._mapping_stack.pop()

    @contextlib.contextmanager
    def mapping_module(self, module: RuntimeModule) -> Iterator[None]:
        self.begin_mapping(module)
        try:
            yield
        finally:
            self.end_mapping()

    @contextlib.contextmanager
    def peb_removal_reason(self, reason: str) -> Iterator[None]:
        """Attribute the PEB removals of the wrapped rollback to one cause."""
        previous = self._peb_remove_reason
        self._peb_remove_reason = reason
        try:
            yield
        finally:
            self._peb_remove_reason = previous

    def _position(self, run: Any = None, *, pid: int | None = None, pc: int | None = None) -> TracePosition:
        emu = self.emu
        run = run if run is not None else emu.curr_run
        if run is not None:
            thread = run.thread or emu.curr_thread
            process = run.process_context or (thread.process if thread else None) or emu.curr_process
            tid = thread.tid if thread else 0
            effective_pid = pid if pid is not None else (process.id if process else 0)
            return TracePosition(tick=run.instr_cnt, tid=tid, pid=effective_pid, pc=pc)
        thread = emu.curr_thread
        process = emu.curr_process
        effective_pid = pid if pid is not None else (process.id if process else 0)
        return TracePosition(tick=0, tid=thread.tid if thread else 0, pid=effective_pid, pc=pc)

    def _emit(self, event: ModuleLoadEvent, run: Any = None) -> None:
        if not self.emu.profiler:
            return
        target = run if run is not None else self.emu.curr_run
        if target is not None:
            target.events.append(event)
        else:
            self._pending_lifecycle.append(event)

    def flush_lifecycle_events(self, run: Run) -> None:
        """Attach the events emitted before the first run existed to that run."""
        if self._pending_lifecycle:
            run.events.extend(self._pending_lifecycle)
            self._pending_lifecycle.clear()

    @staticmethod
    def _module_label(module: RuntimeModule) -> str:
        return module.name or module.get_base_name()

    def _event(
        self,
        module: RuntimeModule,
        action: LifecycleAction,
        *,
        run: Any = None,
        pid: int | None = None,
        reason: str | None = None,
        requested_by: str | None = None,
        callback: CallbackKind | None = None,
        status: InitStatus | None = None,
        pc: int | None = None,
    ) -> ModuleLoadEvent:
        return ModuleLoadEvent(
            pos=self._position(run, pid=pid, pc=pc),
            action=action,
            name=self._module_label(module),
            path=module.emu_path,
            base=hex(module.base),
            size=hex(module.image_size),
            pid=pid,
            reason=reason,
            requested_by=requested_by,
            callback=callback,
            status=status,
        )

    def _current_pid(self) -> int | None:
        process = self.emu.get_current_process()
        return process.id if process is not None else None

    def record_map(
        self,
        module: RuntimeModule,
        *,
        trigger: str | None = None,
        requested_by: str | None = None,
        run: Any = None,
    ) -> None:
        """Record that an image was mapped, naming what action pulled it in."""
        if module.source != GUEST_IMAGE_SOURCE:
            return
        if not trigger:
            if self._mapping_stack:
                trigger = "static_import"
                parent = self._mapping_stack[-1]
                if requested_by is None:
                    requested_by = self._module_label(parent)
            else:
                trigger = "explicit"
        self._emit(
            self._event(
                module,
                "map",
                run=run,
                pid=self._current_pid(),
                reason=trigger,
                requested_by=requested_by,
            ),
            run,
        )

    def record_current_map(self, module: RuntimeModule) -> None:
        """Record the map of the image that _load_image is bringing up."""
        trigger, requested_by = self._current_trigger or (None, None)
        self.record_map(module, trigger=trigger, requested_by=requested_by)

    def record_peb_change(
        self,
        process: Any,
        module: RuntimeModule,
        *,
        added: bool,
        reason: str | None = None,
    ) -> None:
        """Record that an image entered or left the loader lists of one process."""
        if module.source != GUEST_IMAGE_SOURCE:
            return
        if not added and reason is None:
            reason = self._peb_remove_reason
        self._emit(
            self._event(
                module,
                "peb_add" if added else "peb_remove",
                pid=process.id,
                reason=reason,
            )
        )

    def record_init(self, routine: InitRoutine, status: InitStatus, *, run: Any = None) -> None:
        """Record the result of one TLS callback or DllMain in one process."""
        module = routine.module
        if module.source != GUEST_IMAGE_SOURCE:
            return
        callback: CallbackKind = "dll_entry" if routine.is_entry_point else "tls_callback"
        self._emit(
            self._event(
                module,
                "init",
                run=run,
                pid=routine.pid,
                callback=callback,
                status=status,
                pc=routine.address,
            ),
            run,
        )

    def record_unmap(self, module: RuntimeModule, *, reason: str, run: Any = None) -> None:
        """Record that an image was unmapped and what caused it."""
        if module.source != GUEST_IMAGE_SOURCE:
            return
        self._emit(self._event(module, "unmap", run=run, reason=reason), run)

    # ------------------------------------------------------------------
    # Loading and rollback
    # ------------------------------------------------------------------

    def load_image(
        self,
        image: Any,
        base: int | None = None,
        *,
        is_input: bool = False,
        trigger: str | None = None,
        requested_by: str | None = None,
    ) -> RuntimeModule:
        """Load an image and its dependencies. If the load fails, remove what it added."""
        emu = self.emu
        outer = not self._load_depth
        if outer:
            original_modules = list(emu.modules)
            original_maps = {id(mapping) for mapping in emu.maps}
            original_bindings = dict(self.import_bindings)
            original_shared = set(self.shared_peb_modules)
            original_peb_modules = self.snapshot_peb_modules()
        self._load_depth += 1
        previous_trigger = self._current_trigger
        self._current_trigger = (trigger, requested_by)
        try:
            module: RuntimeModule = emu._load_image(image, base, is_input=is_input)
        except Exception:
            if outer:
                removed = [module for module in emu.modules if module not in original_modules]
                with self.peb_removal_reason("load_failed"):
                    for module in reversed(removed):
                        self._remove_from_active_pebs(module)
                        emu.api_registry.unregister_module(module)
                    self.rollback_peb_modules(original_peb_modules)
                emu.modules[:] = original_modules
                self.import_bindings = original_bindings
                self.shared_peb_modules = original_shared
                self.guest_dependencies[:] = [
                    module for module in self.guest_dependencies if module in original_modules
                ]
                for mapping in tuple(emu.maps):
                    if id(mapping) not in original_maps and (mapping.tag or "").startswith("emu.module."):
                        emu.mem_unmap(mapping.base, mapping.size)
                        emu.maps.remove(mapping)
                for module in reversed(removed):
                    self.record_unmap(module, reason="load_failed")
            raise
        finally:
            self._load_depth -= 1
            self._current_trigger = previous_trigger
        if outer:
            self.notify_module_change()
        return module

    def notify_module_change(self) -> None:
        """Call the module change listeners. A listener that fails does not stop the others."""
        for listener in tuple(self.emu.module_change_listeners):
            try:
                listener()
            except Exception:
                logger.exception("module change listener failed: %r", listener)

    def discard_module(self, module: RuntimeModule, *, reason: str = "unload") -> None:
        emu = self.emu
        with self.peb_removal_reason(reason):
            self._remove_from_active_pebs(module)
        emu.api_registry.unregister_module(module)
        self.shared_peb_modules.discard(module.base)
        if module in emu.modules:
            emu.modules.remove(module)
        if module in self.guest_dependencies:
            self.guest_dependencies.remove(module)
        mapping = emu.get_address_map(module.base)
        if mapping is not None:
            emu.mem_unmap(mapping.base, mapping.size)
            emu.maps.remove(mapping)
        self.import_bindings = {
            address: target
            for address, target in self.import_bindings.items()
            if not module.base <= address < module.base + module.image_size
        }
        self.record_unmap(module, reason=reason)
        self.notify_module_change()

    def snapshot_peb_modules(self) -> PebModuleSnapshot:
        return [(process, dict(process.peb_modules)) for process in self._get_processes()]

    def rollback_peb_modules(self, snapshot: PebModuleSnapshot) -> None:
        for process, original in snapshot:
            for base, module in tuple(process.peb_modules.items()):
                if base not in original:
                    process.remove_module_from_peb(module)

    def remove_failed_module_from_peb(self, module: RuntimeModule, pid: int) -> None:
        """Remove the module from one process after its initialization failed. Other processes keep it."""
        module.load_states.pop(pid, None)
        with self.peb_removal_reason("init_failed"):
            for process in self._get_processes():
                if process.id == pid:
                    process.remove_module_from_peb(module)

    def rollback_guest_load(self, frame: GuestCallbackFrame, run: Any = None) -> None:
        # Remove the modules that the load added to processes. Unmap a new image
        # only if no process has it. Do not unmap older images.
        # Classify the callbacks that never reported a result first, because all
        # callbacks of a module in one process share its load state.
        interrupted: list[InitRoutine] = [
            routine
            for routine in frame.initializers.values()
            if routine.module.load_states.get(routine.pid) is LoadState.INITIALIZING
            and routine.address not in frame.completed_initializers
        ]
        faulting = frame.function
        for routine in interrupted:
            faulted = run is not None and run.error is not None and routine.address == faulting
            self.record_init(routine, "faulted" if faulted else "canceled", run=run)
        with self.peb_removal_reason("init_failed"):
            self.rollback_peb_modules(frame.peb_module_snapshot)
            original = {process.id: modules for process, modules in frame.peb_module_snapshot}
            for routine in frame.initializers.values():
                module, pid = routine.module, routine.pid
                if module.load_states.get(pid) is LoadState.INITIALIZING or module.base not in original.get(pid, {}):
                    module.load_states.pop(pid, None)
            for module in reversed(frame.created_modules):
                if not any(module.base in process.peb_modules for process in self._get_processes()):
                    self.discard_module(module, reason="init_failed")
        frame.pending[:] = [(function, args) for function, args in frame.pending if function not in frame.initializers]
        frame.initializers.clear()
        frame.created_modules.clear()
        frame.peb_module_snapshot = []

    def finish_initializer(
        self,
        routine: InitRoutine,
        return_value: int,
        faulted: bool = False,
        run: Any = None,
    ) -> bool:
        """
        Record the end of an initializer, and return True if it succeeded.

        A DllMain fails if it faults, or if the low byte of its result is zero.
        The Windows loader reads the BOOL result as a BOOLEAN. A TLS callback fails
        only if it faults. When the last initializer of a module succeeds, set the
        state of the module to READY_TO_RUN.
        """
        status: InitStatus
        if faulted:
            status = "faulted"
        elif routine.is_entry_point and not return_value & 0xFF:
            status = "returned_false"
        else:
            status = "success"
        self.record_init(routine, status, run=run)
        if status != "success":
            return False
        if routine.is_last:
            routine.module.load_states[routine.pid] = LoadState.READY_TO_RUN
        return True

    def cancel_initializers(self, routines: Iterable[InitRoutine], run: Any = None) -> None:
        """
        Clear the INITIALIZING state of initializers that will not run.
        A later load of the module runs them again.
        """
        for routine in routines:
            if routine.module.load_states.get(routine.pid) is LoadState.INITIALIZING:
                routine.module.load_states.pop(routine.pid)
                self.record_init(routine, "canceled", run=run)

    def collect_initializers(self) -> list[InitRoutine]:
        """
        Get the DllMain and TLS callbacks of the DLLs that the current process has
        not initialized. Set the state of these DLLs to INITIALIZING.
        """
        process = self.emu.get_current_process()
        if process is None:
            return []
        result = []
        for module in self.guest_dependencies:
            if (
                module not in self.emu.modules
                or module.base not in process.peb_modules
                or process.id in module.load_states
            ):
                continue
            module.load_states[process.id] = LoadState.INITIALIZING
            functions = [(function, False) for function in module.get_tls_callbacks()]
            if module.ep:
                functions.append((module.base + module.ep, True))
            if not functions:
                module.load_states[process.id] = LoadState.READY_TO_RUN
            for index, (function, is_entry_point) in enumerate(functions):
                result.append(InitRoutine(module, function, is_entry_point, index == len(functions) - 1, process.id))
        return result
