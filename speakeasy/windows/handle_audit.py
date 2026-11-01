# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""
Handle lifecycle auditing for resource leak triage.

Every guest-visible handle binding (open/create and close) is recorded as a
generation-scoped :class:`HandleBinding`. A handle value that gets rebound after
being closed starts a new generation, so records for the old and the new object
never share state. At run boundaries the auditor produces a per-process /
per-module / per-type tally plus the list of bindings that are still open,
including the process and module that last touched the handle.
"""

from __future__ import annotations

import ntpath
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from speakeasy.profiler import Run

HANDLE_MASK = 0xFFFFFFFF


@dataclass
class _Context:
    """Execution context captured for one audit event."""

    pid: int | None
    process_name: str | None
    tid: int | None
    module: str | None
    api: str | None
    run: int | None


@dataclass
class HandleBinding:
    """One open/close lifecycle of a single handle value (one generation)."""

    namespace: str
    handle: int
    generation: int
    object_type: str
    name: str | None

    # Owner / creation attributes
    create_seq: int
    create_run: int | None
    pid: int | None
    process_name: str | None
    module: str | None
    create_api: str | None

    # Pre-existing emulator objects (predefined HKEYs, boot desktop, ...)
    system: bool = False

    # Close attributes
    closed: bool = False
    close_seq: int | None = None
    close_run: int | None = None
    close_module: str | None = None
    close_api: str | None = None
    # The value was rebound without an explicit close (allocator anomaly)
    rebind: bool = False

    # Last holder: the most recent execution context that referenced the handle
    last_pid: int | None = None
    last_process_name: str | None = None
    last_tid: int | None = None
    last_module: str | None = None
    last_run: int | None = None
    last_seq: int | None = None


def describe_object(obj: Any) -> tuple[str, str | None]:
    """Return ``(type_name, display_name)`` for a managed resource object."""

    object_type = type(obj).__name__
    name = getattr(obj, "path", None)
    if not name:
        name = getattr(obj, "name", None)
    if isinstance(name, int):
        name = None
    if not name:
        host = getattr(obj, "connected_host", None)
        if host:
            name = f"{host}:{getattr(obj, 'connected_port', 0)}"
    if not name:
        provider = getattr(obj, "provider_name", None)
        if provider:
            name = str(provider)
    return object_type, str(name) if name else None


class HandleAuditor:
    """
    Tracks handle bindings across all resource managers and summarizes
    per-run resource usage for the emulation report.
    """

    def __init__(self, emu: Any):
        self.emu: Any = emu
        self._live: dict[tuple[str, int], HandleBinding] = {}
        self._system: set[tuple[str, int]] = set()
        self._history: list[HandleBinding] = []
        self._generations: dict[tuple[str, int], int] = {}
        self._seq: int = 0
        self._run_ordinal: int = 0

    # ------------------------------------------------------------------
    # Run boundaries
    # ------------------------------------------------------------------

    def begin_run(self, run: Run) -> None:
        """Mark the start of a run; runs are numbered in execution order."""
        self._run_ordinal += 1

    def end_run(self, run: Run) -> dict[str, Any] | None:
        """
        Attach the audit snapshot for the finished run to the run record.

        Returns the snapshot, or ``None`` when the emulation has not observed
        any guest-owned handle yet.
        """
        if not self._history:
            run.handle_audit = None
            return None
        report = self.build_run_report(self._run_ordinal)
        run.handle_audit = report
        return report

    # ------------------------------------------------------------------
    # Binding lifecycle
    # ------------------------------------------------------------------

    def created(
        self,
        namespace: str,
        handle: int | None,
        obj: Any = None,
        *,
        object_type: str | None = None,
        name: str | None = None,
        system: bool | None = None,
        api: str | None = None,
    ) -> HandleBinding | None:
        """
        Record that ``handle`` now references ``obj``.

        Reusing a handle value that was closed before starts a fresh generation;
        the previous binding stays untouched in the history.
        """
        if not handle:
            return None
        key = (namespace, int(handle) & HANDLE_MASK)
        ctx = self._context(api)
        if system is None:
            # Bindings appearing before any guest context exists belong to the
            # emulator itself (predefined keys, boot window station, ...).
            system = ctx.module is None and ctx.pid is None and not getattr(self.emu, "is_kernel_mode", False)

        generation = self._generations.get(key, 0) + 1
        self._generations[key] = generation

        if obj is not None:
            if object_type is None or name is None:
                inferred_type, inferred_name = describe_object(obj)
                object_type = object_type or inferred_type
                name = name or inferred_name
        if object_type is None:
            object_type = "Unknown"

        self._seq += 1
        binding = HandleBinding(
            namespace=namespace,
            handle=key[1],
            generation=generation,
            object_type=object_type,
            name=name,
            create_seq=self._seq,
            create_run=ctx.run,
            pid=ctx.pid,
            process_name=ctx.process_name,
            module=ctx.module,
            create_api=ctx.api,
            system=system,
        )
        # Seed holder tracking with the creating context.
        binding.last_pid = ctx.pid
        binding.last_process_name = ctx.process_name
        binding.last_tid = ctx.tid
        binding.last_module = ctx.module
        binding.last_run = ctx.run
        binding.last_seq = self._seq

        self._history.append(binding)

        if system:
            # System bindings are never closed by the guest and never leak.
            self._system.add(key)
            return binding

        previous = self._live.pop(key, None)
        if previous is not None and not previous.closed:
            # The allocator handed out a value that was still bound. Retire the
            # stale record explicitly instead of silently overwriting it.
            previous.closed = True
            previous.rebind = True
            previous.close_run = ctx.run
            previous.close_module = ctx.module
            previous.close_api = "handle_rebound"
            self._seq += 1
            previous.close_seq = self._seq

        self._live[key] = binding
        return binding

    def closed(self, namespace: str, handle: int | None, *, api: str | None = None) -> bool:
        """
        Record that the current generation of ``handle`` was closed.

        Returns whether a tracked binding was closed. Closes of pre-existing
        system objects (predefined HKEYs, ...) are accepted but not counted.
        """
        if not handle:
            return False
        key = (namespace, int(handle) & HANDLE_MASK)
        binding = self._live.pop(key, None)
        if binding is None:
            return key in self._system
        ctx = self._context(api)
        binding.closed = True
        self._seq += 1
        binding.close_seq = self._seq
        binding.close_run = ctx.run
        binding.close_module = ctx.module
        if ctx.api:
            binding.close_api = ctx.api
        return True

    def release_object(self, namespace: str, handles: list[int], *, api: str | None = None) -> None:
        """
        Close every live binding attached to an object that is being torn down
        (for example an object manager object whose reference count hit zero).
        """
        for handle in handles:
            self.closed(namespace, handle, api=api or "object_released")

    def touch(self, namespace: str, handle: int | None) -> None:
        """
        Remember the current execution context as the last holder of a handle.
        """
        if not handle:
            return
        key = (namespace, int(handle) & HANDLE_MASK)
        binding = self._live.get(key)
        if binding is None:
            return
        ctx = self._context()
        self._seq += 1
        if ctx.pid is not None:
            binding.last_pid = ctx.pid
            binding.last_process_name = ctx.process_name
        if ctx.tid is not None:
            binding.last_tid = ctx.tid
        if ctx.module:
            binding.last_module = ctx.module
        binding.last_run = ctx.run
        binding.last_seq = self._seq

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def build_run_report(self, run_ordinal: int) -> dict[str, Any]:
        """
        Build the audit snapshot attached to a run record.

        ``created``/``closed`` count lifecycle events that happened during the
        run, attributed to the owning process/module; ``remaining`` counts
        bindings that are still open when the run ends.
        """
        rows: dict[tuple[Any, ...], dict[str, Any]] = {}

        def row_for(binding: HandleBinding) -> dict[str, Any]:
            key = (binding.pid, binding.process_name, binding.module, binding.object_type)
            row = rows.get(key)
            if row is None:
                row = {
                    "process_id": binding.pid,
                    "process_name": binding.process_name,
                    "module": binding.module,
                    "object_type": binding.object_type,
                    "created": 0,
                    "closed": 0,
                    "remaining": 0,
                }
                rows[key] = row
            return row

        created_count = 0
        closed_count = 0

        for binding in self._history:
            if binding.system:
                continue
            if binding.create_run == run_ordinal:
                row_for(binding)["created"] += 1
                created_count += 1
            if binding.closed and binding.close_run == run_ordinal:
                row_for(binding)["closed"] += 1
                closed_count += 1

        for binding in self._live.values():
            row_for(binding)["remaining"] += 1

        def sort_key(key):
            return (key[0] is None, key[0] or 0, key[1] or "", key[2] or "", key[3])

        summary = [rows[key] for key in sorted(rows, key=sort_key)]

        unclosed: list[dict[str, Any]] = []
        for binding in self._live.values():
            unclosed.append(
                {
                    "namespace": binding.namespace,
                    "handle": binding.handle,
                    "generation": binding.generation,
                    "object_type": binding.object_type,
                    "name": binding.name,
                    "process_id": binding.pid,
                    "process_name": binding.process_name,
                    "owner_module": binding.module,
                    "last_holder_process_id": binding.last_pid if binding.last_pid is not None else binding.pid,
                    "last_holder_process_name": binding.last_process_name or binding.process_name,
                    "last_holder_module": binding.last_module or binding.module,
                    "last_holder_thread_id": binding.last_tid,
                    "opened_in_run": binding.create_run,
                    "create_api": binding.create_api,
                }
            )
        unclosed.sort(key=lambda b: (b["process_id"] is None, b["process_id"] or 0, b["object_type"], b["handle"]))

        return {
            "created": created_count,
            "closed": closed_count,
            "remaining": len(self._live),
            "summary": summary,
            "unclosed": unclosed,
        }

    # ------------------------------------------------------------------
    # Context capture
    # ------------------------------------------------------------------

    def _context(self, api: str | None = None) -> _Context:
        emu = self.emu
        proc = None
        thread = None
        try:
            proc = emu.get_current_process()
        except Exception:
            proc = None
        try:
            thread = emu.get_current_thread()
        except Exception:
            thread = None

        module = None
        try:
            # Dispatch records the guest call site; prev_pc covers registered
            # traps in other contexts. Both fall back to the current PC.
            call_pc = getattr(emu, "_audit_call_pc", 0) or 0
            prev_pc = getattr(emu, "prev_pc", 0) or 0
            pc = call_pc or prev_pc or emu.get_pc()
            mod = emu.get_module_from_addr(pc)
            if mod is not None:
                module = getattr(mod, "name", None) or ntpath.basename(getattr(mod, "emu_path", "") or "") or None
        except Exception:
            module = None

        if api is None:
            api = getattr(emu, "_audit_api_name", None)
        if api is None:
            frame = getattr(emu, "_active_api_frame", None)
            event = getattr(frame, "event", None) if frame is not None else None
            api = getattr(event, "api_name", None)

        pid = getattr(proc, "id", None)
        process_name = None
        if proc is not None:
            process_name = (
                getattr(proc, "name", None)
                or ntpath.basename(getattr(proc, "path", "") or "")
                or getattr(proc, "image", None)
                or None
            )
        elif getattr(emu, "is_kernel_mode", False):
            process_name = "Kernel"

        tid = getattr(thread, "tid", None)
        return _Context(
            pid=pid,
            process_name=process_name,
            tid=tid,
            module=module,
            api=api,
            run=self._run_ordinal or None,
        )
