# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Before/after change tracking for emulated files and registry state.

The emulator keeps file and registry state in memory while a sample runs.
``ChangeTracker`` snapshots that state right before emulated code starts,
produces a before/after comparison at run end, and can roll the emulated
filesystem and registry back to the snapshot without touching the profiler
records (events, dropped files and the report).
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import TYPE_CHECKING, Any, Literal, cast

from speakeasy.artifacts import MAX_EMBEDDED_FILE_SIZE
from speakeasy.report import (
    ChangeReport,
    FileChange,
    RegistryKeyChange,
    RegistryValueChange,
    RollbackFailure,
    RollbackResult,
)
from speakeasy.windows.fileman import File, get_path_key
from speakeasy.windows.regman import (
    HKEY_CLASSES_ROOT,
    HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE,
    HKEY_USERS,
    RegValue,
)
from speakeasy.winenv.defs.registry import reg as regdefs

if TYPE_CHECKING:
    from speakeasy.artifacts import ArtifactStore
    from speakeasy.windows.fileman import FileManager
    from speakeasy.windows.regman import RegistryManager

logger = logging.getLogger(__name__)

CHANGE_CREATED: Literal["created"] = "created"
CHANGE_OVERWRITTEN: Literal["overwritten"] = "overwritten"
CHANGE_DELETED: Literal["deleted"] = "deleted"

ROOT_HKEYS = (HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _value_to_json(data: Any) -> str | int | None:
    """Render a normalized RegValue data payload for JSON output."""
    if isinstance(data, bytes):
        # REG_BINARY payloads are normalized to base64 ascii bytes in RegValue.
        return data.decode("ascii")
    return cast("str | int | None", data)


class ChangeTracker:
    """Holds the pre-run baseline and computes diffs and rollbacks against it."""

    def __init__(self) -> None:
        self._baseline_files: dict[str, tuple[str, bytes]] | None = None
        self._baseline_deleted_files: set[str] = set()
        # key path lower -> ordered (value name lower wins first) value rows
        self._baseline_key_values: dict[str, list[tuple[str, int, Any, str]]] = {}
        self._baseline_keys: dict[str, str] = {}
        self._baseline_live_keys: set[str] = set()
        self._armed: bool = False

    @property
    def armed(self) -> bool:
        return self._armed

    def arm(
        self,
        fileman: FileManager | None,
        regman: RegistryManager | None,
        *,
        force: bool = False,
    ) -> None:
        """Capture the pre-run baseline. Later calls are no-ops unless forced."""
        if self._armed and not force:
            return
        if fileman is not None:
            self._baseline_files, self._baseline_deleted_files = self._snapshot_files(fileman)
        else:
            self._baseline_files = {}
            self._baseline_deleted_files = set()
        if regman is not None:
            self._baseline_key_values, self._baseline_keys, self._baseline_live_keys = self._snapshot_registry(regman)
        else:
            self._baseline_key_values = {}
            self._baseline_keys = {}
            self._baseline_live_keys = set()
        self._armed = True

    # ------------------------------------------------------------------
    # Snapshotting
    # ------------------------------------------------------------------

    def _materialize_config_entry(self, fileman: FileManager, path: str, entry: Any) -> bytes | None:
        try:
            return File(fileman.emu.handle_allocator, path, config=entry).get_contents()
        except Exception:
            logger.debug("could not materialize configured file %r", path, exc_info=True)
            return None

    def _logical_files(self, fileman: FileManager) -> dict[str, tuple[str, bytes]]:
        """
        Enumerate the files that logically exist, mirroring how the emulated
        program sees the filesystem:

        - configured modules exist with no readable content
        - exact full_path config entries exist with their configured bytes
        - wildcard/by_ext/default handlers serve content for opened paths
        - live files (created, opened or written) override all of the above

        Deleted paths are removed, matching FileManager.get_emu_file. The same
        enumeration backs the baseline snapshot and the final state, so merely
        reading a pre-existing file never shows up as a change.
        """
        files: dict[str, tuple[str, bytes]] = {}

        modules = list(fileman.config.modules.user_modules) + list(fileman.config.modules.system_modules)
        for module in modules:
            if not module.path:
                continue
            full = fileman.get_full_path(module.path)
            files.setdefault(get_path_key(full), (full, b""))

        for entry in fileman.file_config.files:
            mode = getattr(entry, "mode", None)
            emu_path = getattr(entry, "emu_path", None)
            if mode != "full_path" or not emu_path or any(ch in emu_path for ch in "*?[]"):
                continue
            full = fileman.get_full_path(emu_path)
            key = get_path_key(full)
            if key in files:
                continue
            data = self._materialize_config_entry(fileman, full, entry)
            if data is not None:
                files[key] = (full, data)

        for f in fileman.files:
            if type(f) is not File:
                continue
            full = fileman.get_full_path(f.path)
            key = get_path_key(full)
            if key not in files and f.config:
                # Opened through a wildcard full_path, by_ext or default
                # handler: the path existed and served this content.
                data = self._materialize_config_entry(fileman, full, f.config)
                if data is not None:
                    files[key] = (full, data)
            # Live contents win: this is what a final read of the path returns.
            files[key] = (full, f.get_contents())

        for key in fileman.deleted_paths:
            files.pop(key, None)

        return files

    def _snapshot_files(self, fileman: FileManager) -> tuple[dict[str, tuple[str, bytes]], set[str]]:
        return self._logical_files(fileman), set(fileman.deleted_paths)

    def _snapshot_registry(
        self, regman: RegistryManager
    ) -> tuple[dict[str, list[tuple[str, int, Any, str]]], dict[str, str], set[str]]:
        key_values: dict[str, list[tuple[str, int, Any, str]]] = {}
        key_paths: dict[str, str] = {}
        live_keys: set[str] = set()

        def consume(path: str, values: list[RegValue]) -> None:
            key_lower = path.lower()
            key_paths.setdefault(key_lower, path)
            rows = key_values.setdefault(key_lower, [])
            seen: set[str] = set()
            for value in values:
                name = value.get_name()
                name_lower = name.lower()
                if name_lower in seen:
                    continue
                seen.add(name_lower)
                rows.append((name, value.get_type(), value.get_data(), path))

        for key in regman.keys:
            live_keys.add(key.get_path().lower())
            consume(key.get_path(), key.get_values())

        # Config-defined keys exist even before the sample opens one.
        if regman.config:
            for entry in regman.config.keys:
                if entry.path.lower() in key_paths:
                    continue
                key = regman.get_key_from_config(entry.path)
                if key is not None:
                    consume(key.get_path(), key.get_values())

        return key_values, key_paths, live_keys

    def _current_files(self, fileman: FileManager) -> dict[str, tuple[str, bytes]]:
        return self._logical_files(fileman)

    def _current_registry(
        self, regman: RegistryManager
    ) -> tuple[dict[str, list[tuple[str, int, Any, str]]], dict[str, str]]:
        key_values: dict[str, list[tuple[str, int, Any, str]]] = {}
        key_paths: dict[str, str] = {}

        for key in regman.keys:
            path = key.get_path()
            key_paths[path.lower()] = path
            rows: list[tuple[str, int, Any, str]] = []
            seen: set[str] = set()
            for value in key.get_values():
                name = value.get_name()
                if name.lower() in seen:
                    continue
                seen.add(name.lower())
                rows.append((name, value.get_type(), value.get_data(), path))
            key_values[path.lower()] = rows

        # Values of config keys the sample never opened still exist, so they
        # are not "deleted".
        if regman.config:
            for entry in regman.config.keys:
                key_lower = entry.path.lower()
                if key_lower in key_paths:
                    continue
                key = regman.get_key_from_config(entry.path)
                if key is None:
                    continue
                key_paths[key_lower] = key.get_path()
                rows = []
                for value in key.get_values():
                    rows.append((value.get_name(), value.get_type(), value.get_data(), key.get_path()))
                key_values[key_lower] = rows

        return key_values, key_paths

    # ------------------------------------------------------------------
    # Change report
    # ------------------------------------------------------------------

    def build_change_report(
        self,
        fileman: FileManager,
        regman: RegistryManager,
        artifact_store: ArtifactStore | None = None,
    ) -> ChangeReport:
        """Build the before/after comparison against the captured baseline."""
        if not self._armed:
            self.arm(fileman, regman)

        report = ChangeReport()
        assert self._baseline_files is not None
        baseline = self._baseline_files
        current = self._current_files(fileman)

        def embed(data: bytes) -> str | None:
            if not artifact_store or not data or len(data) > MAX_EMBEDDED_FILE_SIZE:
                return None
            return artifact_store.put_bytes(data)

        for key, (path, after) in current.items():
            if key not in baseline:
                report.files_created.append(
                    FileChange(
                        change=CHANGE_CREATED,
                        path=path,
                        size_after=len(after),
                        sha256_after=_hash(after),
                        after_data_ref=embed(after),
                    )
                )
            elif baseline[key][1] != after:
                before = baseline[key][1]
                report.files_overwritten.append(
                    FileChange(
                        change=CHANGE_OVERWRITTEN,
                        path=path,
                        size_before=len(before),
                        size_after=len(after),
                        sha256_before=_hash(before),
                        sha256_after=_hash(after),
                        before_data_ref=embed(before),
                        after_data_ref=embed(after),
                    )
                )

        for key, (path, before) in baseline.items():
            if key in current:
                continue
            report.files_deleted.append(
                FileChange(
                    change=CHANGE_DELETED,
                    path=path,
                    size_before=len(before),
                    sha256_before=_hash(before),
                    before_data_ref=embed(before),
                )
            )

        current_values, _current_key_paths = self._current_registry(regman)
        live_now = {k.get_path().lower() for k in regman.keys}
        # Keys live now that neither the baseline nor the config knew about.
        created_keys = [
            reg_key
            for reg_key in regman.keys  # only materialized keys can be "created"
            if reg_key.get_path().lower() not in self._baseline_keys
        ]
        for reg_key in sorted(created_keys, key=lambda k: k.get_path().lower()):
            report.registry_keys_created.append(
                RegistryKeyChange(change=CHANGE_CREATED, path=reg_key.get_path())
            )
        deleted_keys = sorted(self._baseline_live_keys - live_now)
        for kl in deleted_keys:
            report.registry_keys_deleted.append(RegistryKeyChange(change=CHANGE_DELETED, path=self._baseline_keys[kl]))
        deleted_key_set = set(deleted_keys)

        def value_rows(
            rows: dict[str, list[tuple[str, int, Any, str]]],
        ) -> dict[tuple[str, str], tuple[str, str, int, Any]]:
            indexed: dict[tuple[str, str], tuple[str, str, int, Any]] = {}
            for kl, entries in rows.items():
                for name, vtype, data, path in entries:
                    indexed.setdefault((kl, name.lower()), (path, name, vtype, data))
            return indexed

        before_index = value_rows(self._baseline_key_values)
        after_index = value_rows(current_values)

        for sk in sorted(after_index):
            path, name, vtype, data = after_index[sk]
            if sk[0] in deleted_key_set:
                continue
            old = before_index.get(sk)
            if old is None:
                report.registry_values_created.append(
                    RegistryValueChange(
                        change=CHANGE_CREATED,
                        key_path=path,
                        value_name=name,
                        type_after=vtype,
                        data_after=_value_to_json(data),
                    )
                )
            elif (old[2], old[3]) != (vtype, data):
                report.registry_values_overwritten.append(
                    RegistryValueChange(
                        change=CHANGE_OVERWRITTEN,
                        key_path=path,
                        value_name=name,
                        type_before=old[2],
                        type_after=vtype,
                        data_before=_value_to_json(old[3]),
                        data_after=_value_to_json(data),
                    )
                )

        for sk in sorted(before_index):
            if sk in after_index or sk[0] in deleted_key_set:
                continue
            path, name, vtype, data = before_index[sk]
            report.registry_values_deleted.append(
                RegistryValueChange(
                    change=CHANGE_DELETED,
                    key_path=path,
                    value_name=name,
                    type_before=vtype,
                    data_before=_value_to_json(data),
                )
            )

        return report

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self, fileman: FileManager, regman: RegistryManager) -> RollbackResult:
        """Restore emulated files and registry to the captured baseline.

        The profiler and its observation records are never touched. Every
        item is restored independently; failures are collected instead of
        aborting the rollback.
        """
        result = RollbackResult()
        if not self._armed:
            return result

        assert self._baseline_files is not None
        result.files_restored = self._rollback_files(fileman, result)
        keys_restored, values_restored = self._rollback_registry(regman, result)
        result.registry_keys_restored = keys_restored
        result.registry_values_restored = values_restored
        return result

    def _rollback_files(self, fileman: FileManager, result: RollbackResult) -> int:
        assert self._baseline_files is not None
        baseline = self._baseline_files
        current = self._current_files(fileman)

        created = set(current) - set(baseline)
        deleted = set(baseline) - set(current)
        overwritten = {key for key in set(current) & set(baseline) if current[key][1] != baseline[key][1]}
        restored = 0
        # Deletions whose restore failed stay marked deleted, so a later
        # rollback retries them instead of treating the config entry as
        # having come back to life.
        still_deleted: set[str] = set()

        # Revert or restore every baseline path, each independently.
        for key in sorted(deleted | overwritten):
            path, data = baseline[key]
            try:
                self._restore_file_contents(fileman, key, data)
            except Exception as err:
                result.failures.append(
                    RollbackFailure(kind="file", path=path, error=f"could not restore contents: {err}")
                )
                if key in deleted:
                    still_deleted.add(key)
                continue
            restored += 1

        # Remove files the run created.
        if created:
            try:
                self._remove_created_files(fileman, created)
            except Exception:
                # Per-item removal so one failure still reports the others.
                for key in sorted(created):
                    try:
                        self._remove_created_files(fileman, {key})
                        restored += 1
                    except Exception as item_err:
                        result.failures.append(
                            RollbackFailure(
                                kind="file",
                                path=current[key][0],
                                error=f"could not remove created file: {item_err}",
                            )
                        )
            else:
                restored += len(created)

        fileman.deleted_paths = set(self._baseline_deleted_files) | still_deleted
        return restored

    def _file_objects(self, fileman: FileManager) -> dict[str, set[File]]:
        objects: dict[str, set[File]] = {}

        def note(obj: Any) -> None:
            if type(obj) is not File:
                return
            key = get_path_key(fileman.get_full_path(obj.path))
            objects.setdefault(key, set()).add(obj)

        for f in fileman.files:
            note(f)
        for f in fileman.file_handles.values():
            note(f)
        for fmap in fileman.file_maps.values():
            note(fmap.backed_file)
        return objects

    def _restore_file_contents(self, fileman: FileManager, key: str, data: bytes) -> None:
        objects = self._file_objects(fileman).get(key, set())
        if not objects:
            path = self._baseline_files[key][0]  # type: ignore[index]
            recreated = fileman.add_existing_file(path, data)
            objects = {recreated}

        rewritten_buffers: set[int] = set()
        for obj in objects:
            buf = obj.get_buffer()
            if id(buf) not in rewritten_buffers:
                buf.seek(0)
                buf.truncate()
                buf.write(data)
                rewritten_buffers.add(id(buf))
            obj.pos = 0

    def _remove_created_files(self, fileman: FileManager, keys: set[str]) -> None:
        fileman.files = [
            f for f in fileman.files if type(f) is not File or get_path_key(fileman.get_full_path(f.path)) not in keys
        ]
        for handle, obj in list(fileman.file_handles.items()):
            if type(obj) is File and get_path_key(fileman.get_full_path(obj.path)) in keys:
                del fileman.file_handles[handle]
        for fmap in fileman.file_maps.values():
            backed = fmap.backed_file
            if type(backed) is File and get_path_key(fileman.get_full_path(backed.path)) in keys:
                fmap.backed_file = None

    def _rollback_registry(self, regman: RegistryManager, result: RollbackResult) -> tuple[int, int]:
        current_values, _ = self._current_registry(regman)
        before_index: dict[tuple[str, str], tuple[str, str, int, Any]] = {}
        for kl, entries in self._baseline_key_values.items():
            for name, vtype, data, path in entries:
                before_index.setdefault((kl, name.lower()), (path, name, vtype, data))
        after_index: dict[tuple[str, str], tuple[str, str, int, Any]] = {}
        for kl, entries in current_values.items():
            for name, vtype, data, path in entries:
                after_index.setdefault((kl, name.lower()), (path, name, vtype, data))

        created_key_set = {k.get_path().lower() for k in regman.keys} - set(self._baseline_keys)
        live_now = {k.get_path().lower() for k in regman.keys}
        deleted_key_set = self._baseline_live_keys - live_now

        failed_keys: set[str] = set()
        keys_restored = 0

        # Recreate keys the run deleted. Config-only keys stay virtual and are
        # not materialized here.
        for kl in sorted(deleted_key_set):
            display = self._baseline_keys[kl]
            try:
                regman.create_key(display)
                keys_restored += 1
            except Exception as err:
                failed_keys.add(kl)
                result.failures.append(
                    RollbackFailure(kind="registry_key", path=display, error=f"could not recreate key: {err}")
                )

        # Restore values of every live key present in the baseline, including
        # config keys the sample opened and keys just recreated above.
        for key in list(regman.keys):
            kl = key.get_path().lower()
            if kl not in self._baseline_key_values or kl in failed_keys:
                continue
            display = self._baseline_keys.get(kl, key.get_path())
            try:
                key.values = [self._make_reg_value(row) for row in self._baseline_key_values[kl]]
            except Exception as err:
                failed_keys.add(kl)
                result.failures.append(
                    RollbackFailure(kind="registry_key", path=display, error=f"could not restore values: {err}")
                )

        # Remove keys the run created.
        for key in [k for k in regman.keys if k.get_path().lower() in created_key_set]:
            path = key.get_path()
            try:
                if key in regman.keys:
                    regman.keys.remove(key)
                for handle, owned in list(regman.reg_handles.items()):
                    if owned is key and handle not in ROOT_HKEYS:
                        del regman.reg_handles[handle]
                keys_restored += 1
            except Exception as err:
                failed_keys.add(path.lower())
                result.failures.append(
                    RollbackFailure(kind="registry_key", path=path, error=f"could not remove created key: {err}")
                )

        # Verify each changed value row and report the exact ones still wrong.
        values_restored = 0
        changed_rows = set(after_index) ^ set(before_index)
        changed_rows |= {
            sk
            for sk in set(after_index) & set(before_index)
            if (after_index[sk][2], after_index[sk][3]) != (before_index[sk][2], before_index[sk][3])
        }
        for sk in sorted(changed_rows):
            kl, _ = sk
            if kl in failed_keys:
                continue
            try:
                if sk in before_index:
                    path, name, vtype, data = before_index[sk]
                    key = regman.get_key_from_path(path)
                    actual = key.get_value(name) if key is not None else None
                    if actual is None or (actual.get_type(), actual.get_data()) != (vtype, data):
                        result.failures.append(
                            RollbackFailure(
                                kind="registry_value",
                                path=path,
                                value_name=name,
                                error="value does not match the baseline after rollback",
                            )
                        )
                        continue
                else:
                    path = after_index[sk][0]
                    key = regman.get_key_from_path(path)
                    name = after_index[sk][1]
                    if key is not None and key.get_value(name) is not None:
                        result.failures.append(
                            RollbackFailure(
                                kind="registry_value",
                                path=path,
                                value_name=name,
                                error="created value still present after rollback",
                            )
                        )
                        continue
            except Exception as err:
                path = before_index.get(sk, after_index[sk])[0]
                result.failures.append(
                    RollbackFailure(
                        kind="registry_value",
                        path=path,
                        value_name=before_index.get(sk, after_index[sk])[1],
                        error=f"could not verify restored value: {err}",
                    )
                )
                continue
            values_restored += 1

        return keys_restored, values_restored

    @staticmethod
    def _make_reg_value(row: tuple[str, int, Any, str]) -> RegValue:
        name, vtype, data, _path = row
        if vtype == regdefs.REG_BINARY and isinstance(data, bytes):
            # RegValue stores REG_BINARY as base64; undo that for the constructor.
            return RegValue(name, vtype, base64.b64decode(data))
        return RegValue(name, vtype, data)
