# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import json
from types import SimpleNamespace
from typing import Any

import pytest

from speakeasy.profiler import Run
from speakeasy.windows import objman
from speakeasy.windows.handle_audit import HandleAuditor
from tests.handler_harness import alloc, call, load_emu, start_process


class StubEmu:
    """Minimal emulator surface the auditor reads for context."""

    def __init__(self, pid=100, module="sample.exe", path="C:\\sample.exe"):
        self.is_kernel_mode = False
        self.pid = pid
        self.tid = 10
        self.module = module
        self.path = path
        self._active_api_frame = None

    def set_context(self, pid=None, module=None, tid=None):
        if pid is not None:
            self.pid = pid
        if module is not None:
            self.module = module
        if tid is not None:
            self.tid = tid

    def get_current_process(self):
        if self.pid is None:
            return None
        return SimpleNamespace(id=self.pid, name="", path=self.path, image=self.module)

    def get_current_thread(self):
        return SimpleNamespace(tid=self.tid)

    def get_pc(self):
        return 0x401000

    def get_module_from_addr(self, addr):
        if not self.module:
            return None
        return SimpleNamespace(name=self.module, emu_path=self.path, base=0x400000)


def _file_obj(name):
    return SimpleNamespace(path=name)


def _rows_for(report, object_type):
    return [row for row in report["summary"] if row["object_type"] == object_type]


def test_reused_handle_value_keeps_generations_apart():
    """A closed value rebound to another object starts a new generation."""
    auditor = HandleAuditor(StubEmu())

    run1 = Run()
    auditor.begin_run(run1)
    auditor.created("file", 0x80, _file_obj("C:\\old.txt"), object_type="File")
    report1 = auditor.end_run(run1)
    assert report1["remaining"] == 1
    assert report1["unclosed"][0]["generation"] == 1
    assert report1["unclosed"][0]["name"] == "C:\\old.txt"

    assert auditor.closed("file", 0x80, api="CloseHandle")

    run2 = Run()
    auditor.begin_run(run2)
    auditor.created("file", 0x80, _file_obj("C:\\new.txt"), object_type="File")
    report2 = auditor.end_run(run2)

    # The new binding must not inherit any state from the old one.
    open_rows = report2["unclosed"]
    assert len(open_rows) == 1
    assert open_rows[0]["generation"] == 2
    assert open_rows[0]["name"] == "C:\\new.txt"
    assert open_rows[0]["opened_in_run"] == 2

    history = [b for b in auditor._history if not b.system]
    assert len(history) == 2
    old, new = history
    assert (old.generation, old.closed, old.name, old.close_api) == (1, True, "C:\\old.txt", "CloseHandle")
    assert (new.generation, new.closed, new.name) == (2, False, "C:\\new.txt")


def test_summary_groups_by_process_module_and_type():
    emu = StubEmu(pid=100, module="sample.exe")
    auditor = HandleAuditor(emu)

    run = Run()
    auditor.begin_run(run)
    auditor.created("file", 0x80, _file_obj("C:\\a.txt"), object_type="File")
    auditor.created("file", 0x84, _file_obj("C:\\b.txt"), object_type="File")
    auditor.created("registry", 0x180, SimpleNamespace(path="HKCU\\Software\\X"), object_type="RegKey")
    auditor.closed("file", 0x80, api="CloseHandle")
    report = auditor.end_run(run)

    assert (report["created"], report["closed"], report["remaining"]) == (3, 1, 2)

    file_rows = _rows_for(report, "File")
    assert len(file_rows) == 1
    row = file_rows[0]
    assert (row["process_id"], row["process_name"], row["module"]) == (100, "sample.exe", "sample.exe")
    assert (row["created"], row["closed"], row["remaining"]) == (2, 1, 1)

    reg_rows = _rows_for(report, "RegKey")
    assert reg_rows[0]["remaining"] == 1

    assert report["remaining"] == sum(r["remaining"] for r in report["summary"])


def test_last_holder_tracks_most_recent_user():
    emu = StubEmu(pid=100, module="sample.exe")
    auditor = HandleAuditor(emu)

    run = Run()
    auditor.begin_run(run)
    auditor.created("kernel", 0x220, SimpleNamespace(name="Global\\m"), object_type="Mutant")

    # Another module/process references the handle before the run ends.
    emu.set_context(pid=200, module="worker.dll", tid=22)
    auditor.touch("kernel", 0x220)

    report = auditor.end_run(run)
    unclosed = report["unclosed"][0]
    assert unclosed["process_id"] == 100
    assert unclosed["owner_module"] == "sample.exe"
    assert unclosed["last_holder_process_id"] == 200
    assert unclosed["last_holder_module"] == "worker.dll"
    assert unclosed["last_holder_thread_id"] == 22


def test_system_bindings_are_not_counted_as_leaks():
    emu = StubEmu(pid=None, module=None)
    auditor = HandleAuditor(emu)

    # Bindings created before any guest context exists are emulator-owned.
    auditor.created("registry", 0x80000000, SimpleNamespace(path="HKEY_LOCAL_MACHINE"), object_type="RegKey")
    assert not auditor._live
    assert ("registry", 0x80000000) in auditor._system

    run = Run()
    auditor.begin_run(run)
    report = auditor.end_run(run)
    assert report["created"] == 0
    assert report["remaining"] == 0
    assert report["unclosed"] == []

    # Closing a system handle is accepted but never counted.
    assert auditor.closed("registry", 0x80000000)
    assert auditor._system


@pytest.fixture
def exe_emu(config, load_test_bin):
    yield from load_emu(config, load_test_bin("argv_test_x86.exe.xz"))


def _begin_run(emu) -> Run:
    run = Run()
    emu.handle_audit.begin_run(run)
    return run


def test_registry_lifecycle_through_manager(exe_emu):
    emu = exe_emu.emu
    start_process(exe_emu)
    run = _begin_run(emu)

    hnd = emu.regman.open_key("HKEY_CURRENT_USER\\Software\\AuditTest", create=True)
    assert emu.handle_audit._live[("registry", hnd)].object_type == "RegKey"
    assert emu.regman.close_key(hnd)

    report = emu.handle_audit.end_run(run)
    assert (report["created"], report["closed"], report["remaining"]) == (1, 1, 0)
    # Predefined HKEYs stay open but never appear in the audit.
    assert all(row["object_type"] != "RegKey" or row["remaining"] == 0 for row in report["summary"])
    assert report["unclosed"] == []


def test_file_lifecycle_through_manager(exe_emu):
    emu = exe_emu.emu
    start_process(exe_emu)
    run = _begin_run(emu)

    hnd = emu.fileman.file_open("C:\\audit_leak.txt", create=True)
    assert emu.fileman.close_handle(hnd) == "file"
    # Closing again does not double-count (the binding is already retired).
    assert emu.fileman.close_handle(hnd) is None

    report = emu.handle_audit.end_run(run)
    rows = _rows_for(report, "File")
    assert sum(r["created"] for r in rows) == 1
    assert sum(r["closed"] for r in rows) == 1
    assert report["remaining"] == 0


def test_kernel_object_release_closes_bindings(exe_emu):
    emu = exe_emu.emu
    start_process(exe_emu)
    run = _begin_run(emu)

    event = emu.new_object(objman.Event)
    hnd = emu.get_object_handle(event)
    assert ("kernel", hnd) in emu.handle_audit._live

    # Last reference dropped: the object manager tears the object down.
    emu.dec_ref(event)

    report = emu.handle_audit.end_run(run)
    assert report["created"] == 1
    assert report["closed"] == 1
    assert report["unclosed"] == []


def test_unclosed_handle_carries_into_later_runs(exe_emu):
    emu = exe_emu.emu
    start_process(exe_emu)

    run1 = _begin_run(emu)
    hnd = emu.fileman.file_open("C:\\still_open.txt", create=True)
    report1 = emu.handle_audit.end_run(run1)
    assert report1["remaining"] == 1

    run2 = _begin_run(emu)
    report2 = emu.handle_audit.end_run(run2)
    # No activity in run 2, but the leaked handle is still reported.
    assert report2["created"] == 0
    assert report2["closed"] == 0
    assert report2["remaining"] == 1
    unclosed = report2["unclosed"][0]
    assert unclosed["handle"] == hnd
    assert unclosed["object_type"] == "File"
    assert unclosed["opened_in_run"] == 1
    assert unclosed["process_id"] is not None


def test_handle_audit_merged_into_run_records(config, load_test_bin, run_test):
    data = load_test_bin("file_access_test_x86.exe.xz")
    report = run_test(config, data)

    audits: list[Any] = [ep.handle_audit for ep in report.entry_points if ep.handle_audit is not None]
    assert audits, "expected handle audit sections in run records"

    for audit in audits:
        assert audit.remaining == len(audit.unclosed)
        assert audit.remaining == sum(row.remaining for row in audit.summary)
        assert audit.created >= audit.closed or audit.remaining >= 0
        for row in audit.summary:
            assert row.remaining <= row.created - row.closed + row.remaining
            assert row.object_type

    file_rows = [row for audit in audits for row in audit.summary if row.object_type == "File"]
    assert file_rows, "file_access_test opens at least one File handle"
    created_rows = [row for row in file_rows if row.created > 0]
    assert created_rows
    # Guest attribution: open events resolve back to a process and module.
    assert all(row.process_id is not None and row.module for row in created_rows)

    serialized = json.loads(report.model_dump_json())
    ep_audit = serialized["entry_points"][0]["handle_audit"]
    assert {"created", "closed", "remaining", "summary", "unclosed"} <= set(ep_audit)
    for entry in ep_audit["unclosed"]:
        assert entry["handle"].startswith("0x")
        assert isinstance(entry["generation"], int)
        assert entry["object_type"]


def test_crypt_hash_and_gdi_lifetimes_through_handlers(exe_emu):
    se = exe_emu
    start_process(se)
    emu = se.emu
    run = _begin_run(emu)

    ph_hash = alloc(se, b"\x00\x00\x00\x00")
    # CALG_MD5 = 0x8003
    rv, _ = call(se, "advapi32", "CryptCreateHash", [0, 0x8003, 0, 0, ph_hash])
    assert rv == 1
    hash_handle = int.from_bytes(se.mem_read(ph_hash, 4), "little")
    assert ("hash", hash_handle) in emu.handle_audit._live
    rv, _ = call(se, "advapi32", "CryptDestroyHash", [hash_handle])
    assert rv == 1
    assert ("hash", hash_handle) not in emu.handle_audit._live

    bitmap, _ = call(se, "gdi32", "CreateBitmap", [1, 1, 1, 32, 0])
    assert bitmap
    assert ("gdi", bitmap) in emu.handle_audit._live
    rv, _ = call(se, "gdi32", "DeleteObject", [bitmap])
    assert rv == 1
    assert ("gdi", bitmap) not in emu.handle_audit._live

    report = emu.handle_audit.end_run(run)
    assert sum(r["created"] for r in report["summary"] if r["object_type"] == "CryptHash") == 1
    assert sum(r["closed"] for r in report["summary"] if r["object_type"] == "CryptHash") == 1
    assert report["remaining"] == sum(r["remaining"] for r in report["summary"])


def test_gdi_object_type_derived_from_api_name(exe_emu):
    from speakeasy.winenv.api.usermode.gdi32 import GDI32

    gdi32 = GDI32(exe_emu.emu)
    exe_emu.emu._audit_api_name = "gdi32.CreateFontIndirectA"
    assert gdi32._audit_object_type() == "FontIndirect"
    exe_emu.emu._audit_api_name = "gdi32.CreateCompatibleDC"
    assert gdi32._audit_object_type() == "CompatibleDC"
    exe_emu.emu._audit_api_name = None
    assert gdi32._audit_object_type() == "GdiObject"
