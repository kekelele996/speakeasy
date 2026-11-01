"""Before/after change reports and single-run rollback for files and registry state."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, load_emu, start_process
from tests.pe_builder import build_pe

HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
REG_SZ = 1
REG_DWORD = 4

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
CREATE_ALWAYS = 2
OPEN_EXISTING = 3

BYTE_FILL_PATH = "c:\\programdata\\mydir\\myfile.bin"
CMD_PATH = "c:\\Windows\\system32\\cmd.exe"
SVCHOST_PATH = "c:\\Windows\\system32\\svchost.exe"


@pytest.fixture
def emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    """An emulator where only the configured full paths exist."""
    files = config["filesystem"]["files"]
    config["filesystem"]["files"] = [f for f in files if f["mode"] == "full_path"]
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        start_process(se)
        yield se


def create_file(se: Speakeasy, path: bytes, *, disposition: int = CREATE_ALWAYS, access: int = GENERIC_WRITE) -> int:
    return call(se, "kernel32", "CreateFileA", [alloc(se, path + b"\x00"), access, 0, 0, disposition, 0, 0])[0]


def write_handle(se: Speakeasy, handle: int, data: bytes) -> None:
    written = alloc(se, b"\x00" * 4)
    assert call(se, "kernel32", "WriteFile", [handle, alloc(se, data), len(data), written, 0])[0]


def create_reg_key(se: Speakeasy, hkey: int, subkey: bytes) -> int:
    phk = alloc(se, b"\x00" * 4)
    rv, _ = call(se, "advapi32", "RegCreateKeyExA", [hkey, alloc(se, subkey + b"\x00"), 0, 0, 0, 0xF003F, 0, phk, 0])
    assert rv == 0
    return int.from_bytes(se.mem_read(phk, 4), "little")


def set_reg_value(se: Speakeasy, hkey: int, name: bytes, vtype: int, data: bytes, size: int | None = None) -> None:
    rv, _ = call(
        se,
        "advapi32",
        "RegSetValueExA",
        [hkey, alloc(se, name + b"\x00"), 0, vtype, alloc(se, data), len(data) if size is None else size],
    )
    assert rv == 0


def paths(changes: list[Any]) -> set[str]:
    return {c.path.lower() for c in changes}


# ---------------------------------------------------------------------------
# File change classification
# ---------------------------------------------------------------------------


def test_file_changes_distinguish_created_overwritten_and_deleted(emu: Speakeasy) -> None:
    emu.arm_change_tracking()

    hnd = create_file(emu, b"c:\\drop.bin")
    write_handle(emu, hnd, b"hello dropper")
    call(emu, "kernel32", "CloseHandle", [hnd])

    hnd = create_file(emu, BYTE_FILL_PATH.encode())
    write_handle(emu, hnd, b"new contents")
    call(emu, "kernel32", "CloseHandle", [hnd])

    assert call(emu, "kernel32", "DeleteFileA", [alloc(emu, CMD_PATH.encode() + b"\x00")])[0]

    # A file created and then deleted within the run has no net change.
    hnd = create_file(emu, b"c:\\gone.txt")
    write_handle(emu, hnd, b"ephemeral")
    call(emu, "kernel32", "CloseHandle", [hnd])
    assert call(emu, "kernel32", "DeleteFileA", [alloc(emu, b"c:\\gone.txt\x00")])[0]

    # Reading a pre-existing file is not a change.
    hnd = create_file(emu, SVCHOST_PATH.encode(), disposition=OPEN_EXISTING, access=GENERIC_READ)
    call(emu, "kernel32", "CloseHandle", [hnd])

    report = emu.get_change_report()

    assert paths(report.files_created) == {"c:\\drop.bin"}
    created = report.files_created[0]
    assert created.sha256_after == hashlib.sha256(b"hello dropper").hexdigest()
    assert created.size_after == len(b"hello dropper")
    assert created.size_before is None

    assert paths(report.files_overwritten) == {BYTE_FILL_PATH}
    overwritten = report.files_overwritten[0]
    assert overwritten.sha256_before == hashlib.sha256(b"A" * 512).hexdigest()
    assert overwritten.size_before == 512
    assert overwritten.sha256_after == hashlib.sha256(b"new contents").hexdigest()

    assert paths(report.files_deleted) == {CMD_PATH.lower()}
    deleted = report.files_deleted[0]
    assert deleted.size_after is None and deleted.sha256_before

    # Final contents are resolvable through the report data store.
    store = emu.emu.profiler.artifact_store
    assert store.get_bytes(created.after_data_ref) == b"hello dropper"
    assert store.get_bytes(overwritten.before_data_ref) == b"A" * 512
    assert store.get_bytes(overwritten.after_data_ref) == b"new contents"


# ---------------------------------------------------------------------------
# Registry change classification
# ---------------------------------------------------------------------------


def test_registry_changes_distinguish_created_overwritten_and_deleted(emu: Speakeasy) -> None:
    emu.arm_change_tracking()

    hkey = create_reg_key(emu, HKEY_CURRENT_USER, b"Software\\Evil")
    set_reg_value(emu, hkey, b"Payload", REG_SZ, b"wlogon.dll\x00")
    set_reg_value(emu, hkey, b"Payload", REG_SZ, b"overwritten\x00")

    # A value created and deleted within the run has no net change.
    set_reg_value(emu, hkey, b"Doomed", REG_SZ, b"bye\x00")
    assert call(emu, "advapi32", "RegDeleteValueA", [hkey, alloc(emu, b"Doomed\x00")])[0] == 0

    # Deleting a value supplied by the config is a deletion; changing one is
    # an overwrite rather than a create.
    svc = create_reg_key(emu, HKEY_LOCAL_MACHINE, b"System\\CurrentControlSet\\Services\\usbsamp")
    set_reg_value(emu, svc, b"Start", REG_DWORD, struct.pack("<I", 4), size=4)
    assert call(emu, "advapi32", "RegDeleteValueA", [svc, alloc(emu, b"DisplayName\x00")])[0] == 0

    report = emu.get_change_report()

    assert {c.path.lower() for c in report.registry_keys_created} == {"hkey_current_user\\software\\evil"}

    values = {(c.key_path.lower(), c.value_name): c for c in report.registry_values_created}
    created = values[("hkey_current_user\\software\\evil", "Payload")]
    # A value created and re-written within the run nets to its final content.
    assert created.type_after == REG_SZ and created.data_after == "overwritten"

    # Only a pre-existing (config) value being changed counts as overwritten.
    overwritten = {(c.key_path.lower(), c.value_name): c for c in report.registry_values_overwritten}
    assert set(overwritten) == {("hkey_local_machine\\system\\currentcontrolset\\services\\usbsamp", "Start")}
    start = overwritten[("hkey_local_machine\\system\\currentcontrolset\\services\\usbsamp", "Start")]
    assert start.type_before == REG_DWORD and (start.data_before, start.data_after) == (3, 4)

    all_values = [
        (c.key_path.lower(), c.value_name)
        for group in (
            report.registry_values_created,
            report.registry_values_overwritten,
            report.registry_values_deleted,
        )
        for c in group
    ]
    assert ("hkey_current_user\\software\\evil", "Doomed") not in all_values

    deleted = {(c.key_path.lower(), c.value_name): c for c in report.registry_values_deleted}
    display_name = deleted[("hkey_local_machine\\system\\currentcontrolset\\services\\usbsamp", "DisplayName")]
    assert display_name.data_before == "An example service" and display_name.data_after is None


def test_change_report_is_empty_when_nothing_changed(emu: Speakeasy) -> None:
    emu.arm_change_tracking()
    hnd = create_file(emu, SVCHOST_PATH.encode(), disposition=OPEN_EXISTING, access=GENERIC_READ)
    call(emu, "kernel32", "CloseHandle", [hnd])
    create_reg_key(emu, HKEY_LOCAL_MACHINE, b"System\\CurrentControlSet\\Services\\usbsamp")

    assert emu.get_change_report().is_empty()


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def test_rollback_restores_state_and_keeps_observation_records(emu: Speakeasy) -> None:
    emu.arm_change_tracking()

    hnd = create_file(emu, b"c:\\drop.bin")
    write_handle(emu, hnd, b"hello dropper")
    call(emu, "kernel32", "CloseHandle", [hnd])

    hnd = create_file(emu, BYTE_FILL_PATH.encode())
    write_handle(emu, hnd, b"new contents")
    call(emu, "kernel32", "CloseHandle", [hnd])

    assert call(emu, "kernel32", "DeleteFileA", [alloc(emu, CMD_PATH.encode() + b"\x00")])[0]

    hkey = create_reg_key(emu, HKEY_CURRENT_USER, b"Software\\Evil")
    set_reg_value(emu, hkey, b"Payload", REG_SZ, b"wlogon.dll\x00")

    svc = create_reg_key(emu, HKEY_LOCAL_MACHINE, b"System\\CurrentControlSet\\Services\\usbsamp")
    set_reg_value(emu, svc, b"Start", REG_DWORD, struct.pack("<I", 4), size=4)

    report_before = emu.get_json_report()
    assert "drop.bin" in report_before and "wlogon.dll" in report_before

    result = emu.rollback_changes()
    assert result.success
    assert result.files_restored == 3  # one created removed, one overwritten, one deleted
    assert result.registry_values_restored == 2
    assert result.registry_keys_restored == 1

    # Files are back to the baseline.
    assert emu.emu.fileman.get_file_from_path("c:\\drop.bin") is None
    restored = emu.emu.fileman.get_file_from_path(BYTE_FILL_PATH)
    assert restored is not None and restored.get_contents() == b"A" * 512
    restored_cmd = emu.emu.fileman.get_file_from_path(CMD_PATH)
    assert restored_cmd is not None and restored_cmd.get_contents()

    # Registry is back to the baseline.
    assert emu.emu.regman.get_key_from_path("HKEY_CURRENT_USER\\Software\\Evil") is None
    start = emu.emu.regman.get_key_from_path(
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\usbsamp"
    ).get_value("Start")
    assert start is not None and start.get_data() == 3

    assert emu.get_change_report().is_empty()

    # Observation records (events and the already-built report) survive.
    assert emu.emu.curr_run is not None
    reg_writes = [
        event for event in emu.emu.curr_run.events if event.event == "reg_write_value" and "Evil" in event.path
    ]
    assert reg_writes and reg_writes[0].value_name == "Payload"
    assert "drop.bin" in report_before and "wlogon.dll" in report_before

    # A second rollback restores nothing new and stays successful.
    again = emu.rollback_changes()
    assert again.success
    assert (again.files_restored, again.registry_keys_restored, again.registry_values_restored) == (0, 0, 0)


def test_rollback_names_every_file_item_that_could_not_be_restored(emu: Speakeasy, monkeypatch) -> None:
    emu.arm_change_tracking()
    assert call(emu, "kernel32", "DeleteFileA", [alloc(emu, CMD_PATH.encode() + b"\x00")])[0]
    assert call(emu, "kernel32", "DeleteFileA", [alloc(emu, SVCHOST_PATH.encode() + b"\x00")])[0]

    original = emu.emu.fileman.add_existing_file

    def flaky_add_existing_file(path, data):
        if path.lower() == CMD_PATH.lower():
            raise RuntimeError("simulated restore failure")
        return original(path, data)

    monkeypatch.setattr(emu.emu.fileman, "add_existing_file", flaky_add_existing_file)

    result = emu.rollback_changes()
    assert not result.success
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert failure.kind == "file"
    assert failure.path.lower() == CMD_PATH.lower()
    assert "simulated restore failure" in failure.error

    # The other item was still restored despite the failure.
    assert emu.emu.fileman.get_file_from_path(SVCHOST_PATH) is not None
    assert emu.emu.fileman.get_file_from_path(CMD_PATH) is None
    assert not emu.emu.does_file_exist(CMD_PATH)

    # Once the fault clears, another rollback finishes the job.
    monkeypatch.undo()
    assert emu.rollback_changes().success
    assert emu.emu.fileman.get_file_from_path(CMD_PATH) is not None


def test_rollback_reports_a_registry_key_it_cannot_recreate(emu: Speakeasy, monkeypatch) -> None:
    path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    emu.arm_change_tracking()

    key = emu.emu.regman.get_key_from_path(path)
    assert key is not None
    emu.emu.regman.keys.remove(key)
    for handle, owned in list(emu.emu.regman.reg_handles.items()):
        if owned is key:
            del emu.emu.regman.reg_handles[handle]
    assert any(c.path == path for c in emu.get_change_report().registry_keys_deleted)

    def flaky_create_key(candidate, *args, **kwargs):
        if candidate == path:
            raise RuntimeError("simulated key failure")
        return original(candidate, *args, **kwargs)

    original = emu.emu.regman.create_key
    monkeypatch.setattr(emu.emu.regman, "create_key", flaky_create_key)

    result = emu.rollback_changes()
    assert not result.success
    assert len(result.failures) == 1
    assert result.failures[0].kind == "registry_key"
    assert result.failures[0].path == path

    monkeypatch.undo()
    assert emu.rollback_changes().success
    assert emu.emu.regman.get_key_from_path(path) is not None


# ---------------------------------------------------------------------------
# End to end: a real PE run arms tracking automatically and the JSON report
# carries the comparison.
# ---------------------------------------------------------------------------


def build_changer_pe() -> bytes:
    base = 0x400000
    code = bytearray()
    call_sites: list[tuple[int, tuple[str, str]]] = []

    def emit(blob: bytes) -> None:
        code.extend(blob)

    def push(value: int) -> None:
        emit(b"\x68" + struct.pack("<I", value & 0xFFFFFFFF))

    def indirect_call(symbol: tuple[str, str]) -> None:
        emit(b"\xff\x15")
        call_sites.append((len(code), symbol))
        emit(b"\x00\x00\x00\x00")

    push(0)  # hTemplateFile
    push(0x80)  # FILE_ATTRIBUTE_NORMAL
    push(CREATE_ALWAYS)
    emit(b"\x6a\x00\x6a\x00")  # security attributes, share mode
    push(GENERIC_WRITE)
    push(base + 0x2000)
    indirect_call(("kernel32.dll", "CreateFileW"))
    emit(b"\x8b\xf0")  # mov esi, eax
    emit(b"\x6a\x00")
    push(base + 0x2100)  # bytes written
    push(2)
    push(base + 0x2040)  # "PE"
    emit(b"\x56")  # push esi
    indirect_call(("kernel32.dll", "WriteFile"))
    emit(b"\x56")  # push esi
    indirect_call(("kernel32.dll", "CloseHandle"))
    push(base + 0x2108)  # lpdwDisposition (handler writes it unconditionally)
    push(base + 0x2104)  # phkResult
    emit(b"\x6a\x00")  # lpSecurityAttributes
    push(0xF003F)  # samDesired
    emit(b"\x6a\x00\x6a\x00\x6a\x00")  # dwOptions, lpClass, Reserved
    push(base + 0x2050)  # subkey
    push(HKEY_CURRENT_USER)
    indirect_call(("advapi32.dll", "RegCreateKeyExW"))
    push(8)  # cbData of "yes\0"
    push(base + 0x20A0)
    push(REG_SZ)
    emit(b"\x6a\x00")
    push(base + 0x2080)  # Marker\0
    emit(b"\x8b\x3d" + struct.pack("<I", base + 0x2104))  # mov edi, [phkResult]
    emit(b"\x57")  # push edi
    indirect_call(("advapi32.dll", "RegSetValueExW"))
    emit(b"\xc3")

    data = bytearray(0x200)

    def put(offset: int, blob: bytes) -> None:
        data[offset : offset + len(blob)] = blob

    put(0x00, "c:\\rollback\\drop.bin".encode("utf-16le") + b"\x00\x00")
    put(0x40, b"PE")
    put(0x50, "Software\\RollbackDemo".encode("utf-16le") + b"\x00\x00")
    put(0x80, "Marker".encode("utf-16le") + b"\x00\x00")
    put(0xA0, "yes".encode("utf-16le") + b"\x00\x00")

    image, iat = build_pe(
        32,
        text=bytes(code),
        data=bytes(data),
        imports={
            "kernel32.dll": ["CreateFileW", "WriteFile", "CloseHandle"],
            "advapi32.dll": ["RegCreateKeyExW", "RegSetValueExW"],
        },
    )
    image = bytearray(image)
    text_raw_offset = 0x400
    for offset, symbol in call_sites:
        struct.pack_into("<I", image, text_raw_offset + offset, base + iat[symbol])
    return bytes(image)


def test_end_to_end_pe_run_includes_change_report_and_rolls_back() -> None:
    with Speakeasy() as se:
        module = se.load_module(data=build_changer_pe())
        se.run_module(module)

        assert [ep.error for ep in se.get_report().entry_points] == [None]

        report = json.loads(se.get_json_report())
        changes = report["change_report"]
        assert {f["path"].lower() for f in changes["files_created"]} == {"c:\\rollback\\drop.bin"}
        assert {(k["path"].lower()) for k in changes["registry_keys_created"]} == {
            "hkey_current_user\\software\\rollbackdemo"
        }
        values = {(v["key_path"].lower(), v["value_name"]): v for v in changes["registry_values_created"]}
        assert values[("hkey_current_user\\software\\rollbackdemo", "Marker")]["data_after"] == "yes"

        result = se.rollback_changes()
        assert result.success
        assert result.files_restored >= 1 and result.registry_keys_restored >= 1
        assert se.emu.fileman.get_file_from_path("c:\\rollback\\drop.bin") is None
        assert se.emu.regman.get_key_from_path("HKEY_CURRENT_USER\\Software\\RollbackDemo") is None
        assert se.get_change_report().is_empty()


@pytest.mark.parametrize("mode", [[], ["--no-mp"]])
def test_cli_writes_change_report_and_runs_rollback(tmp_path, mode: list[str]) -> None:
    target = tmp_path / "changer.exe"
    target.write_bytes(build_changer_pe())
    output = tmp_path / "report.json"
    change_report = tmp_path / "changes.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "speakeasy.cli",
            "-t",
            str(target),
            "-o",
            str(output),
            "--change-report",
            str(change_report),
            "--rollback-changes",
            *mode,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr

    embedded = json.loads(output.read_text())["change_report"]
    assert {f["path"].lower() for f in embedded["files_created"]} == {"c:\\rollback\\drop.bin"}

    standalone = json.loads(change_report.read_text())
    assert standalone["files_created"][0]["path"] == "c:\\rollback\\drop.bin"
    assert standalone["registry_values_created"][0]["data_after"] == "yes"


def test_cli_emulate_binary_rolls_back_in_process(tmp_path) -> None:
    """The --no-mp path returns the rollback outcome on the result queue."""
    import multiprocessing as mp

    from speakeasy.cli import emulate_binary, format_rollback_error
    from speakeasy.config import get_default_config_dict

    target = tmp_path / "changer.exe"
    target.write_bytes(build_changer_pe())
    change_report = tmp_path / "changes.json"

    q: mp.Queue = mp.Queue()
    emulate_binary(
        q,
        mp.Event(),
        str(target),
        get_default_config_dict(),
        [],
        False,
        change_report_path=str(change_report),
        rollback_changes=True,
    )
    report, error, rollback = q.get()

    assert error is None and report is not None
    assert rollback is not None
    assert rollback["failures"] == []
    assert rollback["files_restored"] >= 1
    assert rollback["registry_keys_restored"] >= 1
    assert rollback["registry_values_restored"] >= 1
    assert json.loads(change_report.read_text())["files_created"]
    assert format_rollback_error(rollback) is None

    message = format_rollback_error(
        {"failures": [{"kind": "file", "path": "C:\\a.bin", "value_name": None, "error": "boom"}]}
    )
    assert message is not None and "C:\\a.bin" in message and "boom" in message
    assert format_rollback_error({"failures": []}) is None
