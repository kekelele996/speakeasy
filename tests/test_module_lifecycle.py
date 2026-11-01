"""Guest images leave a per-module, per-process lifecycle trail in run events."""

import struct

import pytest
from unicorn import UcError

from speakeasy import Speakeasy, common
from speakeasy.windows import objman
from speakeasy.windows.loaders import LoadedImage, LoadState, MemoryRegion, SectionEntry
from tests.guest_harness import get_api, guest_call
from tests.pe_builder import build_pe
from tests.test_guest_dependency_loading import image_base, make_native_dll, native_config


def module_events(report):
    return [
        event
        for entry_point in report.entry_points
        for event in (entry_point.events or [])
        if event.event == "module_load"
    ]


def steps(events, name):
    return [
        (event.action, event.callback, event.status, event.reason, event.pid)
        for event in events
        if event.name == name
    ]


def guest_image(emu, name, base):
    return LoadedImage(
        arch=emu.get_arch(),
        module_type="dll",
        name=name,
        emu_path=rf"C:\test\{name}.dll",
        image_base=base,
        image_size=0x5000,
        regions=[
            MemoryRegion(0, b"MZ" + b"\0" * 0xFE, ".headers", 3),
            MemoryRegion(0x1000, b"\xc3", ".text", 5),
        ],
        imports=[],
        exports=[],
        entry_points=[],
    )


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_runtime_load_records_map_attach_and_callbacks(config, tmp_path, arch):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x400, arch=arch)
        ptr = se.get_ptr_size()
        make_native_dll(se.emu, tmp_path / "guest_dependency.dll")
        dll_name = se.mem_alloc(0x100, base=0x20000000)
        se.mem_write(dll_name, b"guest_dependency.dll\0")
        program = guest_call(ptr, get_api(se, "kernel32", "LoadLibraryA"), dll_name)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        report = se.get_report()
        assert [entry_point.error for entry_point in report.entry_points] == [None]
        pid = report.entry_points[0].pid
        events = module_events(report)
    finally:
        se.shutdown()

    mapped = [event for event in events if event.action == "map"]
    assert len(mapped) == 1
    assert mapped[0].name == "guest_dependency"
    assert mapped[0].reason == "kernel32.LoadLibraryA"
    assert mapped[0].pos.pid == pid
    assert int(mapped[0].base, 16) == se.emu.get_mod_by_name("guest_dependency").base

    assert steps(events, "guest_dependency") == [
        ("map", None, None, "kernel32.LoadLibraryA", pid),
        ("peb_add", None, None, None, pid),
        ("init", "tls_callback", "success", None, pid),
        ("init", "dll_entry", "success", None, pid),
    ]


def test_static_import_records_where_the_dependency_came_from(config, tmp_path):
    builder = Speakeasy(config=config)
    try:
        builder.load_shellcode(data=b"\xc3", arch="x86")
        make_native_dll(builder.emu, tmp_path / "guest_dependency.dll")
    finally:
        builder.shutdown()

    def text(base, iat):
        slot = base + iat[("guest_dependency", "GetTickCount")]
        return b"\xff\x15" + struct.pack("<I", slot) + b"\xc3"  # call [iat]; ret

    sample, _ = build_pe(32, text=text, imports={"guest_dependency": ["GetTickCount"]})

    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        module = se.load_module(data=sample)
        se.run_module(module)

        report = se.get_report()
        events = module_events(report)
        input_name = se.emu.modules[0].name
        pid = report.entry_points[0].pid
    finally:
        se.shutdown()

    mapped = {event.name: event for event in events if event.action == "map"}
    assert mapped[input_name].reason == "input"
    dependency = mapped["guest_dependency"]
    assert dependency.reason == "static_import"
    assert dependency.requested_by == input_name
    assert ("init", "tls_callback", "success", None, pid) in steps(events, "guest_dependency")
    assert ("init", "dll_entry", "success", None, pid) in steps(events, "guest_dependency")
    assert not [event for event in events if event.action in ("peb_remove", "unmap")]


def test_returning_false_from_dllmain_records_failed_callback_and_teardown(config, tmp_path):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x400, arch="x86")
        make_native_dll(se.emu, tmp_path / "guest_dependency.dll", result=0)
        dll_name = se.mem_alloc(0x100, base=0x20000000)
        se.mem_write(dll_name, b"guest_dependency.dll\0")
        program = guest_call(4, get_api(se, "kernel32", "LoadLibraryA"), dll_name)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        report = se.get_report()
        pid = report.entry_points[0].pid
        events = module_events(report)
    finally:
        se.shutdown()

    assert steps(events, "guest_dependency") == [
        ("map", None, None, "kernel32.LoadLibraryA", pid),
        ("peb_add", None, None, None, pid),
        ("init", "tls_callback", "success", None, pid),
        ("init", "dll_entry", "returned_false", None, pid),
        ("peb_remove", None, None, "init_failed", pid),
        ("unmap", None, None, "init_failed", None),
    ]
    assert se.emu.get_mod_by_name("guest_dependency") is None


def test_faulting_dllmain_records_fault_and_everything_it_pulled_in(config, tmp_path):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x400, arch="x86")
        make_native_dll(se.emu, tmp_path / "guest_dependency.dll", fault="Initializer")
        dll_name = se.mem_alloc(0x100, base=0x20000000)
        se.mem_write(dll_name, b"guest_dependency.dll\0")
        program = guest_call(4, get_api(se, "kernel32", "LoadLibraryA"), dll_name)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        pid = se.get_report().entry_points[0].pid
        events = module_events(se.get_report())
    finally:
        se.shutdown()

    assert steps(events, "guest_dependency") == [
        ("map", None, None, "kernel32.LoadLibraryA", pid),
        ("peb_add", None, None, None, pid),
        ("init", "tls_callback", "success", None, pid),
        ("init", "dll_entry", "faulted", None, pid),
        ("peb_remove", None, None, "init_failed", pid),
        ("unmap", None, None, "init_failed", None),
    ]


def test_startup_tls_fault_cancels_the_remaining_callbacks_but_keeps_image(config, tmp_path):
    builder = Speakeasy(config=config)
    try:
        builder.load_shellcode(data=b"\xc3", arch="x86")
        make_native_dll(builder.emu, tmp_path / "first.dll", fault="TlsCallback")
    finally:
        builder.shutdown()
    config["modules"]["user_modules"] += [
        {
            "name": "first",
            "base_addr": hex(image_base(tmp_path / "first.dll")),
            "path": r"C:\Windows\first.dll",
        }
    ]

    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x100, arch="x86")
        se.run_shellcode(code)

        pid = se.get_report().entry_points[0].pid
        events = module_events(se.get_report())
        module = se.emu.get_mod_by_name("first")
    finally:
        se.shutdown()

    assert steps(events, "first") == [
        ("map", None, None, "configured_module", None),
        ("peb_add", None, None, None, pid),
        ("init", "tls_callback", "faulted", None, pid),
        ("init", "dll_entry", "canceled", None, pid),
    ]
    # A startup failure keeps the image mapped, unlike a failed runtime load.
    assert module is not None
    assert module.load_states[pid] is LoadState.INIT_ERROR


def test_failed_mapping_records_unmap_of_what_it_added(config):
    config["max_instructions"] = 1
    se = Speakeasy(config=config)
    try:
        address = se.load_shellcode(data=b"\x90\x90", arch="x86")
        se.run_shellcode(address)
        emu = se.emu
        base, _ = emu.get_valid_ranges(0x5000, addr=0x67000000)
        image = guest_image(emu, "lifecycle_rollback", base)
        # Protection past the mapped span fails after the image registered.
        image.sections.append(SectionEntry(".bad", 0x9000, 0x3000, common.PERM_MEM_READ))

        with pytest.raises(UcError):
            emu.load_image(image)

        events = [
            event
            for event in emu.curr_run.events
            if event.event == "module_load" and event.name == "lifecycle_rollback"
        ]
    finally:
        se.shutdown()

    assert [(event.action, event.reason, event.base) for event in events] == [
        ("map", "explicit", hex(base)),
        ("unmap", "load_failed", hex(base)),
    ]


def test_same_library_in_two_processes_is_tracked_per_process(config, tmp_path):
    config["max_instructions"] = 1
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        address = se.load_shellcode(data=b"\xc3", arch="x86")
        se.run_shellcode(address)
        emu = se.emu
        make_native_dll(emu, tmp_path / "guest_dependency.dll")
        first = emu.get_current_process()
        assert emu.load_library("guest_dependency", trigger="kernel32.LoadLibraryA")

        second = objman.Process(emu, name="second", path=r"C:\second.exe")
        emu.processes.append(second)
        emu.om.objects.update({second.address: second})
        dependency = emu.get_mod_by_name("guest_dependency")
        emu.curr_process = second
        emu.alloc_peb(second)
        emu._add_module_to_current_peb(dependency)
        # Re-attaching in the same process adds nothing.
        emu._add_module_to_current_peb(dependency)
        emu.curr_process = first
        emu._add_module_to_current_peb(dependency)

        events = [event for event in emu.curr_run.events if event.event == "module_load"]
        mapped = [event for event in events if event.action == "map" and event.name == "guest_dependency"]
        attached = sorted(
            event.pid for event in events if event.action == "peb_add" and event.name == "guest_dependency"
        )

        # Collecting initializers per process keeps the states separate.
        emu.curr_process = first
        assert {routine.pid for routine in emu.module_loader.collect_initializers()} == {first.id}
        emu.curr_process = second
        assert {routine.pid for routine in emu.module_loader.collect_initializers()} == {second.id}
    finally:
        se.shutdown()

    assert len(mapped) == 1
    assert attached == sorted({first.id, second.id})
    assert set(dependency.load_states) == {first.id, second.id}
    assert {state for state in dependency.load_states.values()} == {LoadState.INITIALIZING}
