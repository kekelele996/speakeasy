"""Child processes run after the parent when emulate_children is set."""

import hashlib
import logging

from speakeasy import Speakeasy
from speakeasy.profiler import build_process_tree
from speakeasy.profiler_events import (
    FileWriteEvent,
    NetDnsEvent,
    NetTrafficEvent,
    ProcessCreateEvent,
    TracePosition,
)
from speakeasy.report import EntryPoint, ErrorInfo

CHILD_PATH = "c:\\child.exe"
CHILD_BASE = 0x10000000
# parent.c starts c:\child.exe. child.c returns the base of the first image in its loader
# list; child_x86 has the image base of the parent, child_at_10000000_x86 has CHILD_BASE.
PARENT = "parent_x86.exe.xz"
CHILD = "child_x86.exe.xz"
CHILD_AT_CHILD_BASE = "child_at_10000000_x86.exe.xz"


def test_child_exe_runs_at_the_base_of_the_parent_exe(config, load_test_bin):
    parent = load_test_bin(PARENT)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=parent)
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.run_module(module, emulate_children=True)
        child = se.emu.get_mod_from_addr(module.base)
        pids = [se.emu.processes[0].pid, se.emu.get_current_process().pid]
        report = se.get_report()
        entries = report.entry_points

    assert (child.name, child.emu_path) == ("child", CHILD_PATH)
    assert report.sha256 == hashlib.sha256(parent).hexdigest()

    assert [(ep.ep_type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[0].ret_val == 1
    assert entries[1].ret_val == module.base
    assert len(set(pids)) == 2
    assert [ep.pid for ep in entries] == pids


def test_child_without_relocations_whose_base_is_in_use_is_skipped(config, load_test_bin, caplog):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.emu.mem_map(0x1000, base=CHILD_BASE, tag="test.block")
        with caplog.at_level(logging.WARNING):
            se.run_module(module, emulate_children=True)
        report = se.get_report()

    assert [(ep.ep_type, ep.error) for ep in report.entry_points] == [("module_entry", None)]
    assert f"skipping child process {CHILD_PATH}" in caplog.text
    assert "Cannot rebase a guest PE without valid relocation data" in caplog.text


def test_child_finds_its_own_image_first_in_its_loader_list(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.run_module(module, emulate_children=True)
        child = se.emu.get_current_process()
        entries = se.get_report().entry_points

    assert [(ep.ep_type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[1].ret_val == CHILD_BASE
    assert [entry.object.DllBase for entry in child.ldr_entries][:4] == [
        CHILD_BASE,
        se.emu.get_mod_by_name("ntdll").base,
        se.emu.get_mod_by_name("kernel32").base,
        se.emu.get_mod_by_name("kernelbase").base,
    ]


def test_finished_parent_gives_up_its_image_peb_and_heap(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.run_module(module, emulate_children=True)
        parent = se.emu.processes[0]
        maps = se.emu.get_mem_maps()
        heap = [address for address, _, name in se.emu.heap_allocs if name == "LocalAlloc"]

    assert parent.pe is module
    assert module not in se.emu.modules
    assert all(not m.base <= module.base < m.base + m.size for m in maps)
    assert all(m.free for m in maps if m.base <= parent.peb.address < m.base + m.size)
    assert len(heap) == 1
    assert all(m.free for m in maps if m.base <= heap[0] < m.base + m.size)


def _run_parent(config, load_test_bin, *, emulate_children, child_bin=CHILD, block_child_base=False):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(child_bin))
        if block_child_base:
            se.emu.mem_map(0x1000, base=CHILD_BASE, tag="test.block")
        se.run_module(module, emulate_children=emulate_children)
        return se.get_report()


def test_process_tree_stitches_parent_and_child_runs(config, load_test_bin):
    report = _run_parent(config, load_test_bin, emulate_children=True)
    entries = report.entry_points

    tree = report.process_tree
    assert tree is not None
    assert len(tree) == 1
    root = tree[0]
    assert root.root is True
    assert root.creator_pid is None
    assert root.pid == entries[0].pid
    assert root.end_reason == "completed"
    assert root.exit_code == entries[0].ret_val == 1

    assert len(root.children) == 1
    child = root.children[0]
    assert child.root is False
    assert child.pid == entries[1].pid
    assert child.path == CHILD_PATH
    assert child.creator_pid == root.pid
    assert child.end_reason == "completed"
    assert child.exit_code == entries[1].ret_val

    # The hierarchy is part of the existing run record, not a separate output.
    assert "process_tree" in report.model_dump_json(exclude_none=True)


def test_process_tree_marks_created_child_as_not_emulated_when_disabled(config, load_test_bin):
    report = _run_parent(config, load_test_bin, emulate_children=False)

    root = report.process_tree[0]
    assert root.end_reason == "completed"
    assert len(root.children) == 1
    child = root.children[0]
    assert child.path == CHILD_PATH
    assert child.pid != root.pid
    assert child.creator_pid == root.pid
    assert child.end_reason == "not_emulated"
    assert child.end_detail is None


def test_process_tree_records_skip_reason_for_unloadable_child(config, load_test_bin):
    report = _run_parent(
        config,
        load_test_bin,
        emulate_children=True,
        child_bin=CHILD_AT_CHILD_BASE,
        block_child_base=True,
    )

    root = report.process_tree[0]
    assert len(root.children) == 1
    child = root.children[0]
    assert child.end_reason == "skipped"
    assert child.creator_pid == root.pid
    assert "Cannot rebase a guest PE" in (child.end_detail or "")


def _pos(pid, tid=1, tick=0):
    return TracePosition(tick=tick, tid=tid, pid=pid)


def _entry(pid, *, ep_type="module_entry", ret_val=None, error=None, events=None):
    return EntryPoint(
        ep_type=ep_type,
        start_addr=0x1000,
        pid=pid,
        tid=pid + 1,
        ret_val=ret_val,
        error=error,
        events=events,
    )


_ROOT_META = {
    100: {"path": "c:\\parent.exe", "cmdline": "parent.exe"},
    200: {"path": CHILD_PATH, "cmdline": CHILD_PATH},
    300: {"path": CHILD_PATH, "cmdline": CHILD_PATH},
}


def test_build_tree_distinguishes_repeated_spawns_of_same_path_by_pid():
    events = [
        ProcessCreateEvent(pos=_pos(100), path=CHILD_PATH, cmdline="first", pid=200),
        ProcessCreateEvent(pos=_pos(100), path=CHILD_PATH, cmdline="second", pid=300),
    ]
    tree = build_process_tree([_entry(100, ret_val=0, events=events)], _ROOT_META)

    assert len(tree) == 1
    root = tree[0]
    assert (root.pid, root.path, root.root) == (100, "c:\\parent.exe", True)
    assert [(c.pid, c.path, c.cmdline) for c in root.children] == [
        (200, CHILD_PATH, "first"),
        (300, CHILD_PATH, "second"),
    ]
    assert len({c.pid for c in root.children}) == 2
    for child in root.children:
        assert child.creator_pid == 100
        assert child.end_reason == "not_emulated"
        assert child.missing_parent is False


def test_build_tree_flags_child_whose_creator_record_is_missing():
    # The creation event is attributed to actor pid 999, but no run or creation
    # record exists for pid 999 anywhere in the report.
    event = ProcessCreateEvent(pos=_pos(999), path=CHILD_PATH, cmdline="", pid=300)
    tree = build_process_tree([_entry(100, events=[event])], _ROOT_META)

    assert [node.pid for node in tree] == [100, 999]
    placeholder = tree[1]
    assert placeholder.missing_record is True
    assert placeholder.missing_parent is False
    assert placeholder.path is None
    assert placeholder.end_reason == "missing_record"
    assert len(placeholder.children) == 1

    orphan = placeholder.children[0]
    assert orphan.pid == 300
    assert orphan.path == CHILD_PATH
    assert orphan.creator_pid == 999
    assert orphan.missing_parent is True


def test_build_tree_flags_executing_process_without_creation_record():
    tree = build_process_tree([_entry(100, ret_val=0), _entry(300, ret_val=7)], _ROOT_META)

    assert [node.pid for node in tree] == [100, 300]
    stray = tree[1]
    assert stray.root is False
    assert stray.missing_parent is True
    assert stray.creator_pid is None
    assert stray.end_reason == "completed"
    assert stray.exit_code == 7


def test_build_tree_attributes_file_and_network_actions_to_actor_process():
    create = ProcessCreateEvent(pos=_pos(100), path=CHILD_PATH, cmdline="", pid=200)
    root_entry = _entry(
        100,
        ret_val=0,
        events=[create, FileWriteEvent(pos=_pos(100), path="c:\\shared.txt", size=11)],
    )
    child_entry = _entry(
        200,
        ret_val=0,
        events=[
            FileWriteEvent(pos=_pos(200), path="c:\\shared.txt", size=22),
            NetDnsEvent(pos=_pos(200), query="example.test", response="1.2.3.4"),
            NetTrafficEvent(pos=_pos(200), server="1.2.3.4", port=443, proto="tcp", type="connect"),
            NetTrafficEvent(pos=_pos(200), server="1.2.3.4", port=443, proto="tcp", type="data_out"),
        ],
    )
    tree = build_process_tree([root_entry, child_entry], _ROOT_META)

    root, child = tree[0], tree[0].children[0]
    assert [(f.path, f.writes, f.bytes_written) for f in root.files] == [("c:\\shared.txt", 1, 11)]
    assert root.network == []

    assert [(f.path, f.writes, f.bytes_written) for f in child.files] == [("c:\\shared.txt", 1, 22)]
    network = {(n.kind, n.endpoint): n for n in child.network}
    dns = network[("dns", "example.test")]
    assert dns.response == "1.2.3.4"
    assert dns.count == 1
    traffic = network[("traffic", "1.2.3.4")]
    assert traffic.port == 443
    assert traffic.proto == "tcp"
    assert traffic.actions == ["connect", "data_out"]
    assert traffic.count == 2


def test_build_tree_marks_failed_process_with_error_layer():
    error = ErrorInfo(type="invalid_insn", context_summary="boom")
    create = ProcessCreateEvent(pos=_pos(100), path=CHILD_PATH, cmdline="", pid=200)
    tree = build_process_tree(
        [_entry(100, ret_val=0, events=[create]), _entry(200, error=error)],
        _ROOT_META,
    )

    child = tree[0].children[0]
    assert child.end_reason == "error"
    assert child.error_type == "invalid_insn"
    assert child.end_detail == "boom"
    assert child.exit_code is None


def test_build_tree_uses_recorded_skip_reason():
    create = ProcessCreateEvent(pos=_pos(100), path=CHILD_PATH, cmdline="", pid=200)
    tree = build_process_tree([_entry(100, events=[create])], _ROOT_META, {200: "no image"})

    child = tree[0].children[0]
    assert child.end_reason == "skipped"
    assert child.end_detail == "no image"


def test_build_tree_without_any_process_returns_none():
    assert build_process_tree([]) is None
