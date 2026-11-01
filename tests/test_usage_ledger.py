"""Per-segment usage ledgers: runtime and instructions broken down by process and thread.

One ledger is settled at the end of every public execution invocation, with the
same accounting whether the segment completed normally or was stopped midway.
"""

import json
import time
from types import SimpleNamespace

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler import Profiler, Run

CHILD_PATH = "c:\\child.exe"


def make_run(pid, tid, elapsed=0.0, instr=0, start=0x1000):
    """Build a profiler Run with only the process/thread and usage fields populated."""
    process = SimpleNamespace(id=pid) if pid is not None else None
    if tid is not None:
        thread = SimpleNamespace(tid=tid, process=process)
    else:
        thread = None
    run = Run()
    run.start_addr = start
    run.process_context = process
    run.thread = thread
    run.execution_elapsed = elapsed
    run.instr_cnt = instr
    return run


def add_segment(profiler, runs):
    """Open a segment, hand the runs to the profiler, and settle it."""
    profiler.begin_usage_segment()
    for run in runs:
        profiler.add_run(run)
    profiler.close_usage_segment()


# --- Profiler-level accounting -------------------------------------------------


def test_ledger_merges_runs_of_one_process_and_thread():
    profiler = Profiler()
    add_segment(
        profiler,
        [make_run(100, 1000, elapsed=1.0, instr=10), make_run(100, 1000, elapsed=3.0, instr=5)],
    )

    (ledger,) = profiler.usage_ledgers
    assert ledger["total_runtime"] == pytest.approx(4.0)
    assert ledger["total_instr_count"] == 15
    (row,) = ledger["entries"]
    assert (row["pid"], row["tid"]) == (100, 1000)
    assert row["runtime"] == pytest.approx(4.0)
    assert row["instr_count"] == 15


def test_ledger_separates_processes_and_threads_in_first_seen_order():
    profiler = Profiler()
    add_segment(
        profiler,
        [
            make_run(100, 1000, elapsed=1.0, instr=10),
            make_run(200, 2000, elapsed=0.5, instr=5),
            make_run(100, 1001, elapsed=0.5, instr=5),
            make_run(100, 1000, elapsed=1.0, instr=0),
        ],
    )

    (ledger,) = profiler.usage_ledgers
    assert ledger["total_runtime"] == pytest.approx(3.0)
    assert ledger["total_instr_count"] == 20
    assert [(row["pid"], row["tid"]) for row in ledger["entries"]] == [
        (100, 1000),
        (200, 2000),
        (100, 1001),
    ]
    merged = ledger["entries"][0]
    assert merged["runtime"] == pytest.approx(2.0)
    assert merged["instr_count"] == 10


def test_ledger_rows_carry_their_share_of_the_totals():
    profiler = Profiler()
    add_segment(
        profiler,
        [make_run(100, 1000, elapsed=4.0, instr=15), make_run(200, 2000, elapsed=1.0, instr=5)],
    )

    report = profiler.get_report()
    (ledger,) = report.usage
    assert ledger.total_runtime == 5.0
    assert ledger.total_instr_count == 20
    first, second = ledger.entries
    assert first.runtime_share == pytest.approx(0.8)
    assert first.instr_share == pytest.approx(0.75)
    assert second.runtime_share == pytest.approx(0.2)
    assert second.instr_share == pytest.approx(0.25)


def test_ledger_accepts_runs_without_process_or_thread_and_zero_totals():
    profiler = Profiler()
    add_segment(profiler, [make_run(None, None, elapsed=0.0, instr=0)])

    report = profiler.get_report()
    (ledger,) = report.usage
    (row,) = ledger.entries
    assert (row.pid, row.tid) == (None, None)
    assert (row.runtime, row.instr_count) == (0.0, 0)
    assert (row.runtime_share, row.instr_share) == (0.0, 0.0)


def test_segment_without_started_runs_adds_no_ledger():
    profiler = Profiler()
    profiler.begin_usage_segment()
    profiler.close_usage_segment()
    assert profiler.usage_ledgers == []
    assert profiler.get_report().usage is None

    # Closing without an open segment is a no-op as well.
    profiler.close_usage_segment()
    assert profiler.usage_ledgers == []


def test_each_segment_settles_its_own_runs():
    profiler = Profiler()
    add_segment(profiler, [make_run(100, 1000, elapsed=1.0, instr=10)])
    add_segment(profiler, [make_run(200, 2000, elapsed=2.0, instr=30)])

    report = profiler.get_report()
    assert len(report.usage) == 2
    assert report.usage[0].total_instr_count == 10
    assert report.usage[1].total_instr_count == 30
    assert [(row.pid, row.tid) for row in report.usage[1].entries] == [(200, 2000)]


def test_entry_point_carries_its_actual_runtime():
    profiler = Profiler()
    add_segment(profiler, [make_run(100, 1000, elapsed=1.2346, instr=7)])

    (entry,) = profiler.get_report().entry_points
    assert entry.runtime == 1.235
    assert entry.instr_count == 7


# --- End-to-end emulation ------------------------------------------------------


def create_thread_then_spin(thread_code):
    """x86 shellcode: CreateThread(NULL, 0, thread, NULL, 0, NULL); JMP $."""
    code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0\xeb\xfe"
    thread = len(code)
    code += thread_code
    return code, thread


def assert_matches_entry_points(ledger, entries):
    keys = {(ep.pid, ep.tid) for ep in entries}
    row_keys = {(row.pid, row.tid) for row in ledger.entries}
    assert row_keys == keys
    assert ledger.total_instr_count == sum(ep.instr_count or 0 for ep in entries)
    assert ledger.total_runtime == pytest.approx(sum(ep.runtime or 0 for ep in entries), abs=0.01)
    for row in ledger.entries:
        matched = [ep for ep in entries if (ep.pid, ep.tid) == (row.pid, row.tid)]
        assert row.instr_count == sum(ep.instr_count or 0 for ep in matched)
        assert row.instr_share == pytest.approx(
            row.instr_count / ledger.total_instr_count if ledger.total_instr_count else 0.0,
            abs=1e-6,
        )
        assert 0.0 <= row.runtime_share <= 1.0


def test_ledger_splits_capped_runs_by_thread(config):
    config.update(timeout=5, max_instructions=200)
    with Speakeasy(config=config) as se:
        code, thread = create_thread_then_spin(b"\xeb\xfe")  # thread: JMP $
        base = se.load_shellcode(data=code, arch="x86")
        se.mem_write(base + 7, (base + thread).to_bytes(4, "little"))
        se.mem_write(base + 16, se.emu.get_proc("kernel32", "CreateThread").to_bytes(4, "little"))

        se.run_shellcode(base)

        report = se.get_report()
        main, created = report.entry_points
        assert main.error is not None and main.error.type == "max_instructions"
        assert created.error is not None and created.error.type == "max_instructions"

        (ledger,) = report.usage
        assert len(ledger.entries) == 2
        assert [row.instr_count for row in ledger.entries] == [200, 200]
        assert ledger.total_instr_count == 400
        assert [row.instr_share for row in ledger.entries] == [0.5, 0.5]
        assert main.runtime is not None and created.runtime is not None
        assert_matches_entry_points(ledger, report.entry_points)

        # The ledger ships with the existing JSON report, no separate output.
        raw = json.loads(se.get_json_report())
        assert raw["report_version"] == "5.1.0"
        assert raw["usage"][0]["total_instr_count"] == 400
        assert "runtime" in raw["entry_points"][0]


def test_ledger_is_settled_the_same_way_when_the_total_cap_stops_midway(config):
    config.update(timeout=5, max_total_time=0.06, max_instructions=10_000_000)
    with Speakeasy(config=config) as se:
        # The thread start is the shellcode itself, so each created thread
        # respawns; each CreateThread sleeps until the total cap stops midway.
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0\xc3"
        ret = len(code) - 1
        base = se.load_shellcode(data=code, arch="x86")
        create_thread = se.emu.get_proc("kernel32", "CreateThread")
        se.mem_write(base + 7, base.to_bytes(4, "little"))
        se.mem_write(base + 16, create_thread.to_bytes(4, "little"))

        def slow_create_thread(e, api, original, args):
            time.sleep(0.04)
            return original(args)

        se.add_api_hook(slow_create_thread, "kernel32", "CreateThread")
        se.run_shellcode(base)
        after_first = se.get_report()

        (ledger,) = after_first.usage
        assert len(after_first.entry_points) >= 2
        assert any(ep.error is not None and ep.error.type == "max_total_time" for ep in after_first.entry_points)
        assert_matches_entry_points(ledger, after_first.entry_points)
        assert all(row.runtime > 0 for row in ledger.entries)

        # A normal follow-up invocation settles a second ledger on the same report,
        # covering only the run of its own segment.
        se.call(base + ret)  # RET
        report = se.get_report()
        assert len(report.usage) == 2
        second = report.usage[1]
        new_entry = report.entry_points[-1]
        assert len(second.entries) == 1
        assert (second.entries[0].pid, second.entries[0].tid) == (new_entry.pid, new_entry.tid)


def test_one_ledger_per_public_invocation(config):
    config.update(timeout=5, max_instructions=1)
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\x90\xc3", arch="x86")
        se.run_shellcode(base)
        se.run_shellcode(base)

        report = se.get_report()
        first, second = report.entry_points
        assert first.instr_count == second.instr_count == 1
        assert first.error.type == second.error.type == "max_instructions"
        assert len(report.usage) == 2
        assert report.usage[0].total_instr_count == 1
        assert report.usage[1].total_instr_count == 1
        assert_matches_entry_points(report.usage[0], [first])
        assert_matches_entry_points(report.usage[1], [second])


def test_ledger_attributes_child_process_runs_to_their_pid(config, load_test_bin):
    config.update(max_instructions=10_000_000)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin("parent_x86.exe.xz"))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin("child_x86.exe.xz"))
        se.run_module(module, emulate_children=True)

        report = se.get_report()
        parent, child = report.entry_points
        assert (parent.error, child.error) == (None, None)
        assert parent.pid != child.pid

        (ledger,) = report.usage
        pids = {row.pid for row in ledger.entries}
        assert pids == {parent.pid, child.pid}
        assert_matches_entry_points(ledger, report.entry_points)
        assert ledger.total_instr_count > 0
