"""Data bundles export the binary payload fragments referenced by reports.

The bundle stores each referenced payload once as plain decoded bytes plus a
manifest recording digest, length, and every report path (source) referencing
it. Readback verifies membership and integrity and can cross-check a report.
"""

import copy
import hashlib
import io
import json
import zipfile

import pytest

from speakeasy import Speakeasy
from speakeasy.data_bundle import MANIFEST_NAME, build_data_bundle, read_data_bundle
from speakeasy.errors import DataBundleError
from speakeasy.profiler import Profiler, Run
from speakeasy.profiler_events import (
    FILE_WRITE,
    REG_WRITE,
    FileWriteEvent,
    RegWriteValueEvent,
    TracePosition,
)
from speakeasy.report import EntryPoint, MemoryLayout, MemoryRegion, Report
from speakeasy.windows.fileman import File
from speakeasy.windows.objman import HandleAllocator


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def finish_report(profiler: Profiler, run: Run) -> Report:
    run.args = []
    run.start_addr = 0x401000
    run.type = "entry_point"
    profiler.add_run(run)
    profiler.stop_run_clock()
    return profiler.get_report()


@pytest.fixture
def populated_report() -> Report:
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    profiler.record_file_access_event(run, pos, "C:\\temp\\download.bin", FILE_WRITE, data=b"downloaded", size=10)
    profiler.record_registry_access_event(
        run,
        pos,
        "HKEY_CURRENT_USER\\Software\\Lab",
        REG_WRITE,
        value_name="Secret",
        data=b"decrypted",
        size=9,
    )
    profiler.record_dropped_files_event(run, [File(HandleAllocator(), "C:\\temp\\drop.bin", data=b"dropped-payload")])
    return finish_report(profiler, run)


def repack(archive: bytes, *, transform=None, skip: tuple[str, ...] = ()) -> bytes:
    """Rewrite a bundle zip, applying ``transform`` and/or dropping members."""

    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(archive)) as src:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
            for info in src.infolist():
                if info.filename in skip:
                    continue
                payload = src.read(info.filename)
                if transform is not None:
                    payload = transform(info.filename, payload)
                dst.writestr(info, payload)
    return out.getvalue()


def test_bundle_exports_plain_decoded_blobs(populated_report):
    archive = build_data_bundle(populated_report)
    bundle = read_data_bundle(archive)

    payloads = [b"downloaded", b"decrypted", b"dropped-payload"]
    assert [entry.sha256 for entry in bundle.entries] == [digest(p) for p in payloads]

    for payload, entry in zip(payloads, bundle.entries):
        assert entry.size == len(payload)
        assert bundle.get_bytes(entry.sha256) == payload
        # The blob is stored raw: consumers no longer base64/zlib-decode it.
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            assert zf.read(entry.file_name) == payload

    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        manifest = json.loads(zf.read(MANIFEST_NAME))
    assert manifest["bundle_type"] == "speakeasy_data_bundle"
    assert len(manifest["entries"]) == 3


def test_bundle_manifest_tracks_each_reference_source(populated_report):
    events = populated_report.entry_points[0].events
    assert isinstance(events[0], FileWriteEvent)
    assert isinstance(events[1], RegWriteValueEvent)

    bundle = read_data_bundle(build_data_bundle(populated_report))
    sources = {entry.sha256: entry.sources for entry in bundle.entries}

    assert sources[digest(b"downloaded")] == ["entry_points[0].events[0].data_ref"]
    assert sources[digest(b"decrypted")] == ["entry_points[0].events[1].data_ref"]
    assert sources[digest(b"dropped-payload")] == ["entry_points[0].dropped_files[0].data_ref"]


def test_bundle_groups_equal_content_under_one_entry():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    profiler.record_file_access_event(run, pos, "C:\\temp\\a.bin", FILE_WRITE, data=b"shared", size=6)
    profiler.record_registry_access_event(
        run, pos, "HKEY_CURRENT_USER\\Software\\Lab", REG_WRITE, value_name="V", data=b"shared", size=6
    )
    report = finish_report(profiler, run)

    bundle = read_data_bundle(build_data_bundle(report))

    assert len(bundle.entries) == 1
    entry = bundle.entries[0]
    assert entry.sha256 == digest(b"shared")
    assert entry.size == 6
    assert entry.sources == [
        "entry_points[0].events[0].data_ref",
        "entry_points[0].events[1].data_ref",
    ]


def test_bundle_builds_from_a_report_loaded_as_json(populated_report):
    report_dict = json.loads(populated_report.model_dump_json())

    bundle = read_data_bundle(build_data_bundle(report_dict), report=report_dict)

    assert {entry.sha256 for entry in bundle.entries} == {
        digest(b"downloaded"),
        digest(b"decrypted"),
        digest(b"dropped-payload"),
    }


def test_bundle_verifies_against_the_source_report(populated_report):
    archive = build_data_bundle(populated_report)

    # Exact cross-check succeeds.
    read_data_bundle(archive, report=populated_report)


def test_bundle_rejects_a_dangling_reference():
    report = Report(
        emulation_total_runtime=0.0,
        timestamp=0,
        entry_points=[
            EntryPoint(
                ep_type="module_entry",
                start_addr=0,
                memory=MemoryLayout(
                    layout=[
                        MemoryRegion(
                            tag="emu.module.main",
                            address=0,
                            size=1,
                            prot="r--",
                            data_ref="a" * 64,
                        )
                    ]
                ),
            )
        ],
    )

    with pytest.raises(DataBundleError, match="missing data store entry"):
        build_data_bundle(report)


def test_bundle_rejects_tampered_blob_content(populated_report):
    archive = build_data_bundle(populated_report)

    def flip_blob(name, payload):
        if name.startswith("blobs/"):
            return bytes([payload[0] ^ 0xFF]) + payload[1:]
        return payload

    tampered = repack(archive, transform=flip_blob)

    with pytest.raises(DataBundleError, match="mismatched digest"):
        read_data_bundle(tampered)


def test_bundle_rejects_a_blob_whose_length_changed(populated_report):
    archive = build_data_bundle(populated_report)

    def append_byte(name, payload):
        if name.startswith("blobs/"):
            return payload + b"\x00"
        return payload

    with pytest.raises(DataBundleError, match="declares"):
        read_data_bundle(repack(archive, transform=append_byte))


def test_bundle_rejects_missing_blob_member(populated_report):
    archive = build_data_bundle(populated_report)
    target = f"blobs/{digest(b'downloaded')}.bin"

    with pytest.raises(DataBundleError, match="missing members"):
        read_data_bundle(repack(archive, skip=(target,)))


def test_bundle_rejects_blob_not_covered_by_manifest(populated_report):
    archive = build_data_bundle(populated_report)

    def drop_manifest_entry(name, payload):
        if name == MANIFEST_NAME:
            manifest = json.loads(payload)
            manifest["entries"].pop(0)
            return json.dumps(manifest).encode()
        return payload

    with pytest.raises(DataBundleError, match="not covered by the manifest"):
        read_data_bundle(repack(archive, transform=drop_manifest_entry))


def test_bundle_rejects_missing_or_corrupt_manifest(populated_report):
    archive = build_data_bundle(populated_report)

    with pytest.raises(DataBundleError, match="missing speakeasy_data_manifest.json"):
        read_data_bundle(repack(archive, skip=(MANIFEST_NAME,)))

    corrupted = repack(
        archive,
        transform=lambda name, payload: b"{not-json" if name == MANIFEST_NAME else payload,
    )
    with pytest.raises(DataBundleError, match="manifest is invalid"):
        read_data_bundle(corrupted)


def test_bundle_rejects_duplicate_manifest_entries(populated_report):
    archive = build_data_bundle(populated_report)

    def duplicate_entry(name, payload):
        if name == MANIFEST_NAME:
            manifest = json.loads(payload)
            manifest["entries"].append(manifest["entries"][0])
            return json.dumps(manifest).encode()
        return payload

    with pytest.raises(DataBundleError, match="duplicate entry"):
        read_data_bundle(repack(archive, transform=duplicate_entry))


def test_bundle_rejects_non_archive_and_empty_input():
    with pytest.raises(DataBundleError, match="not a valid zip"):
        read_data_bundle(b"not a zip archive")
    with pytest.raises(DataBundleError, match="empty"):
        read_data_bundle(b"")


def test_bundle_get_bytes_raises_for_unknown_reference(populated_report):
    bundle = read_data_bundle(build_data_bundle(populated_report))
    with pytest.raises(DataBundleError, match="no payload"):
        bundle.get_bytes("f" * 64)


def test_verify_report_detects_missing_entry_and_source_mismatch(populated_report):
    bundle = read_data_bundle(build_data_bundle(populated_report))

    report_with_extra_ref = Report(
        emulation_total_runtime=0.0,
        timestamp=0,
        entry_points=[
            EntryPoint(
                ep_type="module_entry",
                start_addr=0,
                memory=MemoryLayout(
                    layout=[MemoryRegion(tag="emu.x", address=0, size=1, prot="r--", data_ref="b" * 64)]
                ),
            )
        ],
    )
    with pytest.raises(DataBundleError, match="missing entry"):
        bundle.verify_report(report_with_extra_ref)

    same_digest_other_path = Report(
        emulation_total_runtime=0.0,
        timestamp=0,
        entry_points=[
            EntryPoint(
                ep_type="module_entry",
                start_addr=0,
                memory=MemoryLayout(
                    layout=[
                        MemoryRegion(
                            tag="emu.y",
                            address=0,
                            size=10,
                            prot="rw-",
                            data_ref=digest(b"downloaded"),
                        )
                    ]
                ),
            )
        ],
    )
    with pytest.raises(DataBundleError, match="sources .* do not match"):
        bundle.verify_report(same_digest_other_path)


def test_empty_report_builds_an_empty_manifest_bundle():
    report = Report(emulation_total_runtime=0.0, timestamp=0, entry_points=[])
    bundle = read_data_bundle(build_data_bundle(report))
    assert bundle.entries == []


@pytest.fixture(scope="module")
def snapshot_bundle(base_config, load_test_bin):
    cfg = copy.deepcopy(base_config)
    cfg["snapshot_memory_regions"] = True

    with Speakeasy(config=cfg) as se:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
        archive = se.create_data_archive()
    return report, archive


def test_speakeasy_entry_exports_and_reads_back_memory_snapshots(snapshot_bundle):
    report, archive = snapshot_bundle

    assert archive
    bundle = Speakeasy.read_data_archive(archive, report=report)

    region_refs = [
        (f"entry_points[{ep_index}].memory.layout[{region_index}].data_ref", region.data_ref, region.size)
        for ep_index, ep in enumerate(report.entry_points)
        if ep.memory
        for region_index, region in enumerate(ep.memory.layout)
        if region.data_ref is not None
    ]
    assert region_refs

    manifest_sources = {source for entry in bundle.entries for source in entry.sources}
    entries_by_digest = {entry.sha256: entry for entry in bundle.entries}

    for source_path, ref, size in region_refs:
        assert source_path in manifest_sources
        entry = entries_by_digest[ref]
        assert entry.size == size
        assert len(bundle.get_bytes(ref)) == size

    # Every bundle entry comes from the report data store.
    assert {entry.sha256 for entry in bundle.entries} <= set(report.data)


def test_create_data_archive_is_empty_without_payloads(config):
    with Speakeasy(config=config) as se:
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch="x86"))
        assert se.get_report().data is None
        assert se.create_data_archive() == b""
