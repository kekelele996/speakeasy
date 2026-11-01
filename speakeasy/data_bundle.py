# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Build and verify data bundles for report payload fragments.

Reports keep deduplicated binary payloads (memory snapshots, file and registry
bytes, network traffic) in a compressed top-level ``data`` store and reference
them from run records through ``data_ref``/``body_ref`` fields. A data bundle
exports the referenced payloads as plain, content-addressed blob files plus a
manifest recording each blob's digest, length, and every report path that
references it.
"""

import hashlib
import zipfile
from base64 import b64decode
from collections.abc import Iterator
from io import BytesIO
from typing import Any, Literal
from zlib import decompress

from pydantic import ValidationError

from speakeasy.errors import DataBundleError
from speakeasy.report import DataArtifact, DataBundleEntry, DataBundleManifest, Report

MANIFEST_NAME = "speakeasy_data_manifest.json"
BLOB_PREFIX = "blobs/"
BLOB_SUFFIX = ".bin"
BUNDLE_TYPE: Literal["speakeasy_data_bundle"] = "speakeasy_data_bundle"
BUNDLE_VERSION = "1.0.0"

# Report fields that hold a reference (SHA-256 key) into the data store.
REF_FIELD_NAMES = frozenset({"data_ref", "body_ref"})


def blob_name(sha256: str) -> str:
    """Return the zip member path used for one payload blob."""

    return f"{BLOB_PREFIX}{sha256}{BLOB_SUFFIX}"


def _coerce_report(report: Report | dict[str, Any]) -> Report:
    if isinstance(report, Report):
        return report
    if isinstance(report, dict):
        try:
            return Report.model_validate(report)
        except ValidationError as exc:
            raise DataBundleError(f"invalid report supplied to data bundle: {exc}") from exc
    raise DataBundleError(f"expected a Report model or report dict, got {type(report).__name__}")


def _join_field(path: str, field_name: str) -> str:
    return field_name if not path else f"{path}.{field_name}"


def _iter_refs(value: Any, path: str = "", field_name: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(report_path, ref)`` pairs for every ``data_ref``/``body_ref`` leaf.

    The walk is generic over pydantic models, dicts, and lists so it keeps
    covering new event types without changes. The top-level data store itself
    is skipped: it defines the references rather than holding any.
    """

    if field_name in REF_FIELD_NAMES:
        if value is not None:
            if not isinstance(value, str):
                raise DataBundleError(f"report reference at {path} must be a string, got {type(value).__name__}")
            yield path, value
        return

    model_fields = getattr(type(value), "model_fields", None)
    if model_fields is not None:
        for name in model_fields:
            if path == "" and name == "data":
                continue
            yield from _iter_refs(getattr(value, name), _join_field(path, name), name)
        for name, child in (getattr(value, "model_extra", None) or {}).items():
            yield from _iter_refs(child, _join_field(path, name), name)
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_refs(child, f"{path}[{key!r}]" if path else str(key))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _iter_refs(child, f"{path}[{index}]", "")
    # Other values are scalar leaves without references and need no traversal.


def decode_artifact(artifact: DataArtifact) -> bytes:
    """Decode one report data-store entry into its plain payload bytes."""

    if artifact.compression != "zlib":
        raise DataBundleError(f"unsupported artifact compression: {artifact.compression}")
    if artifact.encoding != "base64":
        raise DataBundleError(f"unsupported artifact encoding: {artifact.encoding}")
    try:
        payload = decompress(b64decode(artifact.data))
    except Exception as exc:
        raise DataBundleError("failed to decode report data store entry") from exc
    if len(payload) != artifact.size:
        raise DataBundleError(
            f"artifact size mismatch: manifest declares {artifact.size} bytes, decoded {len(payload)} bytes"
        )
    return payload


def build_data_bundle(report: Report | dict[str, Any]) -> bytes:
    """Build a zip data bundle containing every payload referenced by a report.

    Payloads are grouped by content (SHA-256 key) and stored once as plain
    decoded bytes. The manifest records length, digest, and every referencing
    report path.

    Raises:
        DataBundleError: a reference is dangling, a stored artifact cannot be
            decoded, or its digest does not match its data-store key.
    """

    report = _coerce_report(report)
    data = report.data or {}

    sources: dict[str, list[str]] = {}
    order: list[str] = []
    payloads: dict[str, bytes] = {}

    for source_path, ref in _iter_refs(report):
        artifact = data.get(ref)
        if artifact is None:
            raise DataBundleError(f"report reference {source_path} points to missing data store entry: {ref}")
        payload = decode_artifact(artifact)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != ref:
            raise DataBundleError(f"data store entry {ref} holds bytes with mismatched digest {digest}")
        if ref not in sources:
            sources[ref] = []
            order.append(ref)
            payloads[ref] = payload
        sources[ref].append(source_path)

    entries = [
        DataBundleEntry(
            sha256=ref,
            size=len(payloads[ref]),
            file_name=blob_name(ref),
            sources=sources[ref],
        )
        for ref in order
    ]
    manifest = DataBundleManifest(bundle_type=BUNDLE_TYPE, bundle_version=BUNDLE_VERSION, entries=entries)

    archive = BytesIO()
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST_NAME, manifest.model_dump_json(indent=2))
        for ref in order:
            zf.writestr(blob_name(ref), payloads[ref])
    return archive.getvalue()


class DataBundle:
    """Verified contents of a data bundle read back from a zip archive."""

    def __init__(self, manifest: DataBundleManifest, payloads: dict[str, bytes]):
        self._manifest = manifest
        self._payloads = payloads

    @property
    def manifest(self) -> DataBundleManifest:
        return self._manifest

    @property
    def entries(self) -> list[DataBundleEntry]:
        return list(self._manifest.entries)

    def get_bytes(self, ref: str) -> bytes:
        """Return the plain payload bytes for one SHA-256 reference."""

        try:
            return self._payloads[ref]
        except KeyError:
            raise DataBundleError(f"data bundle has no payload for reference: {ref}") from None

    def verify_report(self, report: Report | dict[str, Any]) -> None:
        """Check that the bundle covers exactly the references in a report.

        Raises:
            DataBundleError: a report reference has no manifest entry, a
                manifest entry is not referenced by the report, or recorded
                source paths do not line up with the report.
        """

        report = _coerce_report(report)
        expected: dict[str, list[str]] = {}
        for source_path, ref in _iter_refs(report):
            expected.setdefault(ref, []).append(source_path)

        actual = {entry.sha256: set(entry.sources) for entry in self._manifest.entries}

        for ref, source_paths in expected.items():
            if ref not in actual:
                raise DataBundleError(f"manifest is missing entry {ref} referenced at {source_paths[0]}")
            if actual[ref] != set(source_paths):
                raise DataBundleError(f"manifest sources for {ref} do not match the report references")

        unreferenced = set(actual) - set(expected)
        if unreferenced:
            raise DataBundleError(
                "manifest contains entries not referenced by the report: " + ", ".join(sorted(unreferenced))
            )


def read_data_bundle(data: bytes, report: Report | dict[str, Any] | None = None) -> DataBundle:
    """Read and verify a data bundle produced by :func:`build_data_bundle`.

    Every manifest entry must have a matching blob, every blob must be listed
    in the manifest, and blob length/SHA-256 must match. When ``report`` is
    supplied, its references are additionally checked against the manifest.

    Raises:
        DataBundleError: the archive or manifest is malformed, a member is
            missing or unexpected, or content verification fails.
    """

    if not data:
        raise DataBundleError("data bundle is empty")

    try:
        zf = zipfile.ZipFile(BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise DataBundleError(f"not a valid zip data bundle: {exc}") from exc

    with zf:
        names = set(zf.namelist())
        if MANIFEST_NAME not in names:
            raise DataBundleError(f"data bundle is missing {MANIFEST_NAME}")

        try:
            manifest = DataBundleManifest.model_validate_json(zf.read(MANIFEST_NAME))
        except ValidationError as exc:
            raise DataBundleError(f"data bundle manifest is invalid: {exc}") from exc

        seen: set[str] = set()
        for entry in manifest.entries:
            if entry.sha256 in seen:
                raise DataBundleError(f"manifest lists duplicate entry: {entry.sha256}")
            seen.add(entry.sha256)

        expected_names = {MANIFEST_NAME} | {entry.file_name for entry in manifest.entries}
        missing_members = expected_names - names
        if missing_members:
            raise DataBundleError(
                "data bundle is missing members listed in the manifest: " + ", ".join(sorted(missing_members))
            )
        unexpected_members = names - expected_names
        if unexpected_members:
            raise DataBundleError(
                "data bundle contains members not covered by the manifest: " + ", ".join(sorted(unexpected_members))
            )

        payloads: dict[str, bytes] = {}
        for entry in manifest.entries:
            payload = zf.read(entry.file_name)
            if len(payload) != entry.size:
                raise DataBundleError(
                    f"bundled payload {entry.sha256} has {len(payload)} bytes, manifest declares {entry.size}"
                )
            digest = hashlib.sha256(payload).hexdigest()
            if digest != entry.sha256:
                raise DataBundleError(f"bundled payload {entry.sha256} has mismatched digest {digest}")
            payloads[entry.sha256] = payload

    bundle = DataBundle(manifest, payloads)
    if report is not None:
        bundle.verify_report(report)
    return bundle
