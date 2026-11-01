"""Configured regex masking for exported JSON reports."""

import json
import logging
import subprocess
import sys

import pytest
from pydantic import ValidationError

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig, get_default_config_dict
from speakeasy.errors import ConfigError
from speakeasy.report_masking import mask_report_data, mask_report_json

ARGV_TEST_BIN = "argv_test_x86.exe.xz"
SECRET_TOKEN = "secret-token-xyz"

MASKING_SECTION = {
    "report_masking": {
        "rules": [
            {"name": "token", "pattern": SECRET_TOKEN, "replacement": "[REDACTED]"},
            {"name": "never_hits", "pattern": "zz-no-such-value-zz"},
        ]
    }
}


def _rules(rules):
    return SpeakeasyConfig.model_validate({"report_masking": {"rules": rules}}).report_masking.rules


# --- config validation -------------------------------------------------------


def test_default_config_ships_without_masking_rules():
    config = SpeakeasyConfig.model_validate(get_default_config_dict())

    assert config.report_masking.rules == []


def test_masking_rules_round_trip_through_config_dump():
    config = SpeakeasyConfig.model_validate(MASKING_SECTION)
    restored = SpeakeasyConfig.model_validate(config.model_dump(mode="python"))

    assert [rule.name for rule in restored.report_masking.rules] == ["token", "never_hits"]
    assert restored.report_masking.rules[0].replacement == "[REDACTED]"


def test_invalid_regex_reports_rule_location_and_reason():
    with pytest.raises(ValidationError) as exc_info:
        SpeakeasyConfig.model_validate({"report_masking": {"rules": [{"name": "bad", "pattern": "("}]}})

    error = exc_info.value.errors()[0]
    assert error["loc"] == ("report_masking", "rules", 0, "pattern")
    assert "invalid regular expression" in error["msg"]
    assert "missing )" in error["msg"]


@pytest.mark.parametrize(
    "pattern,replacement",
    [
        ("x", r"\1"),  # group reference with no matching group
        ("x", r"\g<name>"),  # named group that does not exist
        ("x", r"\g<"),  # unterminated group name
        ("x", r"\j"),  # bad escape
    ],
)
def test_invalid_replacement_template_is_rejected(pattern, replacement):
    with pytest.raises(ValidationError) as exc_info:
        SpeakeasyConfig.model_validate(
            {"report_masking": {"rules": [{"name": "bad", "pattern": pattern, "replacement": replacement}]}}
        )

    error = exc_info.value.errors()[0]
    assert error["loc"] == ("report_masking", "rules", 0)
    assert "invalid replacement template" in error["msg"]


def test_replacement_backreference_is_accepted_when_group_exists():
    config = SpeakeasyConfig.model_validate(
        {"report_masking": {"rules": [{"name": "keep", "pattern": "(token-\\d+)", "replacement": r"[\1]"}]}}
    )

    assert config.report_masking.rules[0].replacement == r"[\1]"


@pytest.mark.parametrize("name", ["", "   "])
def test_empty_rule_name_is_rejected(name):
    with pytest.raises(ValidationError) as exc_info:
        SpeakeasyConfig.model_validate({"report_masking": {"rules": [{"name": name, "pattern": "x"}]}})

    assert "must not be empty" in exc_info.value.errors()[0]["msg"]


def test_duplicate_rule_names_are_rejected():
    with pytest.raises(ValidationError, match="duplicate masking rule name"):
        SpeakeasyConfig.model_validate(
            {
                "report_masking": {
                    "rules": [
                        {"name": "same", "pattern": "a"},
                        {"name": "same", "pattern": "b"},
                    ]
                }
            }
        )


def test_speakeasy_constructor_surfaces_bad_rule_as_config_error():
    conf = get_default_config_dict()
    conf["report_masking"] = {"rules": [{"name": "bad", "pattern": "("}]}

    with pytest.raises(ConfigError):
        Speakeasy(config=conf)


# --- masking engine ----------------------------------------------------------


def test_masking_rewrites_nested_strings_and_counts_hits():
    data = {
        "path": "/Users/alice/secret/sample.exe",
        "events": [
            {"cred": "Bearer abc123 and Bearer def456", "n": 4},
            "plain",
            True,
            None,
        ],
    }
    rules = _rules(
        [
            {"name": "home", "pattern": r"/Users/alice/secret", "replacement": "[PATH]"},
            {"name": "bearer", "pattern": r"Bearer \w+", "replacement": "Bearer <token>"},
        ]
    )

    masked, counts = mask_report_data(data, rules)

    assert masked == {
        "path": "[PATH]/sample.exe",
        "events": [
            {"cred": "Bearer <token> and Bearer <token>", "n": 4},
            "plain",
            True,
            None,
        ],
    }
    assert counts == {"home": 1, "bearer": 2}


def test_masking_preserves_dict_keys_and_structure():
    data = {SECRET_TOKEN: [SECRET_TOKEN, {"k": SECRET_TOKEN}], "untouched": 1}

    masked, _ = mask_report_data(data, _rules([{"name": "token", "pattern": SECRET_TOKEN}]))

    assert list(masked) == [SECRET_TOKEN, "untouched"]
    assert masked[SECRET_TOKEN] == ["[REDACTED]", {"k": "[REDACTED]"}]
    assert masked["untouched"] == 1


def test_masking_does_not_mutate_input():
    data = {"nested": [SECRET_TOKEN]}

    masked, _ = mask_report_data(data, _rules([{"name": "token", "pattern": SECRET_TOKEN}]))

    assert data == {"nested": [SECRET_TOKEN]}
    assert masked == {"nested": ["[REDACTED]"]}


def test_zero_hit_rules_are_reported_with_count_zero():
    _, counts = mask_report_data({"a": "nothing here"}, _rules([{"name": "absent", "pattern": SECRET_TOKEN}]))

    assert counts == {"absent": 0}


def test_rules_run_in_configured_order():
    rules = _rules(
        [
            {"name": "first", "pattern": "abc", "replacement": "xyz"},
            {"name": "second", "pattern": "xyz", "replacement": "FINAL"},
        ]
    )

    masked, counts = mask_report_data("abc", rules)

    assert masked == "FINAL"
    assert counts == {"first": 1, "second": 1}


def test_replacement_backreferences_are_supported():
    rules = _rules([{"name": "user", "pattern": r"user=(\w+)", "replacement": r"user=<\1>"}])

    masked, counts = mask_report_data("user=alice", rules)

    assert masked == "user=<alice>"
    assert counts == {"user": 1}


def test_mask_report_json_keeps_unicode_and_round_trips():
    report_text = json.dumps({"msg": "café 凭据 secret", "n": 1}, ensure_ascii=False)
    rules = _rules([{"name": "token", "pattern": SECRET_TOKEN, "replacement": "X"}])
    # No match: content must survive unchanged and stay valid JSON.
    masked, counts = mask_report_json(report_text, rules)

    assert json.loads(masked)["msg"] == "café 凭据 secret"
    assert "凭据" in masked
    assert counts == {"token": 0}


# --- end-to-end export -------------------------------------------------------


def _run_with_masking(config, load_test_bin):
    config["report_masking"] = MASKING_SECTION["report_masking"]
    with Speakeasy(config=config, argv=[SECRET_TOKEN]) as se:
        module = se.load_module(data=load_test_bin(ARGV_TEST_BIN))
        se.run_module(module)
        raw_text = se.emu.get_json_report()
        masked_text = se.get_json_report()
        report = se.get_report()
    return raw_text, masked_text, report


def test_json_export_is_masked_but_raw_report_is_not(config, load_test_bin, caplog):
    caplog.set_level(logging.INFO, logger="speakeasy")

    raw_text, masked_text, report = _run_with_masking(config, load_test_bin)

    assert SECRET_TOKEN in raw_text
    assert SECRET_TOKEN not in masked_text
    assert "[REDACTED]" in masked_text

    # Structure is preserved.
    raw_data, masked_data = json.loads(raw_text), json.loads(masked_text)
    assert set(raw_data) == set(masked_data)
    assert len(raw_data["entry_points"]) == len(masked_data["entry_points"])

    # The in-memory report and the emulator-level export stay unmasked.
    displays = [
        arg.display
        for ep in report.entry_points
        for event in (ep.events or [])
        for arg in (event.args or [])
        if getattr(arg, "display", None)
    ]
    assert any(SECRET_TOKEN in display for display in displays)

    messages = [record.getMessage() for record in caplog.records]
    assert any("'token' replaced 1 occurrence" in message for message in messages)
    assert any("'never_hits' replaced 0 occurrences" in message for message in messages)


def test_export_without_rules_is_unchanged(config, load_test_bin):
    with Speakeasy(config=config, argv=[SECRET_TOKEN]) as se:
        module = se.load_module(data=load_test_bin(ARGV_TEST_BIN))
        se.run_module(module)
        assert se.get_json_report() == se.emu.get_json_report()


def test_cli_export_writes_masked_report(tmp_path, load_test_bin):
    target = tmp_path / "argv_test.exe"
    target.write_bytes(load_test_bin(ARGV_TEST_BIN))
    config_path = tmp_path / "mask.json"
    config_path.write_text(json.dumps(MASKING_SECTION))
    output = tmp_path / "report.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "speakeasy.cli",
            "--no-mp",
            "-t",
            str(target),
            "-c",
            str(config_path),
            "--argv",
            SECRET_TOKEN,
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    exported = output.read_text()
    assert SECRET_TOKEN not in exported
    assert "[REDACTED]" in exported
    json.loads(exported)  # the masked export stays valid JSON
