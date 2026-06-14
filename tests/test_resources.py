"""Resource extraction (ADR-0010): lift only the declared scoping id, never
the payload; hash it when sensitive; fail closed when absent."""

from __future__ import annotations

import hashlib

import pytest

from olive.gateway.resources import ResourceExtractor, extract_resource


def test_extracts_declared_scoping_id():
    ex = ResourceExtractor(type="order", id_arg="order_id", classification="customer-pii")
    ref = ex.extract({"order_id": 4471, "note": "ignored payload"})
    assert ref.type == "order"
    assert ref.id == "4471"  # stringified scoping key only
    assert ref.classification == "customer-pii"
    assert ref.id_hashed is False


def test_only_the_scoping_arg_is_read_not_the_payload():
    ex = ResourceExtractor(type="order", id_arg="order_id")
    ref = ex.extract({"order_id": "A1", "body": "secret customer data"})
    # The ref carries the id and labels - nothing from `body` is reachable.
    assert ref.id == "A1"
    assert "secret" not in (ref.id + ref.type + (ref.classification or ""))


def test_absent_scoping_arg_yields_empty_id_fail_closed():
    ex = ResourceExtractor(type="order", id_arg="order_id")
    ref = ex.extract({"other": "x"})
    assert ref.id == ""  # predicates requiring a matching id will then fail closed


def test_none_arguments_yields_empty_id():
    ex = ResourceExtractor(type="file", id_arg="path")
    assert ex.extract(None).id == ""


def test_sensitive_id_is_hashed():
    ex = ResourceExtractor(type="account", id_arg="ssn", hash_id=True)
    ref = ex.extract({"ssn": "123-45-6789"})
    assert ref.id_hashed is True
    assert ref.id == hashlib.sha256(b"123-45-6789").hexdigest()
    assert "123-45-6789" not in ref.id


def test_extract_resource_returns_none_when_no_extractor_declared():
    assert extract_resource("unscoped.tool", {}, {"x": 1}) is None


def test_extract_resource_uses_matching_extractor():
    extractors = {"support.read_order": ResourceExtractor(type="order", id_arg="order_id")}
    ref = extract_resource("support.read_order", extractors, {"order_id": "9"})
    assert ref is not None and ref.id == "9"


@pytest.mark.parametrize("value,expected", [(0, "0"), (False, "False"), ("", "")])
def test_falsy_ids_stringify_predictably(value, expected):
    ex = ResourceExtractor(type="t", id_arg="k")
    assert ex.extract({"k": value}).id == expected
