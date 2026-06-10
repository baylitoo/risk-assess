import pytest

from riskos.ids import kind_of, new_id, stable_id


def test_stable_ids_are_deterministic():
    a = stable_id("component", "Payments-Hub", "Public API")
    b = stable_id("component", "payments-hub", "public api")
    assert a == b  # normalization: case, whitespace
    assert a.startswith("cmp-")


def test_unicode_normalization():
    assert stable_id("system", "Núcleo") == stable_id("system", "nucleo")


def test_different_kinds_never_collide():
    assert stable_id("system", "x") != stable_id("component", "x")


def test_natural_key_order_matters():
    assert stable_id("component", "a", "b") != stable_id("component", "b", "a")


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        stable_id("nonsense", "x")
    with pytest.raises(ValueError):
        new_id("nonsense")


def test_empty_natural_key_rejected():
    with pytest.raises(ValueError):
        stable_id("system", "  ")


def test_kind_roundtrip():
    assert kind_of(stable_id("finding", "x")) == "finding"
    assert kind_of(new_id("evidence")) == "evidence"
    assert kind_of(stable_id("document", "assessment", "sats.md")) == "document"
    assert kind_of(stable_id("chunk", "document", "0")) == "chunk"
