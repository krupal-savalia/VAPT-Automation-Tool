import pytest

from scanner.mutation_engine import MutationEngine


def test_mutations():
    engine = MutationEngine()
    original = "test123"
    mutated = engine.mutate(original, ["url_encode", "case_mutation", "unicode_encode"])
    assert mutated[0] == "test123"  # no special chars so url encoding is same
    assert mutated[1] != original
    assert "%u" in mutated[2]


def test_unknown_strategy_returns_original():
    engine = MutationEngine()
    assert engine.mutate("foo", ["nosuch"]) == ["foo"]
