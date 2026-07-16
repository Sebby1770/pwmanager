"""Tests for fuzzy search."""

from __future__ import annotations

from pwmanager.models import Entry
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"


def _vault_with_entries(tmp_path) -> Vault:
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.add(
        "GitHub",
        Entry(username="dev", password="x" * 20, tags=["work"], url="https://github.com"),
    )
    v.add(
        "GitLab",
        Entry(username="dev", password="y" * 20, tags=["work"], url="https://gitlab.com"),
    )
    v.add(
        "Bank of America",
        Entry(username="me", password="z" * 20, tags=["finance"], notes="savings"),
    )
    v.add(
        "Amazon AWS",
        Entry(username="cloud", password="w" * 20, tags=["cloud"], favorite=True),
    )
    return v


def test_exact_search_still_works(tmp_path):
    v = _vault_with_entries(tmp_path)
    assert v.search("github") == ["GitHub"]
    assert "GitHub" in v.search("git")


def test_fuzzy_finds_close_names(tmp_path):
    v = _vault_with_entries(tmp_path)
    # Typo / near miss that may not be exact substring of all fields
    hits = v.fuzzy_search("githb", cutoff=0.4)
    names = [n for n, _ in hits]
    assert "GitHub" in names
    # Scores descending
    scores = [s for _, s in hits]
    assert scores == sorted(scores, reverse=True)


def test_fuzzy_excludes_exact_matches(tmp_path):
    v = _vault_with_entries(tmp_path)
    exact = v.search("git")
    fuzzy = v.fuzzy_search("git", exclude=exact, cutoff=0.3)
    for name, _ in fuzzy:
        assert name not in exact


def test_fuzzy_respects_tag_filter(tmp_path):
    v = _vault_with_entries(tmp_path)
    hits = v.fuzzy_search("git", tag="finance", cutoff=0.2)
    # finance entries shouldn't match github strongly, but if any, not GitHub
    for name, _ in hits:
        assert "work" not in v.entries[name].tags or name != "GitHub"
    # Bank may appear with low score; GitHub filtered by tag
    assert all("finance" in v.entries[n].tags for n, _ in hits)


def test_fuzzy_empty_query(tmp_path):
    v = _vault_with_entries(tmp_path)
    assert v.fuzzy_search("") == []
