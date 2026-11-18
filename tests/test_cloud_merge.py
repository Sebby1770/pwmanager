"""Three-way merge between the CLI vault and the cloud (web) vault."""

from __future__ import annotations

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st

from pwmanager.cloud import entry_from_web, entry_to_web, three_way_merge
from pwmanager.models import Entry


def ids():
    counter = itertools.count(1)
    return lambda: f"new-{next(counter)}"


def L(password="pw", t=10.0, cid="", **kw):
    return Entry(password=password, updated_at=t, created_at=1.0, cloud_id=cid, **kw)


def R(rid, name, password="pw", t=10.0, **kw):
    return {"id": rid, "name": name, "password": password, "updated_at": t, "created_at": 1.0,
            "username": "", "url": "", "notes": "", "tags": [], "totp_secret": "", "history": [],
            "favorite": False, "kind": "login", **kw}


def test_first_sync_pushes_local_and_pulls_remote():
    local = {"github": L()}
    remote = [R("r1", "bank")]
    out_l, out_r, base, rep = three_way_merge(local, remote, {}, new_id=ids())
    assert sorted(out_l) == ["bank", "github"]
    assert {e["name"] for e in out_r} == {"bank", "github"}
    assert out_l["github"].cloud_id == "new-1" and out_l["bank"].cloud_id == "r1"
    assert rep.added_local == ["bank"] and rep.added_remote == ["github"]
    assert set(base) == {"r1", "new-1"}


def test_first_sync_links_same_named_entries_instead_of_duplicating():
    local = {"github": L(password="old", t=5)}
    remote = [R("r1", "github", password="new", t=9)]
    out_l, out_r, _, rep = three_way_merge(local, remote, {})
    assert list(out_l) == ["github"] and len(out_r) == 1
    assert out_l["github"].password == "new" and out_l["github"].cloud_id == "r1"
    assert any(h["password"] == "old" for h in out_l["github"].history), "the older password is kept"


def test_newer_edit_wins_in_both_directions():
    base = {"a": 10.0, "b": 10.0}
    local = {"A": L(password="local-new", t=20, cid="a"), "B": L(password="b-old", t=10, cid="b")}
    remote = [R("a", "A", password="a-old", t=10), R("b", "B", password="remote-new", t=30)]
    out_l, out_r, base2, rep = three_way_merge(local, remote, base)
    remote_by_id = {e["id"]: e for e in out_r}
    assert remote_by_id["a"]["password"] == "local-new" and out_l["B"].password == "remote-new"
    assert rep.updated_remote == ["A"] and rep.updated_local == ["B"] and not rep.conflicts
    assert base2 == {"a": 20.0, "b": 30.0}


def test_deletions_propagate_both_ways():
    base = {"gone-here": 10.0, "gone-there": 10.0}
    local = {"kept": L(cid="gone-there", t=10)}
    remote = [R("gone-here", "x", t=10)]
    out_l, out_r, base2, rep = three_way_merge(local, remote, base)
    assert out_l == {} and out_r == []
    assert rep.deleted_remote == ["x"] and rep.deleted_local == ["kept"] and base2 == {}


def test_edit_beats_delete():
    base = {"a": 10.0, "b": 10.0}
    # a: deleted locally, but edited remotely since the last sync -> comes back.
    # b: deleted remotely, but edited locally since -> re-uploaded.
    local = {"B": L(cid="b", t=50)}
    remote = [R("a", "A", t=40)]
    out_l, out_r, _, rep = three_way_merge(local, remote, base)
    assert sorted(out_l) == ["A", "B"] and {e["id"] for e in out_r} == {"a", "b"}
    assert rep.added_local == ["A"] and rep.added_remote == ["B"]


def test_conflict_keeps_newer_and_records_the_other_password():
    base = {"a": 10.0}
    local = {"A": L(password="mine", t=20, cid="a")}
    remote = [R("a", "A", password="theirs", t=30)]
    out_l, _, _, rep = three_way_merge(local, remote, base)
    assert rep.conflicts == ["A"] and out_l["A"].password == "theirs"
    assert out_l["A"].history[0]["password"] == "mine"


def test_duplicate_remote_names_get_unique_local_names():
    remote = [R("r1", "mail"), R("r2", "mail"), R("r3", "mail")]
    out_l, out_r, _, _ = three_way_merge({}, remote, {})
    assert sorted(out_l) == ["mail", "mail (2)", "mail (3)"]
    assert [e["name"] for e in out_r] == ["mail"] * 3, "remote names are not rewritten"


def test_unknown_remote_fields_survive_a_local_edit():
    remote = [R("a", "A", t=10, passkey_hint="from a newer web client")]
    local = {"A": L(password="changed", t=20, cid="a")}
    _, out_r, _, _ = three_way_merge(local, remote, {"a": 10.0})
    assert out_r[0]["passkey_hint"] == "from a newer web client" and out_r[0]["password"] == "changed"


def test_rename_follows_the_cloud_id():
    local = {"renamed": L(cid="a", t=20)}
    remote = [R("a", "original", t=10)]
    out_l, out_r, _, _ = three_way_merge(local, remote, {"a": 10.0})
    assert list(out_l) == ["renamed"] and out_r[0]["name"] == "renamed"


def test_pull_mode_never_changes_the_remote_and_never_forgets_local_entries():
    base = {"gone-here": 10.0}
    local = {"local-only": L()}
    remote = [R("gone-here", "x", t=10), R("r2", "new-remote")]
    out_l, out_r, base2, rep = three_way_merge(local, remote, base, mode="pull", new_id=ids())
    assert out_r == remote
    assert sorted(out_l) == ["local-only", "new-remote"]
    # The never-uploaded entry is not in the base, so a later sync uploads it
    # instead of treating it as deleted in the cloud.
    assert out_l["local-only"].cloud_id not in base2
    assert base2["gone-here"] == 10.0, "a later sync still deletes it remotely"
    _, out_r2, _, rep2 = three_way_merge(out_l, out_r, base2, new_id=ids())
    assert {e["name"] for e in out_r2} == {"local-only", "new-remote"}
    assert rep2.added_remote == ["local-only"] and rep2.deleted_remote == ["x"]


def test_inputs_are_not_mutated():
    local = {"a": L()}
    three_way_merge(local, [R("r", "a", password="other", t=99)], {})
    assert local["a"].cloud_id == "" and local["a"].password == "pw" and local["a"].history == []


def test_web_mapping_roundtrips():
    entry = L(password="p", t=7.5, cid="x1", username="u", url="https://e.x", notes="n", tags=["t"],
              totp_secret="JBSWY3DP", favorite=True, kind="note", rotate_after_days=30)
    name, back = entry_from_web(entry_to_web("name", entry))
    assert name == "name" and back.to_dict() == entry.to_dict()


# ------------------------------------------------------------------ properties

names = st.sampled_from(["a", "b", "c", "d", "e"])
stamps = st.integers(min_value=1, max_value=50).map(float)


@st.composite
def worlds(draw):
    remote = [R(f"r{i}", draw(names), password=draw(st.text(max_size=4)), t=draw(stamps))
              for i in range(draw(st.integers(0, 5)))]
    local = {}
    for name in draw(st.lists(names, unique=True, max_size=5)):
        cid = draw(st.sampled_from(["", "r0", "r1", "r9"]))
        local[name] = L(password=draw(st.text(max_size=4)), t=draw(stamps), cid=cid)
    base = {rid: draw(stamps) for rid in draw(st.lists(st.sampled_from(["r0", "r1", "r2", "r9"]), unique=True))}
    return local, remote, base


@settings(max_examples=300, deadline=None)
@given(worlds())
def test_sync_is_idempotent(world):
    local, remote, base = world
    out_l, out_r, base2, _ = three_way_merge(local, remote, base, new_id=ids())
    again_l, again_r, base3, rep = three_way_merge(out_l, out_r, base2, new_id=ids())
    assert not rep.local_changed and not rep.remote_changed and not rep.conflicts
    assert {n: e.to_dict() for n, e in again_l.items()} == {n: e.to_dict() for n, e in out_l.items()}
    assert base3 == base2


@settings(max_examples=300, deadline=None)
@given(worlds())
def test_both_sides_agree_after_sync(world):
    local, remote, base = world
    out_l, out_r, _, _ = three_way_merge(local, remote, base, new_id=ids())
    assert {e.cloud_id for e in out_l.values()} == {e["id"] for e in out_r}
    assert len(set(out_l)) == len(out_l)


@settings(max_examples=300, deadline=None)
@given(worlds())
def test_nothing_unsynced_is_ever_lost(world):
    """An entry disappears only if it was in the base (synced before) and untouched since."""
    local, remote, base = world
    out_l, out_r, _, _ = three_way_merge(local, remote, base, new_id=ids())
    kept_ids = {e["id"] for e in out_r}
    for item in remote:
        if item["id"] not in kept_ids:
            assert item["id"] in base and item["updated_at"] <= base[item["id"]]
    surviving_passwords = {e.password for e in out_l.values()} | {
        h["password"] for e in out_l.values() for h in e.history}
    for entry in local.values():
        # Older versions may lose to newer ones, but a non-empty password is
        # never dropped: it survives as the value or in history.
        if (not entry.cloud_id or entry.cloud_id not in base) and entry.password:
            assert entry.password in surviving_passwords


def test_undated_remote_entries_do_not_resurrect():
    """A remote entry with no updated_at must not look freshly edited on every read."""
    item = {"id": "u1", "name": "undated", "password": "p"}
    out_l, out_r, base, _ = three_way_merge({}, [item], {})
    assert base == {"u1": 0.0}
    # Deleted locally after that sync: the next sync deletes it remotely too.
    _, out_r2, _, rep = three_way_merge({}, [item], base)
    assert out_r2 == [] and rep.deleted_remote == ["undated"]
