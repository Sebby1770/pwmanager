"""Zero-knowledge cloud sync for the CLI vault.

Speaks the same protocol as the web vault (web/saas/*.js): derive keys from the
*cloud* master password with ``cloudkdf``, send only authKey, and exchange
AES-256-GCM envelopes the server cannot read.

What is stored on disk, per local vault (``~/.config/pwmanager/cloud/*.json``,
mode 0600): server URL, email, session token, the KDF strength last used (the
downgrade guard), a key-check value, and the *base* of the last sync: each
entry's cloud id and ``updated_at``. Never the password, vaultKey or authKey.

Merging is three-way against that base, so a deletion on either side
propagates instead of the entry being resurrected by the other side.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pwmanager import __version__, cloudkdf
from pwmanager.models import Entry
from pwmanager.profiles import config_dir

AAD = b"pwmanager-vault-v1"
STATE_MODE = 0o600
_ENTRY_FIELDS = ("username", "password", "url", "notes", "tags", "totp_secret", "history", "created_at",
                 "updated_at", "favorite", "kind", "rotate_after_days", "last_accessed")


class CloudError(Exception):
    def __init__(self, message: str, code: str = "cloud_error", status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status


# --------------------------------------------------------------------------- transport


def check_server_url(url: str) -> str:
    """Normalise a server URL; refuse plaintext HTTP except to this machine."""
    parsed = urllib.parse.urlparse((url or "").strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise CloudError("Server must be an https:// URL", "bad_server")
    if parsed.scheme == "http":
        host = parsed.hostname
        loopback = host == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if not loopback:
            raise CloudError("Refusing plain http:// to a remote server: the session token would travel unencrypted",
                             "insecure_server")
    return f"{parsed.scheme}://{parsed.netloc}"


class CloudClient:
    def __init__(self, server: str, token: str = "", timeout: float = 30):
        self.server = check_server_url(server)
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Any = None, headers: Optional[dict] = None):
        data = None
        hdrs = {"Accept": "application/json", "User-Agent": f"pwmanager-cli/{__version__}"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if self.token:
            hdrs["Authorization"] = "Bearer " + self.token
        hdrs.update(headers or {})
        req = urllib.request.Request(self.server + path, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {}), resp.headers
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {}
            raise CloudError(payload.get("message") or f"HTTP {exc.code}", payload.get("error") or "http_error",
                             exc.code) from None
        except urllib.error.URLError as exc:
            raise CloudError(f"Could not reach {self.server}: {exc.reason}", "network") from None

    @staticmethod
    def _token_from(headers) -> str:
        cookie = headers.get("Set-Cookie") or ""
        if "pwmanager_session=" not in cookie:
            return ""
        return cookie.split("pwmanager_session=", 1)[1].split(";", 1)[0]

    def prelogin(self, email: str) -> dict:
        return self._request("POST", "/api/prelogin", {"email": email})[1]

    def login(self, email: str, auth_key_b64: str) -> dict:
        _status, body, headers = self._request("POST", "/api/login", {"email": email, "auth_key": auth_key_b64})
        self.token = self._token_from(headers) or self.token
        return body

    def login_recovery(self, ceremony: str, code: str) -> dict:
        _status, body, headers = self._request("POST", "/api/login/recovery", {"ceremony": ceremony, "code": code})
        self.token = self._token_from(headers) or self.token
        return body

    def me(self) -> dict:
        return self._request("GET", "/api/me")[1]["account"]

    def get_vault(self) -> Tuple[Optional[dict], Optional[str]]:
        try:
            body = self._request("GET", "/api/vault")[1]
        except CloudError as exc:
            if exc.status == 404:
                return None, None
            raise
        return body["envelope"], body.get("etag")

    def put_vault(self, envelope: dict, etag: Optional[str]) -> dict:
        headers = {"If-Match": etag} if etag else {"If-None-Match": "*"}
        return self._request("PUT", "/api/vault", envelope, headers=headers)[1]

    def logout(self) -> None:
        try:
            self._request("POST", "/api/logout", {})
        except CloudError:
            pass


# --------------------------------------------------------------------------- state


def state_path(vault_path: str) -> Path:
    key = hashlib.sha256(os.path.abspath(vault_path).encode("utf-8")).hexdigest()[:16]
    return config_dir() / "cloud" / f"{key}.json"


def load_state(vault_path: str) -> Optional[dict]:
    path = state_path(vault_path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise CloudError(f"Cloud link file is unreadable ({path}): {exc}", "bad_state") from exc
    return state if isinstance(state, dict) else None


def save_state(vault_path: str, state: dict) -> Path:
    path = state_path(vault_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = str(path) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, STATE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return path


def delete_state(vault_path: str) -> bool:
    try:
        os.unlink(state_path(vault_path))
        return True
    except FileNotFoundError:
        return False


def key_check(auth_key: bytes) -> str:
    """Lets a later sync confirm the password without storing anything that opens the vault."""
    return hmac.new(auth_key, b"pwmanager-cli key check v1", hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- envelopes


@dataclass
class CloudKeys:
    vault_key: bytes
    auth_key: bytes
    salt_b64: str
    params: dict

    @property
    def auth_b64(self) -> str:
        return base64.b64encode(self.auth_key).decode("ascii")


def derive_for(prelogin: dict, email: str, password: str, min_rank: int = 0) -> CloudKeys:
    params = prelogin.get("kdf_params")
    try:
        canonical = cloudkdf.normalize(params)
    except cloudkdf.KdfError as exc:
        raise CloudError(f"The server offered key-derivation settings this client refuses: {exc}", "kdf_refused")
    if cloudkdf.rank(canonical) < min_rank:
        raise CloudError("The server asked for a weaker key derivation than this vault has already used. Refusing.",
                         "kdf_downgrade")
    salt = base64.b64decode(prelogin.get("kdf_salt") or "")
    vault_key, auth_key, canonical = cloudkdf.derive_keys(password, email, salt, canonical)
    return CloudKeys(vault_key, auth_key, prelogin["kdf_salt"], canonical)


def open_envelope(envelope: dict, keys: CloudKeys) -> dict:
    try:
        nonce = base64.b64decode(envelope["nonce"])
        ct = base64.b64decode(envelope["ct"])
        doc = json.loads(AESGCM(keys.vault_key).decrypt(nonce, ct, AAD))
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise CloudError("Could not decrypt the cloud vault: wrong cloud master password, or it was changed elsewhere.",
                         "decrypt_failed") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("entries", []), list):
        raise CloudError("The cloud vault is not in the expected format.", "bad_vault")
    return doc


def seal_envelope(doc: dict, keys: CloudKeys) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(keys.vault_key).encrypt(nonce, json.dumps(doc).encode("utf-8"), AAD)
    return {
        "v": 1,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
        "kdf": {**keys.params, "salt": keys.salt_b64},
        "updated_at": int(time.time() * 1000),
    }


# --------------------------------------------------------------------------- merge


def entry_to_web(name: str, entry: Entry, extra: Optional[dict] = None) -> dict:
    out = dict(extra or {})  # keep fields a newer web client added
    data = entry.to_dict()
    for key in _ENTRY_FIELDS:
        out[key] = data[key]
    out["id"] = entry.cloud_id
    out["name"] = name
    return out


def entry_from_web(item: dict) -> Tuple[str, Entry]:
    entry = Entry.from_dict(item)
    # Entry.from_dict stamps a missing time with "now", which would make an
    # undated remote entry look freshly edited on every sync (and undelete it).
    entry.updated_at = _stamp(item.get("updated_at"))
    entry.created_at = _stamp(item.get("created_at"))
    entry.cloud_id = str(item.get("id") or "")
    name = str(item.get("name") or "").strip() or "(unnamed)"
    return name, entry


def _stamp(x: Any) -> float:
    try:
        return float(x or 0)
    except (TypeError, ValueError):
        return 0.0


def _unique(name: str, taken: set) -> str:
    candidate, n = name, 1
    while candidate in taken:
        n += 1
        candidate = f"{name} ({n})"
    taken.add(candidate)
    return candidate


@dataclass
class MergeReport:
    added_local: List[str] = field(default_factory=list)
    added_remote: List[str] = field(default_factory=list)
    updated_local: List[str] = field(default_factory=list)
    updated_remote: List[str] = field(default_factory=list)
    deleted_local: List[str] = field(default_factory=list)
    deleted_remote: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)

    @property
    def local_changed(self) -> bool:
        return bool(self.added_local or self.updated_local or self.deleted_local)

    @property
    def remote_changed(self) -> bool:
        return bool(self.added_remote or self.updated_remote or self.deleted_remote)

    def lines(self) -> List[str]:
        labels = [
            ("added_local", "pulled new"), ("updated_local", "pulled changes to"),
            ("deleted_local", "removed locally (deleted in the cloud)"), ("added_remote", "uploaded new"),
            ("updated_remote", "uploaded changes to"), ("deleted_remote", "removed from the cloud (deleted here)"),
            ("conflicts", "edited on both sides, kept the newer"),
        ]
        return [f"{label}: {', '.join(sorted(getattr(self, attr)))}" for attr, label in labels if getattr(self, attr)]


def _keep_loser_password(winner: Entry, loser: Entry) -> None:
    """A conflict never silently drops a password: the loser's goes into history."""
    if loser.password and loser.password != winner.password:
        known = {h.get("password") for h in winner.history if isinstance(h, dict)}
        if loser.password not in known:
            winner.history = [{"password": loser.password, "changed_at": loser.updated_at}] + list(winner.history)
            winner.history = winner.history[:10]


def three_way_merge(
    local: Dict[str, Entry],
    remote_items: List[dict],
    base: Dict[str, float],
    new_id: Callable[[], str] = lambda: str(uuid.uuid4()),
    mode: str = "sync",
) -> Tuple[Dict[str, Entry], List[dict], Dict[str, float], MergeReport]:
    """Merge local CLI entries with remote web entries against the last-synced base.

    ``mode="pull"`` changes only the local side (the remote list returned is
    the input, unchanged). Returns (local, remote, new_base, report).
    """
    report = MergeReport()
    # Work on copies: the caller's entries must stay untouched if the upload fails.
    local = {name: Entry.from_dict(entry.to_dict()) for name, entry in local.items()}
    remote: Dict[str, dict] = {}
    for item in remote_items:
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]:
            remote.setdefault(item["id"], item)
    by_id: Dict[str, Tuple[str, Entry]] = {}
    unlinked: List[Tuple[str, Entry]] = []
    for name, entry in local.items():
        if entry.cloud_id and entry.cloud_id not in by_id:
            by_id[entry.cloud_id] = (name, entry)
        else:
            entry.cloud_id = ""
            unlinked.append((name, entry))

    # First sync of an existing vault: link same-named entries instead of duplicating.
    unclaimed_by_name: Dict[str, str] = {}
    for rid, item in remote.items():
        if rid not in by_id and rid not in base:
            unclaimed_by_name.setdefault(str(item.get("name") or "").strip(), rid)
    still_unlinked = []
    for name, entry in unlinked:
        rid = unclaimed_by_name.pop(name, None)
        if rid is not None:
            entry.cloud_id = rid
            by_id[rid] = (name, entry)
        else:
            still_unlinked.append((name, entry))

    out_local: Dict[str, Entry] = {}
    out_remote: List[dict] = []
    new_base: Dict[str, float] = {}
    taken: set = set()

    def put_local(name: str, entry: Entry) -> None:
        out_local[_unique(name, taken)] = entry

    for rid in list(remote.keys()) + [i for i in by_id if i not in remote]:
        item = remote.get(rid)
        pair = by_id.get(rid)
        seen = base.get(rid)
        if item is not None and pair is not None:
            name, entry = pair
            r_name, r_entry = entry_from_web(item)
            l_time, r_time = _stamp(entry.updated_at), _stamp(r_entry.updated_at)
            if seen is not None and l_time > seen and r_time > seen and l_time != r_time:
                report.conflicts.append(name)
            if r_time > l_time:
                _keep_loser_password(r_entry, entry)
                r_entry.cloud_id = rid
                put_local(r_name, r_entry)
                out_remote.append(item)
                report.updated_local.append(r_name)
                new_base[rid] = r_time
            else:
                if l_time > r_time:
                    _keep_loser_password(entry, r_entry)
                    report.updated_remote.append(name)
                put_local(name, entry)
                out_remote.append(entry_to_web(name, entry, item) if l_time > r_time else item)
                new_base[rid] = max(l_time, r_time)
        elif item is not None:
            r_name, r_entry = entry_from_web(item)
            if seen is not None and _stamp(r_entry.updated_at) <= seen:
                report.deleted_remote.append(r_name)  # deleted here, untouched there
                continue
            r_entry.cloud_id = rid
            put_local(r_name, r_entry)
            out_remote.append(item)
            report.added_local.append(r_name)
            new_base[rid] = _stamp(r_entry.updated_at)
        else:
            name, entry = pair
            if seen is not None and _stamp(entry.updated_at) <= seen:
                report.deleted_local.append(name)  # deleted there, untouched here
                continue
            put_local(name, entry)
            out_remote.append(entry_to_web(name, entry))
            report.added_remote.append(name)
            new_base[rid] = _stamp(entry.updated_at)

    for name, entry in still_unlinked:
        entry.cloud_id = new_id()
        put_local(name, entry)
        out_remote.append(entry_to_web(name, entry))
        report.added_remote.append(name)
        new_base[entry.cloud_id] = _stamp(entry.updated_at)

    if mode == "pull":
        # Nothing is uploaded, so the base may only describe what the remote
        # really holds. Recording a never-uploaded entry would make the next
        # sync think it had been deleted in the cloud, and delete it here.
        pull_base: Dict[str, float] = {}
        for rid, item in remote.items():
            if rid in new_base:
                pull_base[rid] = min(new_base[rid], _stamp(item.get("updated_at")))
            elif rid in base:
                pull_base[rid] = base[rid]  # deleted here: the next sync removes it remotely
        report.added_remote, report.updated_remote, report.deleted_remote = [], [], []
        return out_local, list(remote_items), pull_base, report
    return out_local, out_remote, new_base, report


# --------------------------------------------------------------------------- commands


def login(vault_path: str, server: str, email: str, password: str,
          recovery_code: Callable[[], str]) -> dict:
    """Sign in and link this local vault to the cloud account. Returns the state."""
    email = cloudkdf.normalize_email(email)
    previous = load_state(vault_path) or {}
    floor = int(previous.get("kdf_rank") or 0) if previous.get("email") == email else 0
    client = CloudClient(server)
    keys = derive_for(client.prelogin(email), email, password, min_rank=floor)
    try:
        body = client.login(email, keys.auth_b64)
    except CloudError as exc:
        if exc.status == 401:
            raise CloudError("Email or cloud master password is incorrect.", "invalid_credentials", 401) from None
        raise
    if body.get("mfa_required"):
        # Passkeys need a browser authenticator; from a terminal the second
        # factor is one of the account's one-time recovery codes.
        code = recovery_code()
        if not code:
            raise CloudError("Sign-in needs your passkey or a recovery code; none given.", "mfa_required")
        body = client.login_recovery(body["ceremony"], code)
    account = body["account"]
    if not client.token:
        raise CloudError("The server did not issue a session.", "no_session")
    state = {
        "server": client.server,
        "email": email,
        "token": client.token,
        "account_id": account["id"],
        "kdf_rank": max(floor, cloudkdf.rank(keys.params)),
        "key_check": key_check(keys.auth_key),
        "base": previous.get("base", {}) if previous.get("account_id") == account["id"] else {},
        "linked_at": int(time.time()),
    }
    save_state(vault_path, state)
    return {**state, "account": account}


def _client_for(state: dict) -> CloudClient:
    if not state or not state.get("token"):
        raise CloudError("This vault is not linked to a cloud account. Run `pwmanager cloud login` first.",
                         "not_linked")
    return CloudClient(state["server"], state["token"])


def status(vault_path: str) -> dict:
    state = load_state(vault_path)
    client = _client_for(state)
    try:
        account = client.me()
    except CloudError as exc:
        if exc.status == 401:
            raise CloudError("The cloud session has expired or was revoked. Run `pwmanager cloud login` again.",
                             "session_expired", 401) from None
        raise
    return {"server": state["server"], "email": state["email"], "account": account,
            "synced_entries": len(state.get("base", {}))}


def logout(vault_path: str) -> bool:
    state = load_state(vault_path)
    if state and state.get("token"):
        CloudClient(state["server"], state["token"]).logout()
    return delete_state(vault_path)


def sync(vault, password: str, mode: str = "sync", dry_run: bool = False, _retry: bool = True) -> MergeReport:
    """Two-way sync (``mode="sync"``) or cloud→local only (``mode="pull"``).

    ``vault`` is an unlocked pwmanager.vault.Vault.
    """
    state = load_state(vault.path)
    client = _client_for(state)
    try:
        account = client.me()
    except CloudError as exc:
        if exc.status == 401:
            raise CloudError("The cloud session has expired or was revoked (for example by a password change "
                             "on another device). Run `pwmanager cloud login` again.", "session_expired", 401) from None
        raise
    keys = derive_for(client.prelogin(state["email"]), state["email"], password, min_rank=int(state.get("kdf_rank") or 0))
    if not hmac.compare_digest(key_check(keys.auth_key), state.get("key_check") or ""):
        raise CloudError("That is not the cloud master password for this link (or it was changed elsewhere; "
                         "run `pwmanager cloud login` again).", "wrong_password")

    envelope, etag = client.get_vault()
    doc = open_envelope(envelope, keys) if envelope else {"version": 1, "entries": []}
    local, remote, base, report = three_way_merge(dict(vault.entries), doc.get("entries", []),
                                                  state.get("base", {}), mode=mode)
    if dry_run:
        return report

    push = mode == "sync" and (report.remote_changed or (envelope is None and bool(remote)))
    if push and not account.get("pro"):
        raise CloudError("Uploading to the cloud is a Pro feature. `pwmanager cloud pull` still works.", "pro_required")
    if push:
        doc = {**doc, "entries": remote, "saved_at": int(time.time() * 1000)}
        try:
            client.put_vault(seal_envelope(doc, keys), etag)
        except CloudError as exc:
            if exc.code == "vault_conflict" and _retry:
                # Someone saved in between: merge again on top of their version.
                return sync(vault, password, mode=mode, _retry=False)
            raise
    before = {n: e.to_dict() for n, e in vault.entries.items()}
    if before != {n: e.to_dict() for n, e in local.items()}:  # includes newly assigned cloud ids
        vault.entries = local
        vault.save()
    state["base"] = base
    state["last_sync"] = int(time.time())
    save_state(vault.path, state)
    return report
