"""SQLite storage for the admin passkey and its ceremony challenges.

Tables come from the db_schema migration `_admin_passkey`. Every function
opens its own connection: gunicorn workers share nothing but the database,
so a challenge issued by one worker must be redeemable in another.
"""

import hmac
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

CHALLENGE_TTL_SECONDS = 5 * 60
# Outstanding challenges per purpose. Issuing one needs no credentials, so
# the table must not grow with the request rate; past the cap new
# ceremonies are refused until the old challenges expire.
MAX_PENDING_CHALLENGES = 100
PURPOSES = ("register", "login")


class TooManyChallenges(RuntimeError):
    """MAX_PENDING_CHALLENGES unexpired challenges already exist for a purpose."""


@dataclass(frozen=True)
class Credential:
    credential_id: bytes
    public_key: bytes
    sign_count: int


def _connect(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(db_path, isolation_level=None)


def _check_purpose(purpose: str) -> None:
    if purpose not in PURPOSES:
        raise ValueError(f"challenge purpose must be one of {PURPOSES}, got {purpose!r}")


def issue_challenge(db_path: Path, challenge: bytes, purpose: str, now: int) -> None:
    """Record a challenge that redeem_challenge accepts once, until it expires."""
    _check_purpose(purpose)
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM admin_challenges WHERE expires_unix <= ?", (now,))
            pending = conn.execute("SELECT COUNT(*) FROM admin_challenges WHERE purpose = ?",
                                   (purpose,)).fetchone()[0]
            if pending >= MAX_PENDING_CHALLENGES:
                raise TooManyChallenges(
                    f"{pending} {purpose} ceremonies are already pending; "
                    f"try again in {CHALLENGE_TTL_SECONDS // 60} minutes")
            conn.execute("INSERT INTO admin_challenges (challenge, purpose, expires_unix) "
                         "VALUES (?, ?, ?)", (challenge, purpose, now + CHALLENGE_TTL_SECONDS))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def redeem_challenge(db_path: Path, challenge: bytes, purpose: str, now: int) -> bool:
    """True once for an unexpired challenge issued for `purpose`; it is deleted either way."""
    _check_purpose(purpose)
    conn = _connect(db_path)
    try:
        row = conn.execute("DELETE FROM admin_challenges WHERE challenge = ? AND purpose = ? "
                           "RETURNING expires_unix", (challenge, purpose)).fetchone()
    finally:
        conn.close()
    return row is not None and now < row[0]


def active_credential(db_path: Path, code_mac: str) -> Credential | None:
    """The stored credential, unless it was registered under a different code.

    A credential whose code_mac does not match is ignored: rotating the
    registration code is how the operator replaces a lost passkey.
    """
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT credential_id, public_key, sign_count, code_mac "
                           "FROM admin_credential WHERE slot = 1").fetchone()
    finally:
        conn.close()
    if row is None or not hmac.compare_digest(row[3].encode(), code_mac.encode()):
        return None
    return Credential(row[0], row[1], row[2])


def store_credential(db_path: Path, credential: Credential, code_mac: str) -> bool:
    """Store the one credential; False if one registered under `code_mac` already exists.

    A credential registered under another code is replaced. The check and
    the write share one transaction, so two concurrent registrations cannot
    both succeed.
    """
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT code_mac FROM admin_credential WHERE slot = 1").fetchone()
            if row is not None and hmac.compare_digest(row[0].encode(), code_mac.encode()):
                conn.execute("ROLLBACK")
                return False
            conn.execute("DELETE FROM admin_credential")
            conn.execute(
                "INSERT INTO admin_credential (slot, credential_id, public_key, sign_count, "
                "code_mac, created_at) VALUES (1, ?, ?, ?, ?, ?)",
                (credential.credential_id, credential.public_key, credential.sign_count,
                 code_mac, datetime.now(timezone.utc).isoformat()))
            conn.execute("COMMIT")
            return True
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def advance_sign_count(db_path: Path, credential: Credential, new_count: int) -> bool:
    """Record a verified assertion's sign count; False if another sign-in moved it first."""
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "UPDATE admin_credential SET sign_count = ? "
            "WHERE slot = 1 AND credential_id = ? AND sign_count = ?",
            (new_count, credential.credential_id, credential.sign_count))
    finally:
        conn.close()
    return cursor.rowcount == 1
