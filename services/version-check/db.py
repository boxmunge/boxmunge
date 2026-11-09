"""Every connection to the service database, with secure_delete on.

SQLite leaves deleted and overwritten rows in the file's free space until
it is reused. With secure_delete, freed content is zeroed as it is freed, so
expired data is gone from the file bytes, not only from queries: the 90-day
deletions the privacy statement (static/index.html) promises, and the full
client addresses migration 5 replaced by network prefixes. The cost is a
little extra writing on a small, rarely written database.
"""

import sqlite3
from pathlib import Path


def connect(db_path: Path, **kwargs) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, **kwargs)
    conn.execute("PRAGMA secure_delete = ON")
    return conn
