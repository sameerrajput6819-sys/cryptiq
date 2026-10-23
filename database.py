
import os
import threading
from contextlib import contextmanager

import mysql.connector
from mysql.connector import pooling

_REQUIRED = ("DB_HOST", "DB_USER", "DB_NAME")
_pool = None
_lock = threading.Lock()


def check_config():
    """Fail fast at startup if required settings are missing (does not connect)."""
    missing = [k for k in _REQUIRED if not os.environ.get(k, "").strip()]
    if "DB_PASSWORD" not in os.environ:
        missing.append("DB_PASSWORD")
    if missing:
        raise RuntimeError(
            "Missing database settings in your environment/.env file: " + ", ".join(missing)
        )


def _get_pool():
    global _pool
    if _pool is None:
        with _lock:
            if _pool is None:
                check_config()
                _pool = pooling.MySQLConnectionPool(
                    pool_name="cryptiq_pool",
                    pool_size=max(1, min(int(os.environ.get("DB_POOL_SIZE", "5")), 32)),
                    host=os.environ["DB_HOST"],
                    port=int(os.environ.get("DB_PORT", "3306")),
                    user=os.environ["DB_USER"],
                    password=os.environ["DB_PASSWORD"],
                    database=os.environ["DB_NAME"],
                    charset="utf8mb4",
                    collation="utf8mb4_unicode_ci",
                    time_zone="+00:00",      # timestamps are read back as UTC
                    autocommit=False,         # we commit explicitly
                    connection_timeout=10,
                )
    return _pool


@contextmanager
def get_cursor(commit=False):
    """Yield a dict cursor from the pool.

    commit=True commits when the block ends normally; any exception rolls back.
    The connection always goes back to the pool.
    """
    conn = _get_pool().get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        yield cursor
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()
