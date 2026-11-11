"""Encrypted, persistent single-owner state. No plaintext event bodies or secrets."""

import json
import os
import sqlite3
import time
from pathlib import Path
from cryptography.fernet import Fernet


class Store:
    def __init__(self, path, key):
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.crypto = Fernet(key)
        self.db = sqlite3.connect(path)
        os.chmod(path, 0o600)
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS state (bucket TEXT, key TEXT, body BLOB, PRIMARY KEY(bucket,key));
        CREATE TABLE IF NOT EXISTS outbox (sub TEXT, id TEXT, body BLOB, attempts INTEGER DEFAULT 0, next REAL DEFAULT 0, priority INTEGER DEFAULT 0, PRIMARY KEY(sub,id));
        """)
        if "priority" not in {
            row[1] for row in self.db.execute("PRAGMA table_info(outbox)")
        }:
            self.db.execute("ALTER TABLE outbox ADD COLUMN priority INTEGER DEFAULT 0")
            self.db.commit()

    def put(self, bucket, key, obj):
        body = self.crypto.encrypt(json.dumps(obj, ensure_ascii=False).encode())
        self.db.execute(
            "INSERT OR REPLACE INTO state VALUES(?,?,?)", (bucket, key, body)
        )
        self.db.commit()

    def get(self, bucket, key, default=None):
        r = self.db.execute(
            "SELECT body FROM state WHERE bucket=? AND key=?", (bucket, key)
        ).fetchone()
        return json.loads(self.crypto.decrypt(r[0])) if r else default

    def all(self, bucket):
        return [
            (k, json.loads(self.crypto.decrypt(v)))
            for k, v in self.db.execute(
                "SELECT key,body FROM state WHERE bucket=?", (bucket,)
            )
        ]

    def delete(self, bucket, key):
        self.db.execute("DELETE FROM state WHERE bucket=? AND key=?", (bucket, key))
        self.db.commit()

    def enqueue(self, sub, event):
        body = self.crypto.encrypt(json.dumps(event, ensure_ascii=False).encode())
        priority = 1 if event.get("data", {}).get("kind") == "health" else 0
        self.db.execute(
            "INSERT OR IGNORE INTO outbox(sub,id,body,priority) VALUES(?,?,?,?)",
            (sub, event["eventId"], body, priority),
        )
        self.db.commit()

    def pending(self, now, only_health=False):
        return [
            (s, i, json.loads(self.crypto.decrypt(b)), a)
            for s, i, b, a in self.db.execute(
                "SELECT sub,id,body,attempts FROM outbox WHERE next<=? AND (?=0 OR priority=1) ORDER BY priority DESC,next,id LIMIT 100",
                (now, int(only_health)),
            )
        ]

    def done(self, sub, event_id):
        self.db.execute("DELETE FROM outbox WHERE sub=? AND id=?", (sub, event_id))
        self.db.commit()

    def retry(self, sub, event_id, attempts, now):
        self.db.execute(
            "UPDATE outbox SET attempts=?,next=? WHERE sub=? AND id=?",
            (attempts, now + min(3600, 2 ** min(attempts, 12)) + 5, sub, event_id),
        )
        self.db.commit()

    def close(self):
        self.db.close()
