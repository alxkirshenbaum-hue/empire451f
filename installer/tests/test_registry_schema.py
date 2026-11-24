"""Exercise the actual W2 SQLite migration on temporary databases."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest


SQL = (Path(__file__).resolve().parents[1] / 'controlpanel/migrations/001_registry.sql').read_text()


def connection(path):
    db = sqlite3.connect(path, timeout=5, isolation_level=None)
    db.execute('PRAGMA foreign_keys=ON')
    return db


def add(db, login, status='active', master=False):
    db.execute('INSERT INTO users(id,login,kind,protected,display_name,status,created_at,updated_at) '
               'VALUES(?,?,?,?,?,?,?,?)', (login,login,'service' if master else 'regular',
                int(master),login,status,'2026-11-12','2026-11-12'))


class RegistryConstraints(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'registry.db'
        self.db = connection(self.path)
        self.addCleanup(self.db.close)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('BEGIN IMMEDIATE;\n'+SQL+'\nCOMMIT;')

    def test_exact_logins_and_tombstones(self):
        add(self.db,'Test')
        add(self.db,'test')
        self.db.execute("UPDATE users SET status='deleted' WHERE login='Test'")
        with self.assertRaises(sqlite3.IntegrityError):
            add(self.db,'Test')
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE users SET status='active' WHERE login='Test'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM users WHERE login='Test'")

    def test_reserved_identity(self):
        with self.assertRaises(sqlite3.IntegrityError):
            add(self.db,'master_user')
        add(self.db,'master_user',master=True)
        add(self.db,'MASTER_USER')
        for assignment in ("status='disabled'","login='renamed'","protected=0","status='deleted'"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("UPDATE users SET "+assignment+" WHERE login='master_user'")

    def test_current_credential_belongs_to_user(self):
        add(self.db,'A')
        add(self.db,'B')
        statement = ('INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) '
                     "VALUES(?,?,1,'AES-256-GCM',?,?,1,'now')")
        self.db.execute(statement,('ca','A',bytes(12),bytes(32)))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO user_current_credentials VALUES('B','ca','now')")
        self.db.execute("INSERT INTO user_current_credentials VALUES('A','ca','now')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(statement,('cb','B',bytes(12),bytes(32)))

    def test_two_writers_one_remaining_slot(self):
        add(self.db,'master_user',master=True)
        for i in range(99):
            add(self.db,f'user-{i}',status=('disabled' if i % 2 else 'provisioning'))
        ready = threading.Barrier(2)
        def create(login):
            db = connection(self.path)
            try:
                ready.wait(5)
                db.execute('BEGIN IMMEDIATE')
                try:
                    add(db,login)
                except sqlite3.IntegrityError as exc:
                    if str(exc) != 'user capacity reached': raise
                    db.rollback()
                    return False
                db.commit()
                return True
            finally:
                db.close()
        with ThreadPoolExecutor(2) as workers:
            self.assertCountEqual(workers.map(create,['one','two']),[True,False])
        self.assertEqual(self.db.execute('SELECT count(*) FROM users').fetchone()[0],101)
        self.db.execute("UPDATE users SET status='deleted' WHERE login='user-0'")
        add(self.db,'replacement')
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])


if __name__=='__main__':
    unittest.main()
