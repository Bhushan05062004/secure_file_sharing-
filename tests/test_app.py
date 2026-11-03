import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402

PW = "StrongPass123"
SECRET = b"TOP-SECRET-PLAINTEXT-MARKER-0123456789"


class Client:
    def __init__(self, app):
        self.c = app.test_client()

    def token(self):
        html = self.c.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, url, data=None, **kw):
        d = dict(data or {})
        d["csrf_token"] = self.token()
        return self.c.post(url, data=d, **kw)

    def register(self, u):
        return self.post("/register", dict(username=u, email=f"{u}@x.com", password=PW, confirm=PW))

    def login(self, u, pw=PW):
        return self.post("/login", dict(username=u, password=pw))

    def upload(self, name="s.txt", data=SECRET):
        return self.post("/upload", {"file": (BytesIO(data), name)},
                         content_type="multipart/form-data")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({"TESTING": True, "RSA_BITS": 2048, "SECRET_KEY": "t",
                               "DATABASE": os.path.join(self.tmp, "t.db"),
                               "STORAGE_DIR": os.path.join(self.tmp, "st")})
        os.makedirs(self.app.config["STORAGE_DIR"], exist_ok=True)
        with self.app.app_context():
            import db
            db.init_db()
        self.alice, self.bob, self.eve = Client(self.app), Client(self.app), Client(self.app)
        for cl, n in ((self.alice, "alice"), (self.bob, "bob"), (self.eve, "eve")):
            cl.register(n)
            cl.login(n)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def q(self, sql, args=()):
        con = sqlite3.connect(self.app.config["DATABASE"])
        con.row_factory = sqlite3.Row
        r = con.execute(sql, args).fetchall()
        con.commit()
        con.close()
        return r


class TestSecurity(Base):
    def test_encrypted_at_rest_and_owner_download(self):
        self.alice.upload()
        stored = os.listdir(self.app.config["STORAGE_DIR"])
        self.assertEqual(len(stored), 1)
        raw = open(os.path.join(self.app.config["STORAGE_DIR"], stored[0]), "rb").read()
        self.assertNotIn(SECRET, raw)
        r = self.alice.c.get("/download/1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, SECRET)

    def test_private_key_not_stored_in_clear(self):
        blob = self.q("SELECT enc_private_key FROM users WHERE username='alice'")[0][0]
        self.assertNotIn("PRIVATE KEY", blob)

    def test_unauthorised_user_denied_and_logged(self):
        self.alice.upload()
        self.assertEqual(self.eve.c.get("/download/1").status_code, 403)
        self.assertEqual(self.eve.c.get("/share/1").status_code, 403)
        fails = self.q("SELECT * FROM audit_logs WHERE success=0 AND username='eve'")
        self.assertGreaterEqual(len(fails), 2)

    def test_share_download_and_limit(self):
        self.alice.upload()
        self.alice.post("/share/1", dict(recipient="bob", max_downloads="2"))
        self.assertEqual(self.bob.c.get("/download/1").data, SECRET)
        self.assertEqual(self.bob.c.get("/download/1").status_code, 200)
        self.assertEqual(self.bob.c.get("/download/1").status_code, 403)
        self.assertEqual(self.eve.c.get("/download/1").status_code, 403)

    def test_expiry(self):
        self.alice.upload()
        self.alice.post("/share/1", dict(recipient="bob", expiry_hours="1"))
        self.q("UPDATE shares SET expires_at='2000-01-01T00:00:00+00:00'")
        self.assertEqual(self.bob.c.get("/download/1").status_code, 403)

    def test_revoke(self):
        self.alice.upload()
        self.alice.post("/share/1", dict(recipient="bob"))
        self.assertEqual(self.bob.c.get("/download/1").status_code, 200)
        self.alice.post("/revoke/1")
        self.assertEqual(self.bob.c.get("/download/1").status_code, 403)
        self.assertEqual(self.q("SELECT * FROM file_keys WHERE user_id=2"), [])

    def test_non_owner_cannot_revoke_or_delete(self):
        self.alice.upload()
        self.alice.post("/share/1", dict(recipient="bob"))
        self.assertEqual(self.eve.post("/revoke/1").status_code, 403)
        self.assertEqual(self.bob.post("/delete/1").status_code, 403)

    def test_tamper_detected(self):
        self.alice.upload()
        p = os.path.join(self.app.config["STORAGE_DIR"], os.listdir(self.app.config["STORAGE_DIR"])[0])
        b = bytearray(open(p, "rb").read())
        b[20] ^= 0xFF
        open(p, "wb").write(bytes(b))
        self.assertEqual(self.alice.c.get("/download/1").status_code, 400)

    def test_csrf_required(self):
        r = self.alice.c.post("/upload", data={"file": (BytesIO(b"x"), "a.txt")},
                              content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_login_required(self):
        anon = Client(self.app)
        self.assertEqual(anon.c.get("/dashboard").status_code, 302)
        self.assertEqual(anon.c.get("/download/1").status_code, 302)

    def test_lockout(self):
        v = Client(self.app)
        for _ in range(5):
            v.login("alice", "wrong-password")
        self.assertEqual(v.login("alice", PW).status_code, 429)

    def test_weak_password_rejected(self):
        c = Client(self.app)
        self.assertEqual(c.post("/register", dict(username="zed", email="z@x.com",
                                                   password="short", confirm="short")).status_code, 400)

    def test_audit_chain_and_admin_only(self):
        self.alice.upload()
        import audit
        with self.app.app_context():
            self.assertTrue(audit.verify_chain()[0])
        self.q("UPDATE audit_logs SET action='HACKED' WHERE id=2")
        with self.app.app_context():
            self.assertFalse(audit.verify_chain()[0])
        self.assertEqual(self.alice.c.get("/admin/users").status_code, 403)

    def test_security_headers(self):
        r = self.alice.c.get("/dashboard")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("Content-Security-Policy", r.headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
