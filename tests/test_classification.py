import io
import os
import shutil
import tempfile
import unittest

from app import create_app
import policy
import services
from tests.test_app import Client, PW


class TestFileClassificationRBAC(unittest.TestCase):
    def setUp(self):
        from blueprints.auth import _IP_FAILURES, _IP_LOCK
        with _IP_LOCK:
            _IP_FAILURES.clear()

        self.tmp = tempfile.mkdtemp()
        self.app = create_app({
            "TESTING": True,
            "RSA_BITS": 2048,
            "SCRYPT_N": 2 ** 14,
            "SECRET_KEY": "classification-test-key",
            "SESSION_COOKIE_SECURE": False,
            "AUDIT_HMAC_KEY": b"test-hmac-key-for-classification-tests",
            "DATABASE": os.path.join(self.tmp, "classify.db"),
            "STORAGE_DIR": os.path.join(self.tmp, "st")
        })
        os.makedirs(self.app.config["STORAGE_DIR"], exist_ok=True)
        with self.app.app_context():
            import db
            db.init_db()
            services.create_user("alice", "alice@corp.local", PW, "user", 2048, scrypt_n=2**14)
            services.create_user("bob", "bob@corp.local", PW, "user", 2048, scrypt_n=2**14)
            services.create_user("secadmin", "sec@corp.local", PW, "security_admin", 2048, scrypt_n=2**14)
            services.create_user("compliance", "com@corp.local", PW, "compliance_officer", 2048, scrypt_n=2**14)

        self.cl_alice = Client(self.app)
        self.cl_alice.login("alice", PW)

        self.cl_bob = Client(self.app)
        self.cl_bob.login("bob", PW)

        self.cl_secadmin = Client(self.app)
        self.cl_secadmin.login("secadmin", PW)

        self.cl_compliance = Client(self.app)
        self.cl_compliance.login("compliance", PW)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_upload_with_classification(self):
        """Uploading files should store the designated classification."""
        res = self.cl_alice.post("/upload", data={
            "file": (io.BytesIO(b"Confidential Strategy Doc"), "strategy.pdf"),
            "classification": "confidential"
        }, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT * FROM files WHERE original_name='strategy.pdf'").fetchone()
            self.assertIsNotNone(f)
            self.assertEqual(f["classification"], "confidential")
            self.assertEqual(f["legal_hold"], 0)

    def test_sharing_restricted_file_policy(self):
        """Restricted files cannot be shared with standard users; only privileged roles."""
        # Alice uploads a restricted file
        self.cl_alice.post("/upload", data={
            "file": (io.BytesIO(b"Critical Infrastructure Key"), "keys.txt"),
            "classification": "restricted"
        }, content_type="multipart/form-data")

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT id FROM files WHERE original_name='keys.txt'").fetchone()
            file_id = f["id"]

        # Attempt to share with Bob (role: user) should be denied
        res = self.cl_alice.post(f"/share/{file_id}", data={
            "recipient": "bob",
            "expiry_hours": 12,
            "max_downloads": 5
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"is not authorized to receive RESTRICTED classified files", res.data)

        # Attempt to share with secadmin (role: security_admin) within 24 hours should succeed
        res_ok = self.cl_alice.post(f"/share/{file_id}", data={
            "recipient": "secadmin",
            "expiry_hours": 20,
            "max_downloads": 2
        }, follow_redirects=True)
        self.assertEqual(res_ok.status_code, 200)
        self.assertIn(b"Shared with secadmin", res_ok.data)

    def test_sharing_max_expiry_enforcement(self):
        """Classification max expiry policies must be strictly enforced."""
        # Alice uploads a restricted file (max expiry = 24h)
        self.cl_alice.post("/upload", data={
            "file": (io.BytesIO(b"Classified Top Secret"), "secret.txt"),
            "classification": "restricted"
        }, content_type="multipart/form-data")

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT id FROM files WHERE original_name='secret.txt'").fetchone()
            file_id = f["id"]

        # Exceeding 24 hours should be rejected
        res = self.cl_alice.post(f"/share/{file_id}", data={
            "recipient": "secadmin",
            "expiry_hours": 48,
            "max_downloads": 1
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"For RESTRICTED files, expiry must be 1-24 hours", res.data)

    def test_legal_hold_blocks_deletion(self):
        """A file placed under legal hold cannot be deleted by anyone, including the owner."""
        self.cl_alice.post("/upload", data={
            "file": (io.BytesIO(b"Audit Evidence Document"), "evidence.doc"),
            "classification": "confidential"
        }, content_type="multipart/form-data")

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT id FROM files WHERE original_name='evidence.doc'").fetchone()
            file_id = f["id"]

        # Compliance officer applies legal hold
        res_hold = self.cl_compliance.post(f"/legal-hold/{file_id}", follow_redirects=True)
        self.assertEqual(res_hold.status_code, 200)

        with self.app.app_context():
            import db
            f_held = db.get_db().execute("SELECT legal_hold FROM files WHERE id=?", (file_id,)).fetchone()
            self.assertEqual(f_held["legal_hold"], 1)

        # Alice attempts to delete her own file under legal hold -> 403 Forbidden
        res_del = self.cl_alice.post(f"/delete/{file_id}")
        self.assertEqual(res_del.status_code, 403)

        # File must still exist
        with self.app.app_context():
            import db
            f_still_there = db.get_db().execute("SELECT id FROM files WHERE id=?", (file_id,)).fetchone()
            self.assertIsNotNone(f_still_there)

        # Compliance officer releases legal hold
        self.cl_compliance.post(f"/legal-hold/{file_id}", follow_redirects=True)

        # Now deletion succeeds
        res_del2 = self.cl_alice.post(f"/delete/{file_id}", follow_redirects=True)
        self.assertEqual(res_del2.status_code, 200)

        with self.app.app_context():
            import db
            f_gone = db.get_db().execute("SELECT id FROM files WHERE id=?", (file_id,)).fetchone()
            self.assertIsNone(f_gone)

    def test_legal_hold_permission_gate(self):
        """Only compliance_officer and security_admin can toggle legal hold."""
        self.cl_alice.post("/upload", data={
            "file": (io.BytesIO(b"General Notice"), "notice.txt"),
            "classification": "internal"
        }, content_type="multipart/form-data")

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT id FROM files WHERE original_name='notice.txt'").fetchone()
            file_id = f["id"]

        # Standard user alice trying to toggle legal hold -> 403
        res = self.cl_alice.post(f"/legal-hold/{file_id}")
        self.assertEqual(res.status_code, 403)

        # Security admin can toggle legal hold -> 200 redirect
        res_sec = self.cl_secadmin.post(f"/legal-hold/{file_id}", follow_redirects=True)
        self.assertEqual(res_sec.status_code, 200)
        self.assertIn(b"Legal hold applied to &#39;notice.txt&#39;.", res_sec.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)

