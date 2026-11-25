import io
import os
import shutil
import tempfile
import unittest

from app import create_app
import policy
import services
from tests.test_app import Client, PW


class TestRoleBasedSharing(unittest.TestCase):
    def setUp(self):
        from blueprints.auth import _IP_FAILURES, _IP_LOCK
        with _IP_LOCK:
            _IP_FAILURES.clear()

        self.tmp = tempfile.mkdtemp()
        self.app = create_app({
            "TESTING": True,
            "RSA_BITS": 2048,
            "SCRYPT_N": 2 ** 14,
            "SECRET_KEY": "role-sharing-test-key",
            "SESSION_COOKIE_SECURE": False,
            "AUDIT_HMAC_KEY": b"test-hmac-key-for-role-sharing-tests",
            "DATABASE": os.path.join(self.tmp, "share.db"),
            "STORAGE_DIR": os.path.join(self.tmp, "st")
        })
        os.makedirs(self.app.config["STORAGE_DIR"], exist_ok=True)
        with self.app.app_context():
            import db
            db.init_db()
            services.create_user("corp_admin", "admin@corp.local", PW, "it_admin", 2048, scrypt_n=2**14)
            services.create_user("mgr_alice", "alice@corp.local", PW, "manager", 2048, scrypt_n=2**14)
            services.create_user("mgr_bob", "bob@corp.local", PW, "manager", 2048, scrypt_n=2**14)
            services.create_user("emp_charlie", "charlie@corp.local", PW, "user", 2048, scrypt_n=2**14)
            services.create_user("emp_david", "david@corp.local", PW, "user", 2048, scrypt_n=2**14)

        self.cl_admin = Client(self.app)
        self.cl_admin.login("corp_admin", PW)

        self.cl_mgr1 = Client(self.app)
        self.cl_mgr1.login("mgr_alice", PW)

        self.cl_mgr2 = Client(self.app)
        self.cl_mgr2.login("mgr_bob", PW)

        self.cl_emp1 = Client(self.app)
        self.cl_emp1.login("emp_charlie", PW)

        self.cl_emp2 = Client(self.app)
        self.cl_emp2.login("emp_david", PW)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_admin_shares_file_to_all_managers(self):
        """Admin shares a file with role 'manager'; all managers receive access and can decrypt."""
        secret_content = b"Q4 Corporate Executive Strategy - For Managers Eyes Only"
        self.cl_admin.post("/upload", data={
            "file": (io.BytesIO(secret_content), "exec_strategy.pdf"),
            "classification": "confidential"
        }, content_type="multipart/form-data")

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT id FROM files WHERE original_name='exec_strategy.pdf'").fetchone()
            file_id = f["id"]

        # Admin shares with entire 'manager' role
        res = self.cl_admin.post(f"/share/{file_id}", data={
            "share_type": "role",
            "target_role": "manager",
            "expiry_hours": 48
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"shared with all 2 user(s) in role &#39;Department Manager&#39;", res.data)

        # Both managers (alice and bob) can download and decrypt the exact original file
        res_mgr1 = self.cl_mgr1.c.get(f"/download/{file_id}")
        self.assertEqual(res_mgr1.status_code, 200)
        self.assertEqual(res_mgr1.data, secret_content)

        res_mgr2 = self.cl_mgr2.c.get(f"/download/{file_id}")
        self.assertEqual(res_mgr2.status_code, 200)
        self.assertEqual(res_mgr2.data, secret_content)

        # Standard employees (charlie) do NOT have access (403 Forbidden)
        res_emp = self.cl_emp1.c.get(f"/download/{file_id}")
        self.assertEqual(res_emp.status_code, 403)

    def test_manager_shares_file_to_all_employees(self):
        """Manager shares a file with role 'user' (Employees); all employees receive access."""
        report_content = b"Team Weekly Sprint Goals and Objectives"
        self.cl_mgr1.post("/upload", data={
            "file": (io.BytesIO(report_content), "team_sprint.txt"),
            "classification": "internal"
        }, content_type="multipart/form-data")

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT id FROM files WHERE original_name='team_sprint.txt'").fetchone()
            file_id = f["id"]

        # Manager shares with role 'user' (all employees)
        res = self.cl_mgr1.post(f"/share/{file_id}", data={
            "share_type": "role",
            "target_role": "user",
            "expiry_hours": 24
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"shared with all 2 user(s) in role &#39;Standard Employee&#39;", res.data)

        # Both employees can download
        res_emp1 = self.cl_emp1.c.get(f"/download/{file_id}")
        self.assertEqual(res_emp1.status_code, 200)
        self.assertEqual(res_emp1.data, report_content)

        res_emp2 = self.cl_emp2.c.get(f"/download/{file_id}")
        self.assertEqual(res_emp2.status_code, 200)
        self.assertEqual(res_emp2.data, report_content)

    def test_revoke_role_shares(self):
        """Owner can revoke a role share; all members of that role immediately lose access."""
        content = b"Temporary Document"
        self.cl_mgr1.post("/upload", data={
            "file": (io.BytesIO(content), "temp_doc.txt"),
            "classification": "internal"
        }, content_type="multipart/form-data")

        with self.app.app_context():
            import db
            f = db.get_db().execute("SELECT id FROM files WHERE original_name='temp_doc.txt'").fetchone()
            file_id = f["id"]

        # Share to employees
        self.cl_mgr1.post(f"/share/{file_id}", data={
            "share_type": "role",
            "target_role": "user"
        }, follow_redirects=True)

        # Verified accessible
        self.assertEqual(self.cl_emp1.c.get(f"/download/{file_id}").status_code, 200)

        # Manager revokes role shares for 'user'
        res_rev = self.cl_mgr1.post(f"/revoke-role/{file_id}/user", follow_redirects=True)
        self.assertEqual(res_rev.status_code, 200)
        self.assertIn(b"Access revoked for all members of role &#39;Standard Employee&#39;", res_rev.data)

        # Access is now forbidden
        self.assertEqual(self.cl_emp1.c.get(f"/download/{file_id}").status_code, 403)
        self.assertEqual(self.cl_emp2.c.get(f"/download/{file_id}").status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
