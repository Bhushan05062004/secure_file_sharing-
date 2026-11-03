import os
import shutil
import tempfile
import unittest

from app import create_app
import policy
import services
from tests.test_app import Client, PW, SECRET


class TestPolicyLayer(unittest.TestCase):
    def setUp(self):
        from blueprints.auth import _IP_FAILURES, _IP_LOCK
        with _IP_LOCK:
            _IP_FAILURES.clear()

        self.tmp = tempfile.mkdtemp()
        self.app = create_app({
            "TESTING": True,
            "RSA_BITS": 2048,
            "SCRYPT_N": 2 ** 14,
            "SECRET_KEY": "policy-test-key",
            "SESSION_COOKIE_SECURE": False,
            "AUDIT_HMAC_KEY": b"test-hmac-key-for-policy-tests",
            "DATABASE": os.path.join(self.tmp, "policy.db"),
            "STORAGE_DIR": os.path.join(self.tmp, "st")
        })
        os.makedirs(self.app.config["STORAGE_DIR"], exist_ok=True)
        with self.app.app_context():
            import db
            db.init_db()

        # Create one user for each granular role
        with self.app.app_context():
            services.create_user("usr_standard", "usr@corp.local", PW, "user", 2048, scrypt_n=2**14)
            services.create_user("usr_auditor", "aud@corp.local", PW, "auditor", 2048, scrypt_n=2**14)
            services.create_user("usr_secadmin", "sec@corp.local", PW, "security_admin", 2048, scrypt_n=2**14)
            services.create_user("usr_compliance", "com@corp.local", PW, "compliance_officer", 2048, scrypt_n=2**14)
            services.create_user("usr_itadmin", "ita@corp.local", PW, "it_admin", 2048, scrypt_n=2**14)

        self.cl_user = Client(self.app)
        self.cl_user.login("usr_standard", PW)

        self.cl_auditor = Client(self.app)
        self.cl_auditor.login("usr_auditor", PW)

        self.cl_secadmin = Client(self.app)
        self.cl_secadmin.login("usr_secadmin", PW)

        self.cl_compliance = Client(self.app)
        self.cl_compliance.login("usr_compliance", PW)

        self.cl_itadmin = Client(self.app)
        self.cl_itadmin.login("usr_itadmin", PW)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_role_permissions_matrix(self):
        """Validates static role permissions via policy.can()."""
        u_standard = {"id": 1, "role": "user"}
        u_auditor = {"id": 2, "role": "auditor"}
        u_secadmin = {"id": 3, "role": "security_admin"}
        u_compliance = {"id": 4, "role": "compliance_officer"}
        u_itadmin = {"id": 5, "role": "it_admin"}

        # 1. Global audit log viewing
        self.assertFalse(policy.can(u_standard, "view_audit_logs"))
        self.assertTrue(policy.can(u_auditor, "view_audit_logs"))
        self.assertTrue(policy.can(u_secadmin, "view_audit_logs"))
        self.assertTrue(policy.can(u_compliance, "view_audit_logs"))
        self.assertTrue(policy.can(u_itadmin, "view_audit_logs"))

        # 2. Verify audit chain
        self.assertFalse(policy.can(u_standard, "verify_audit_chain"))
        self.assertTrue(policy.can(u_auditor, "verify_audit_chain"))
        self.assertTrue(policy.can(u_secadmin, "verify_audit_chain"))
        self.assertTrue(policy.can(u_compliance, "verify_audit_chain"))
        self.assertFalse(policy.can(u_itadmin, "verify_audit_chain"))

        # 3. View users directory
        self.assertFalse(policy.can(u_standard, "view_users"))
        self.assertTrue(policy.can(u_auditor, "view_users"))
        self.assertTrue(policy.can(u_secadmin, "view_users"))
        self.assertTrue(policy.can(u_compliance, "view_users"))
        self.assertTrue(policy.can(u_itadmin, "view_users"))

        # 4. Manage users & groups
        self.assertFalse(policy.can(u_standard, "manage_users"))
        self.assertFalse(policy.can(u_auditor, "manage_users"))
        self.assertTrue(policy.can(u_secadmin, "manage_users"))
        self.assertFalse(policy.can(u_compliance, "manage_users"))
        self.assertTrue(policy.can(u_itadmin, "manage_users"))

        self.assertFalse(policy.can(u_standard, "manage_groups"))
        self.assertFalse(policy.can(u_auditor, "manage_groups"))
        self.assertTrue(policy.can(u_secadmin, "manage_groups"))
        self.assertFalse(policy.can(u_compliance, "manage_groups"))
        self.assertTrue(policy.can(u_itadmin, "manage_groups"))

        # 5. File upload
        self.assertTrue(policy.can(u_standard, "upload_file"))
        self.assertFalse(policy.can(u_auditor, "upload_file"))
        self.assertFalse(policy.can(u_secadmin, "upload_file"))
        self.assertFalse(policy.can(u_compliance, "upload_file"))
        self.assertTrue(policy.can(u_itadmin, "upload_file"))

    def test_resource_level_file_ownership(self):
        """Validates that file operations strictly respect ownership."""
        u1 = {"id": 1, "role": "user"}
        u2 = {"id": 2, "role": "user"}
        u_secadmin = {"id": 3, "role": "security_admin"}

        file_u1 = {"id": 10, "owner_id": 1}

        # Share
        self.assertTrue(policy.can(u1, "share_file", file_u1))
        self.assertFalse(policy.can(u2, "share_file", file_u1))

        # Delete
        self.assertTrue(policy.can(u1, "delete_file", file_u1))
        self.assertFalse(policy.can(u2, "delete_file", file_u1))

        # Revoke share: owner can revoke; security_admin can also revoke to mitigate leak
        self.assertTrue(policy.can(u1, "revoke_share", file_u1))
        self.assertFalse(policy.can(u2, "revoke_share", file_u1))
        self.assertTrue(policy.can(u_secadmin, "revoke_share", file_u1))

    def test_route_authorization_by_role(self):
        """Validates HTTP-level enforcement across routes with different roles."""
        # 1. Standard user cannot view users directory
        r = self.cl_user.c.get("/admin/users")
        self.assertEqual(r.status_code, 403)

        # 2. Auditor can view users directory and audit logs
        r_aud_users = self.cl_auditor.c.get("/admin/users")
        self.assertEqual(r_aud_users.status_code, 200)

        r_aud_audit = self.cl_auditor.c.get("/audit?verify=1")
        self.assertEqual(r_aud_audit.status_code, 200)

        # 3. Auditor cannot upload files
        r_aud_upload = self.cl_auditor.upload("audit_test.txt", SECRET)
        self.assertEqual(r_aud_upload.status_code, 403)

        # 4. Standard user can upload files
        r_usr_upload = self.cl_user.upload("user_test.txt", SECRET)
        self.assertEqual(r_usr_upload.status_code, 302)

        # 5. IT admin can access groups view and manage users
        r_ita_groups = self.cl_itadmin.c.get("/admin/groups")
        self.assertEqual(r_ita_groups.status_code, 200)

        r_ita_users = self.cl_itadmin.c.get("/admin/users")
        self.assertEqual(r_ita_users.status_code, 200)

        # 6. Compliance officer can view audit logs and groups
        r_comp_audit = self.cl_compliance.c.get("/audit")
        self.assertEqual(r_comp_audit.status_code, 200)

        r_comp_groups = self.cl_compliance.c.get("/admin/groups")
        self.assertEqual(r_comp_groups.status_code, 200)

    def test_group_management_and_membership(self):
        """Tests creating enterprise groups and managing user membership."""
        # Standard user cannot create a group
        r_fail = self.cl_user.post("/admin/groups", {"name": "Unauthorized-Group", "description": "test"})
        self.assertEqual(r_fail.status_code, 403)

        # IT Admin creates a group
        r_create = self.cl_itadmin.post("/admin/groups", {
            "name": "SecOps-Team",
            "description": "Security Operations Engineers"
        })
        self.assertEqual(r_create.status_code, 302)

        # Verify group exists in DB
        with self.app.app_context():
            import db
            g_row = db.get_db().execute("SELECT * FROM groups WHERE name='SecOps-Team'").fetchone()
            self.assertIsNotNone(g_row)
            group_id = g_row["id"]

        # IT Admin adds 'usr_standard' to 'SecOps-Team'
        r_add = self.cl_itadmin.post(f"/admin/groups/{group_id}/members", {
            "action": "add",
            "username": "usr_standard"
        })
        self.assertEqual(r_add.status_code, 302)

        # Check membership using policy helper
        with self.app.app_context():
            import db
            user_row = db.get_db().execute("SELECT id FROM users WHERE username='usr_standard'").fetchone()
            memberships = policy.get_user_groups(user_row["id"])
            group_names = [m["name"] for m in memberships]
            self.assertIn("SecOps-Team", group_names)

        # IT Admin removes 'usr_standard' from group
        r_rem = self.cl_itadmin.post(f"/admin/groups/{group_id}/members", {
            "action": "remove",
            "username": "usr_standard"
        })
        self.assertEqual(r_rem.status_code, 302)

        with self.app.app_context():
            memberships = policy.get_user_groups(user_row["id"])
            group_names = [m["name"] for m in memberships]
            self.assertNotIn("SecOps-Team", group_names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
