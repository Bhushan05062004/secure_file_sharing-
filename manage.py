"""Usage:  python manage.py create-admin <username> <email> [role]
Valid roles: it_admin (default), security_admin, auditor, compliance_officer, user
"""
import getpass
import sqlite3
import sys

import db as database
import services
from app import create_app


def main():
    if len(sys.argv) not in (4, 5) or sys.argv[1] != "create-admin":
        sys.exit(__doc__)
    username = sys.argv[2]
    email = sys.argv[3]
    role = sys.argv[4] if len(sys.argv) == 5 else "it_admin"

    if role not in database.VALID_ROLES:
        sys.exit(f"Invalid role '{role}'. Valid roles: {', '.join(database.VALID_ROLES)}")

    pw = getpass.getpass("Password: ")
    errs = services.validate_registration(username, email, pw, pw)
    if errs:
        sys.exit("\n".join(errs))
    app = create_app()
    try:
        with app.app_context():
            services.create_user(username, email, pw, role, app.config["RSA_BITS"])
    except sqlite3.IntegrityError:
        sys.exit(f"Error: Username '{username}' or email '{email}' is already registered.")
    print(f"User '{username}' created with role '{role}'.")


if __name__ == "__main__":
    main()
