"""Usage:  python manage.py create-admin <username> <email>"""
import getpass
import sqlite3
import sys

import services
from app import create_app


def main():
    if len(sys.argv) != 4 or sys.argv[1] != "create-admin":
        sys.exit(__doc__)
    _, _, username, email = sys.argv
    pw = getpass.getpass("Password: ")
    errs = services.validate_registration(username, email, pw, pw)
    if errs:
        sys.exit("\n".join(errs))
    app = create_app()
    try:
        with app.app_context():
            services.create_user(username, email, pw, "admin", app.config["RSA_BITS"])
    except sqlite3.IntegrityError:
        sys.exit(f"Error: Username '{username}' or email '{email}' is already registered.")
    print(f"Admin '{username}' created.")


if __name__ == "__main__":
    main()
