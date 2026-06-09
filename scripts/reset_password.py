"""Emergency password reset — bypasses all auth.

Usage:
    python scripts/reset_password.py <username> <new_password>

Use this when the forgot-password flow is unavailable (e.g. admin locked out
with no SMTP configured and no other admin to approve a reset).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.middleware.auth import hash_password
from src.core.database import get_session_local
from src.core.logging import get_logger
from src.core.models.orm_models import User

logger = get_logger(__name__)


def main():
    if len(sys.argv) != 3:
        print("Usage: python scripts/reset_password.py <username> <new_password>")
        sys.exit(1)

    username = sys.argv[1]
    new_password = sys.argv[2]

    if len(new_password) < 6:
        print("Error: Password must be at least 6 characters")
        sys.exit(1)

    session = get_session_local()()
    try:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"Error: User '{username}' not found")
            sys.exit(1)

        user.hashed_password = hash_password(new_password)
        user.force_password_change = True
        session.commit()
        print(f"Password reset for '{username}'. They must change on next login.")
        logger.info("cli_password_reset", extra={"username": username})
    finally:
        session.close()


if __name__ == "__main__":
    main()
