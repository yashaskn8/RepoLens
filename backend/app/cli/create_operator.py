"""Bootstrap CLI utility to create or elevate an OPERATOR user in RepoLens."""

import argparse
from datetime import datetime, timezone
import getpass
import sys
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.user import UserModel
from app.schemas.enums import UserRole
from app.security.password import hash_password


def create_or_elevate_operator(
    db: Session,
    email: str,
    password: str | None = None,
) -> UserModel:
    """Programmatically create a new OPERATOR user or elevate an existing user to OPERATOR."""
    normalized_email = email.strip().lower()
    now = datetime.now(timezone.utc)

    user = db.query(UserModel).filter(UserModel.email == normalized_email).first()
    if user:
        user.role = UserRole.OPERATOR.value
        if password:
            user.password_hash = hash_password(password)
        user.is_active = True
        user.failed_login_attempts = 0
        user.locked_until = None
        user.updated_at = now
        db.commit()
        db.refresh(user)
        return user

    if not password:
        raise ValueError("Password is required when creating a new operator user.")

    user = UserModel(
        id=str(uuid4()),
        email=normalized_email,
        password_hash=hash_password(password),
        role=UserRole.OPERATOR.value,
        is_active=True,
        failed_login_attempts=0,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def main():
    parser = argparse.ArgumentParser(description="Create or elevate a RepoLens user with OPERATOR role.")
    parser.add_argument("--email", "-e", required=False, help="Operator email address")
    parser.add_argument("--password", "-p", required=False, help="Operator password (min 12 chars)")
    args = parser.parse_args()

    email = args.email
    if not email:
        email = input("Enter operator email: ").strip()

    if not email or "@" not in email:
        print("Error: Valid email address is required.", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Enter operator password (min 12 chars): ")

    if len(password) < 12:
        print("Error: Password must be at least 12 characters.", file=sys.stderr)
        sys.exit(1)

    db = SessionLocal()
    try:
        user = create_or_elevate_operator(db, email=email, password=password)
        print(f"Successfully configured user '{user.email}' with OPERATOR role (ID: {user.id}).")
    except Exception as exc:
        db.rollback()
        print(f"Error creating operator: {str(exc)}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
