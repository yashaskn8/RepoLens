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


def main(input_func=input, getpass_func=getpass.getpass, db_factory=SessionLocal):
    parser = argparse.ArgumentParser(description="Create or elevate a RepoLens user with OPERATOR role.")
    parser.add_argument("--email", "-e", required=False, help="Operator email address")
    args = parser.parse_args()

    email = args.email
    if not email:
        email = input_func("Enter operator email: ").strip()

    if not email or "@" not in email:
        print("Error: Valid email address is required.", file=sys.stderr)
        sys.exit(1)

    normalized_email = email.strip().lower()
    db = db_factory()
    try:
        existing_user = db.query(UserModel).filter(UserModel.email == normalized_email).first()
        if existing_user:
            print(f"User '{existing_user.email}' already exists with role '{existing_user.role}'.")
            confirm = input_func("Elevate this existing USER to OPERATOR? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Elevation cancelled.", file=sys.stderr)
                sys.exit(1)

            user = create_or_elevate_operator(db, email=normalized_email)
            print(f"Successfully elevated user '{user.email}' to OPERATOR role (ID: {user.id}).")
            return

        # New user creation requires password
        password = getpass_func("Enter operator password (min 12 chars): ")
        if len(password) < 12:
            print("Error: Password must be at least 12 characters.", file=sys.stderr)
            sys.exit(1)

        user = create_or_elevate_operator(db, email=normalized_email, password=password)
        print(f"Successfully created user '{user.email}' with OPERATOR role (ID: {user.id}).")
    except Exception as exc:
        db.rollback()
        print(f"Error creating operator: {str(exc)}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
