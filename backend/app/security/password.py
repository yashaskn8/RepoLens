"""Argon2id password hashing and verification for RepoLens authentication.

Uses argon2-cffi with Argon2id variant for secure password storage.
Includes constant-time dummy verification to prevent email enumeration timing attacks.
"""

import logging
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

logger = logging.getLogger(__name__)

# Canonical Argon2id hasher — single instance, default secure parameters
_hasher = PasswordHasher()

# Pre-computed dummy hash for constant-time unknown-email verification
_DUMMY_HASH = _hasher.hash("repolens-dummy-password-for-timing-safety")


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id.

    Returns the full Argon2id hash string including parameters and salt.
    Never logs or exposes the plaintext password.
    """
    return _hasher.hash(password)


def verify_password(arg1: str, arg2: str) -> bool:
    """Verify a plaintext password against an Argon2id hash.

    Accepts either (password, password_hash) or (password_hash, password).
    Uses constant-time comparison internally.
    """
    if arg1.startswith("$argon2"):
        hash_val, plain_val = arg1, arg2
    elif arg2.startswith("$argon2"):
        hash_val, plain_val = arg2, arg1
    else:
        return False

    try:
        return _hasher.verify(hash_val, plain_val)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_dummy_password() -> bool:
    """Perform a dummy password verification to ensure constant-time behavior.

    Called when the email is unknown to prevent timing-based email enumeration.
    Always returns False.
    """
    try:
        _hasher.verify(_DUMMY_HASH, "wrong-password-for-timing-safety")
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pass
    return False
