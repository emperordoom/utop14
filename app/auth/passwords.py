"""Password verification helpers, including a timing-dummy path.

Unknown and inactive accounts do not have a real password hash to verify.  To
avoid an obvious "no hash was checked" branch, those paths verify against a
single precomputed dummy hash.  This narrows the timing difference between
"account exists" and "account does not exist"; it is not a claim of perfectly
constant execution time.
"""

from __future__ import annotations

from werkzeug.security import check_password_hash, generate_password_hash

# Generated once per worker process.  Never generate a hash per login attempt.
_DUMMY_PASSWORD_HASH = generate_password_hash("utop14-dummy-password-not-usable")


def verify_dummy_password(password: object) -> bool:
    """Run one hash verification that always fails.

    The return value is always ``False`` and is intentionally ignored by the
    caller; the purpose is the work performed, not the result.
    """
    candidate = password if isinstance(password, str) else ""
    return check_password_hash(_DUMMY_PASSWORD_HASH, candidate)
