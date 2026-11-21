"""Safe local redirect validation and sensitive query-parameter sanitization."""

from __future__ import annotations

from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SAFE_NEXT_MAX_LENGTH: Final = 2048

# Query parameters that previously carried sensitive security-event filter values.
# They must never be reflected in a redirect Location header, login ``next``
# target, hidden form field, or post-login destination.
SENSITIVE_SECURITY_EVENT_QUERY_PARAMS: Final[frozenset[str]] = frozenset(
    {
        "event_type",
        "outcome",
        "reason",
        "date_from",
        "date_to",
        "request_id",
        "identifier_hash",
        "actor_user_id",
        "subject_user_id",
    }
)


def has_sensitive_query_params(keys: object) -> bool:
    """Return whether any query key matches the sensitive filter parameter set."""
    if not hasattr(keys, "__iter__"):
        return False
    return any(
        isinstance(key, str) and key.lower() in SENSITIVE_SECURITY_EVENT_QUERY_PARAMS
        for key in keys  # type: ignore[union-attr]
    )


def strip_sensitive_query(target: str) -> str:
    """Remove sensitive security-event filter parameters from a local target."""
    parsed = urlsplit(target)
    if not parsed.query:
        return target
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [
        (key, value)
        for key, value in pairs
        if key.lower() not in SENSITIVE_SECURITY_EVENT_QUERY_PARAMS
    ]
    if len(filtered) == len(pairs):
        return target
    return urlunsplit(("", "", parsed.path, urlencode(filtered), parsed.fragment))


def safe_next_url(target: str | None) -> str | None:
    """Return a sanitized local redirect target, or ``None`` for unsafe input."""
    if target is None:
        return None

    candidate = target.strip()
    if not candidate or len(candidate) > _SAFE_NEXT_MAX_LENGTH:
        return None
    if not candidate.startswith("/") or candidate.startswith("//"):
        return None
    if "\\" in candidate or "\r" in candidate or "\n" in candidate:
        return None
    if candidate.lower().startswith(("/%2f", "/%5c")):
        return None

    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        return None
    return strip_sensitive_query(candidate)


def sanitized_request_next_target(path: str, raw_query: bytes) -> str | None:
    """Build a safe, sanitized local ``next`` value from an inbound request."""
    if raw_query:
        query_text = raw_query.decode("utf-8", errors="ignore")
        candidate = f"{path}?{query_text}"
    else:
        candidate = path
    return safe_next_url(candidate)
