"""Static catalog-qualification guard for the security SQL scripts.

The verification, provisioning, and ownership-template scripts must resolve
system catalog objects explicitly.  A temporary relation shadows the same-named
catalog for relation and type lookup (``pg_temp`` is searched before
``pg_catalog``), so one unqualified reference can turn a security check into a
false PASS.

The guard derives the expected names from the live ``pg_catalog`` instead of a
hand-maintained list, so a newly used built-in cannot silently slip through.
Comments and quoted strings are masked before scanning; dollar-quoted bodies
are treated as code because that is where the assertions live.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from flask import Flask
from sqlalchemy import text

from app.extensions import db

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SCRIPTS: Final = (
    "scripts/security_event_retention_verify.sql",
    "scripts/security_event_retention_roles.sql",
    "scripts/security_event_retention_ownership_template.sql",
)

# Names in pg_proc that are SQL grammar constructs in these scripts and cannot
# be schema-qualified: `pg_catalog.current_user` (without parentheses) is
# rejected by the parser, while `CURRENT_USER` is always the session user.
KEYWORD_FUNCTIONS: Final = frozenset({"current_user", "session_user"})

BARE_IDENTIFIER: Final = re.compile(r"(?<![\w.])([a-z_][a-z0-9_]*)")
CALLED_IDENTIFIER: Final = re.compile(r"(?<![\w.])([a-z_][a-z0-9_]*)\s*\(")
REGRCLASS_LITERAL: Final = re.compile(r"'([a-z_][a-z0-9_]*)'::regclass")


def _code_mask(body: str) -> list[bool]:
    """True where the character is SQL code (not comment or quoted string)."""
    mask = [True] * len(body)
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch == "-" and body.startswith("--", i):
            end = body.find("\n", i)
            end = n if end == -1 else end
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        if ch == "/" and body.startswith("/*", i):
            end = body.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        if ch == "'":
            j = i + 1
            while j < n:
                if body[j] == "'":
                    if j + 1 < n and body[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                mask[k] = False
            i = j
            continue
        i += 1
    return mask


def _code_only(body: str) -> str:
    mask = _code_mask(body)
    return "".join(ch if keep else " " for ch, keep in zip(body, mask, strict=True))


def _catalog_names() -> tuple[set[str], set[str], set[str]]:
    relations = {
        row[0]
        for row in db.session.execute(
            text(
                "SELECT c.relname FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'pg_catalog' "
                "AND c.relkind IN ('r', 'v', 'm', 'p')"
            )
        )
    }
    functions = {
        row[0]
        for row in db.session.execute(
            text(
                "SELECT DISTINCT p.proname FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'pg_catalog'"
            )
        )
    }
    types = {
        row[0]
        for row in db.session.execute(
            text(
                "SELECT t.typname FROM pg_catalog.pg_type t "
                "JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace "
                "WHERE n.nspname = 'pg_catalog'"
            )
        )
    }
    return relations - {"pg_catalog"}, functions - KEYWORD_FUNCTIONS, types


def test_security_scripts_use_only_qualified_catalog_references(app: Flask) -> None:
    relations, functions, _ = _catalog_names()
    # Guard against a silently empty catalog query.
    assert "pg_class" in relations
    assert "has_table_privilege" in functions
    assert "array_append" in functions

    offenders: list[str] = []
    for relative in SCRIPTS:
        body = (PROJECT_ROOT / relative).read_text()
        code = _code_only(body)
        for match in BARE_IDENTIFIER.finditer(code):
            name = match.group(1)
            if name in relations:
                line = body.count("\n", 0, match.start()) + 1
                offenders.append(f"{relative}:{line}: relation {name}")
        for match in CALLED_IDENTIFIER.finditer(code):
            name = match.group(1)
            if name in functions:
                line = body.count("\n", 0, match.start()) + 1
                offenders.append(f"{relative}:{line}: function {name}(")
        # `'<catalog_relation>'::regclass` resolves through the search path.
        for match in REGRCLASS_LITERAL.finditer(body):
            if match.group(1) in relations:
                line = body.count("\n", 0, match.start()) + 1
                offenders.append(f"{relative}:{line}: regclass literal '{match.group(1)}'")

    assert offenders == [], "unqualified pg_catalog references:\n" + "\n".join(offenders)


def test_security_scripts_pin_search_path(app: Flask) -> None:
    for relative in SCRIPTS:
        body = (PROJECT_ROOT / relative).read_text()
        assert re.search(r"^SET search_path = pg_catalog, public;$", body, re.MULTILINE), (
            f"{relative} does not pin search_path to pg_catalog, public"
        )


def test_qualified_catalog_names_exist(app: Flask) -> None:
    relations, functions, types = _catalog_names()
    known = relations | functions | types
    missing: list[str] = []
    for relative in SCRIPTS:
        body = (PROJECT_ROOT / relative).read_text()
        for name in sorted(set(re.findall(r"pg_catalog\.([a-z_][a-z0-9_]*)", body))):
            if name not in known:
                missing.append(f"{relative}: pg_catalog.{name} does not exist")
    assert missing == [], "\n".join(missing)
