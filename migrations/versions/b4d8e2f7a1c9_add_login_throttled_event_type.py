"""add login throttled security event type

Revision ID: b4d8e2f7a1c9
Revises: e1b7c4a9d2f3
Create Date: 2026-11-05 12:00:00.000000

Extends the authentication security-event constraints with
``auth.login_throttled`` and its three IP/identifier/combined reason codes.
This is additive at the schema level and does not mutate existing events.

Downgrade removes the new allowed values. If any throttled events already
exist, downgrade will fail the check constraint; archive or remove those rows
under an approved process before downgrading.
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "b4d8e2f7a1c9"
down_revision = "e1b7c4a9d2f3"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint(
        "security_event_type_valid",
        "security_events",
        type_="check",
    )
    op.create_check_constraint(
        "security_event_type_valid",
        "security_events",
        "event_type IN ('auth.login_succeeded', 'auth.login_failed', "
        "'auth.login_throttled', 'auth.logout')",
    )

    op.drop_constraint(
        "security_event_reason_valid",
        "security_events",
        type_="check",
    )
    op.create_check_constraint(
        "security_event_reason_valid",
        "security_events",
        "(event_type = 'auth.login_succeeded' "
        "AND outcome = 'success' "
        "AND reason_code = 'authenticated') "
        "OR (event_type = 'auth.login_failed' "
        "AND outcome = 'failure' "
        "AND reason_code IN ('unknown_account', 'inactive_account', 'invalid_password')) "
        "OR (event_type = 'auth.login_throttled' "
        "AND outcome = 'failure' "
        "AND reason_code IN ('ip_rate_limited', 'identifier_rate_limited', "
        "'combined_rate_limited')) "
        "OR (event_type = 'auth.logout' "
        "AND outcome = 'success' "
        "AND reason_code = 'user_requested')",
    )


def downgrade():
    op.drop_constraint(
        "security_event_reason_valid",
        "security_events",
        type_="check",
    )
    op.create_check_constraint(
        "security_event_reason_valid",
        "security_events",
        "(event_type = 'auth.login_succeeded' "
        "AND outcome = 'success' "
        "AND reason_code = 'authenticated') "
        "OR (event_type = 'auth.login_failed' "
        "AND outcome = 'failure' "
        "AND reason_code IN ('unknown_account', 'inactive_account', 'invalid_password')) "
        "OR (event_type = 'auth.logout' "
        "AND outcome = 'success' "
        "AND reason_code = 'user_requested')",
    )

    op.drop_constraint(
        "security_event_type_valid",
        "security_events",
        type_="check",
    )
    op.create_check_constraint(
        "security_event_type_valid",
        "security_events",
        "event_type IN ('auth.login_succeeded', 'auth.login_failed', 'auth.logout')",
    )
