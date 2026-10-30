"""Development-only simulated payment provider.

This provider never contacts a payment network, never processes real money and
never accepts cardholder data.  It exists solely to exercise the payment
lifecycle in development and automated tests.
"""

from __future__ import annotations

from typing import Final

from app.models.payment import (
    PAYMENT_PROVIDER_SIMULATED,
    PAYMENT_STATUS_FAILED,
    PAYMENT_STATUS_PAID,
)

SIMULATED_OUTCOME_SUCCESS: Final = "success"
SIMULATED_OUTCOME_FAILURE: Final = "failure"
SIMULATED_OUTCOMES: Final[tuple[str, ...]] = (
    SIMULATED_OUTCOME_SUCCESS,
    SIMULATED_OUTCOME_FAILURE,
)


class SimulatedPaymentProvider:
    """Deterministic, offline provider used only when explicitly enabled."""

    name = PAYMENT_PROVIDER_SIMULATED

    def provider_reference(self, payment_reference: str) -> str:
        """Return a clearly simulated provider reference."""
        return f"SIM-{payment_reference}"

    def status_for_outcome(self, outcome: str) -> str:
        """Map a simulated outcome to a terminal payment status."""
        if outcome == SIMULATED_OUTCOME_SUCCESS:
            return PAYMENT_STATUS_PAID
        if outcome == SIMULATED_OUTCOME_FAILURE:
            return PAYMENT_STATUS_FAILED
        raise ValueError(f"Unknown simulated payment outcome: {outcome!r}")
