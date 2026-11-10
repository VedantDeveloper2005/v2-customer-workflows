"""Current adapter capability, separate from observations and write consent.

A response header, configuration flag, or diagnostic report cannot establish
atomic writes. A supported implementation requires a reviewed code change and
independent apply, restore, and cross-endpoint concurrency verification.
"""

MODE = "app-service-saved-plan-update"
API_VERSION = "2023-12-01"
FAILURE_CODE = "ATOMIC_WRITE_UNAVAILABLE"
BLOCKER = (
    "The current App Service adapter has not verified atomic image/digest writes, "
    "stale-write rejection and candidate apply concurrency. Customer execution is unavailable."
)


def supported() -> bool:
    """Never promote this unverified implementation from external evidence."""
    return False


def snapshot() -> dict:
    """Return fresh descriptive data; mutating it never grants authority."""
    return {
        "mode": MODE,
        "api_version": API_VERSION,
        "supported": False,
        "failure_code": FAILURE_CODE,
        "capabilities": {
            "candidate_apply_concurrency": "unverified",
            "stale_conditional_write": "unverified",
            "cross_settings_fence": "unverified",
            "atomic_image_digest_write": "unverified",
        },
    }
