"""Read-only operator observations, never customer execution authority.

A strong configuration ETag is only one prerequisite. This diagnostic cannot
prove conditional writes, saved-plan fencing, permissions, health or recovery.
It never reads application settings or sends an Azure management write.
"""
from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import json
import re
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


ARM = "https://management.azure.com"
LIMIT = 131072
STRONG_ETAG = re.compile(r'^"[A-Za-z0-9_:.\-/]{1,180}"$')


@dataclass(frozen=True)
class Target:
    subscription_id: str
    resource_group: str
    app_name: str

    def __post_init__(self):
        try:
            if not isinstance(self.subscription_id, str) or str(UUID(self.subscription_id)) != self.subscription_id:
                raise ValueError()
            if (not isinstance(self.resource_group, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.()\-]{1,90}", self.resource_group)
                    or self.resource_group in {".", ".."}):
                raise ValueError()
            if not isinstance(self.app_name, str) or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,58}[A-Za-z0-9])?", self.app_name):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ValueError("An exact Azure subscription, resource group and app name are required.") from None

    @property
    def resource_id(self):
        return f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Web/sites/{self.app_name}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _versions(value):
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 8:
        raise ValueError("Choose one to eight explicit stable API versions.")
    for version in value:
        try:
            if not isinstance(version, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", version):
                raise ValueError()
            date.fromisoformat(version)
        except (ValueError, TypeError):
            raise ValueError("API versions must be explicit ISO dates without query parameters.") from None
    if len(set(value)) != len(value):
        raise ValueError("API versions must be distinct.")
    return tuple(value)


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError()
            value[key] = item
        return value

    def invalid(_):
        raise ValueError()

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def _row(version):
    return {"api_version": version, "status": None, "reason": "TRANSPORT_UNAVAILABLE",
            "strong_etag_observed": False, "target_id_matches": False,
            "response_sha256": None, "etag_sha256": None}


def _observe(target, version, token, open_url):
    row = _row(version)
    request = Request(ARM + target.resource_id + "/config/web?api-version=" + version,
                      headers={"Authorization": "Bearer " + token, "Accept": "application/json",
                               "Accept-Encoding": "identity"}, method="GET")
    try:
        with open_url(request, timeout=30) as response:
            if type(response.status) is not int or not 100 <= response.status <= 599:
                raise ValueError()
            row["status"] = response.status
            if response.status != 200:
                raise HTTPError(request.full_url, response.status, "", response.headers, None)
            if (response.headers.get("Content-Encoding", "identity").casefold() != "identity"
                    or response.headers.get("Content-Type", "").split(";", 1)[0].casefold() != "application/json"):
                raise ValueError()
            raw = response.read(LIMIT + 1)
            if not isinstance(raw, bytes) or len(raw) > LIMIT:
                raise ValueError()
            value = _json(raw)
            if not isinstance(value, dict) or not isinstance(value.get("properties"), dict):
                raise ValueError()
            row["response_sha256"] = hashlib.sha256(raw).hexdigest()
            actual_id = value.get("id")
            if not isinstance(actual_id, str) or actual_id.casefold() != (target.resource_id + "/config/web").casefold():
                row["reason"] = "INVALID_CONFIGURATION_RESPONSE"
                return row
            row["target_id_matches"] = True
            tags = (response.headers.get_all("ETag") if hasattr(response.headers, "get_all")
                    else [response.headers["ETag"]] if "ETag" in response.headers else None)
            if not tags:
                row["reason"] = "ETAG_HEADER_ABSENT"
                return row
            if len(tags) != 1 or not isinstance(tags[0], str):
                row["reason"] = "ETAG_INVALID"
                return row
            tag = tags[0]
            if tag.startswith("W/"):
                row["reason"] = "WEAK_ETAG"
                return row
            if not STRONG_ETAG.fullmatch(tag):
                row["reason"] = "ETAG_INVALID"
                return row
            if "etag" in value and value["etag"] != tag:
                row["reason"] = "ETAG_BODY_MISMATCH"
                return row
            row.update(reason="STRONG_ETAG_OBSERVED", strong_etag_observed=True,
                       etag_sha256=hashlib.sha256(tag.encode()).hexdigest())
            return row
    except HTTPError as error:
        row["status"] = error.code
        row["reason"] = {401: "AUTH_UNAVAILABLE", 403: "PERMISSION_DENIED", 404: "TARGET_NOT_FOUND"}.get(error.code, "HTTP_UNAVAILABLE")
        if 300 <= error.code <= 399:
            row["reason"] = "REDIRECT_REJECTED"
        if error.code == 400:
            try:
                raw = error.read(LIMIT + 1)
                if len(raw) <= LIMIT:
                    code = _json(raw).get("error", {}).get("code")
                    if code in {"InvalidApiVersionParameter", "NoRegisteredProviderFound", "UnsupportedApiVersion"}:
                        row["reason"] = "API_VERSION_UNAVAILABLE"
            except Exception:
                pass
        return row
    except (URLError, OSError, TimeoutError):
        row["reason"] = "TRANSPORT_UNAVAILABLE"
        return row
    except (ValueError, TypeError, AttributeError, RecursionError):
        row["reason"] = "INVALID_CONFIGURATION_RESPONSE"
        return row
    except Exception:
        # Do not emit an unexpected transport exception that may carry the
        # request headers or provider body. Cancellation still propagates.
        row["reason"] = "TRANSPORT_UNAVAILABLE"
        return row


def diagnose(target: Target, api_versions, *, acquire_token: Callable[[], str], open_url=None):
    """Produce bounded observations; even strong tags leave admission blocked."""
    if not isinstance(target, Target):
        raise ValueError("An explicitly validated target is required.")
    versions = _versions(api_versions)
    observations = []
    try:
        token = acquire_token()
        if not isinstance(token, str) or not 10 <= len(token) <= 16384 or any(not 33 <= ord(c) <= 126 for c in token):
            raise ValueError()
    except Exception:
        observations = [{**_row(version), "reason": "AUTH_UNAVAILABLE"} for version in versions]
    else:
        try:
            opener = open_url or build_opener(NoRedirect()).open
        except Exception:
            observations = [_row(version) for version in versions]
        else:
            for version in versions:
                observations.append(_observe(target, version, token, opener))
    requirements = {name: "not-run" for name in (
        "stale_conditional_write_rejection", "cross_endpoint_settings_fence",
        "atomic_image_digest_restore", "saved_plan_apply_concurrency",
        "restricted_identity_permissions", "customer_github_oidc", "release_health_and_rollback")}
    requirements["strong_configuration_etag"] = "observed" if all(row["strong_etag_observed"] for row in observations) else "unavailable"
    return {"schema_version": "v2.azure-concurrency-diagnostic.v1",
            "observed_at": datetime.now(timezone.utc).isoformat(), "auth_source": "operator-cli",
            "target_resource_id": target.resource_id, "observation_type": "operator-read-only",
            "customer_oidc_tested": False, "azure_write_attempts": 0,
            "customer_execution_enabled": False, "execution_admission": "blocked",
            "is_authorization": False, "observations": observations, "requirements": requirements}
