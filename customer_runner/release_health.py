"""Customer-side multi-point health observation. No cloud writes or API reports."""
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from urllib.parse import urlencode
from uuid import uuid4
from backend.contracts import golden_customer_plan as golden, release_safety

ARM = "https://management.azure.com"
APP_ID = re.compile(r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()\-]{1,90}/providers/Microsoft.Web/sites/[a-z][a-z0-9-]{1,58}[a-z0-9]$")


class HealthError(Exception):
    def __init__(self, code, outcome="unavailable"):
        self.code, self.outcome = code, outcome
        super().__init__(code)


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None: raise ValueError()
    return parsed.astimezone(timezone.utc)


def utc_text(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def public_addresses(host):
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,230}[a-z0-9])?\.azurewebsites\.net", host) or ".." in host:
        raise HealthError("TARGET_REJECTED")
    try:
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        if not 1 <= len(addresses) <= 16 or any(not ipaddress.ip_address(addr).is_global for addr in addresses): raise ValueError()
        return addresses
    except (OSError, ValueError):
        raise HealthError("TARGET_REJECTED") from None


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, port=443, timeout=10, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Resolve once, reject private/link-local addresses, connect to that IP,
        # and retain the Azure hostname for TLS verification and HTTP Host.
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close(); raise


def probe(host, path, challenge):
    addresses = public_addresses(host)
    conn = PinnedHTTPS(host, addresses[0])
    try:
        conn.request("GET", path, headers={"Accept": "application/json", "Cache-Control": "no-store", "X-V2-Health-Challenge": challenge})
        response = conn.getresponse()
        if response.status != 200: raise HealthError("HTTP_REJECTED", "failed")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().casefold() != "application/json" or response.getheader("Content-Encoding", "identity").casefold() != "identity":
            raise HealthError("PROBE_RESPONSE_REJECTED", "failed")
        raw = response.read(8193)
        if len(raw) > 8192: raise HealthError("PROBE_RESPONSE_REJECTED", "failed")
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value: raise ValueError()
                value[key] = item
            return value
        def invalid(_): raise ValueError()
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except HealthError: raise
    except (OSError, ValueError, http.client.HTTPException):
        raise HealthError("PROBE_UNAVAILABLE") from None
    finally:
        conn.close()


def site(manifest, digest, request, access):
    target = golden.app_resource_id(manifest)
    if not APP_ID.fullmatch(target) or not re.fullmatch(r"[0-9a-f]{64}", digest): raise HealthError("TARGET_REJECTED")
    try:
        app = request(ARM + target + "?api-version=2023-12-01", token=access)
        config = request(ARM + target + "/config/web?api-version=2023-12-01", token=access)
        properties = app["properties"]
        if app["id"].casefold() != target.casefold() or config["id"].casefold() != (target + "/config/web").casefold() or properties["state"].casefold() != "running" or properties.get("reserved") is not True or properties.get("httpsOnly") is not True:
            raise HealthError("TARGET_REJECTED")
        p = manifest["input"]
        expected = f"DOCKER|{p['registry_name']}.azurecr.io/{p['image_repository']}@sha256:{digest}"
        if config["properties"].get("linuxFxVersion") != expected: raise HealthError("ACTIVE_IMAGE_CHANGED", "failed")
        host = properties["defaultHostName"]
        if not isinstance(host, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,230}[a-z0-9])?\.azurewebsites\.net", host) or ".." in host: raise HealthError("TARGET_REJECTED")
        return host
    except HealthError: raise
    except Exception: raise HealthError("AZURE_READ_UNAVAILABLE") from None


def metrics(payload, target, start, minutes, policy):
    """Only complete post-start one-minute aggregate buckets can verify health."""
    try:
        span = payload["timespan"].split("/")
        if len(span) != 2 or timestamp(span[0]).timestamp() != start or timestamp(span[1]).timestamp() != start + minutes * 60 or payload["interval"] != "PT1M": raise ValueError()
        rows = payload["value"]
        if not isinstance(rows, list) or len(rows) != 2: raise ValueError()
        values = {}
        for row in rows:
            name = row["name"]["value"]
            if name not in {"Requests", "Http5xx"} or name in values or row["id"].casefold() != (target + "/providers/Microsoft.Insights/metrics/" + name).casefold() or row["unit"] != "Count" or row.get("errorCode", "Success") != "Success": raise ValueError()
            series = row["timeseries"]
            if len(series) != 1 or series[0].get("metadatavalues", []) or series[0].get("metadataValues", []): raise ValueError()
            points = series[0]["data"]
            if len(points) != minutes: raise ValueError()
            buckets = {}
            for point in points:
                when, count = timestamp(point["timeStamp"]).timestamp(), point["total"]
                if type(count) not in {int, float} or not math.isfinite(count) or not 0 <= count <= 2**53 - 1 or int(count) != count or when in buckets: raise ValueError()
                buckets[when] = int(count)
            if set(buckets) != {start + i * 60 for i in range(minutes)}: raise ValueError()
            values[name] = buckets
        total, errors = 0, 0
        for when, count in values["Requests"].items():
            error = values["Http5xx"][when]
            if count < policy["min_requests_per_minute"] or error > count: raise ValueError()
            if error * 10000 > count * policy["max_5xx_basis_points"]: raise HealthError("TELEMETRY_THRESHOLD_FAILED", "failed")
            total += count; errors += error
        return {"requests": total, "http_5xx": errors, "minutes": minutes, "response_sha256": golden.sha(golden.encode(payload))}
    except HealthError: raise
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError): raise HealthError("TELEMETRY_UNAVAILABLE") from None


def observe(manifest, policy, digest, access, *, request, fetch_probe=probe, checkpoint=lambda: None, resolve_site=site,
            observation_id=None, now=lambda: datetime.now(timezone.utc), monotonic=time.monotonic, sleep=time.sleep):
    """Wait a real stabilization window; never treat missing metrics as zero."""
    samples = 0
    chain = "0" * 64
    try:
        release_safety.validate(policy)
        observation_id = observation_id or uuid4().hex
        if not isinstance(observation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", observation_id): raise HealthError("TARGET_REJECTED")
        host = resolve_site(manifest, digest, request, access)
        started = now().timestamp(); clock = monotonic()
        start = math.ceil(started / 60) * 60
        end = start + policy["stabilization_minutes"] * 60
        deadline = end + policy["telemetry_grace_seconds"]
        last = clock
        while True:
            checkpoint()
            current, tick = now().timestamp(), monotonic()
            if tick < last or tick - last > policy["poll_seconds"] + 30 or abs((current - started) - (tick - clock)) > 5:
                raise HealthError("TIMING_UNAVAILABLE")
            last = tick
            for kind in ("synthetic", "dependency"):
                challenge = uuid4().hex
                body = fetch_probe(host, policy[kind + "_path"], challenge)
                if not isinstance(body, dict) or body.get("status") != "ok" or body.get("image_sha256") != digest or body.get("challenge") != challenge:
                    raise HealthError("PROBE_RESPONSE_REJECTED", "failed")
                if kind == "dependency" and (not isinstance(body.get("dependencies"), dict) or set(body["dependencies"]) != set(policy["dependencies"]) or any(v != "ok" for v in body["dependencies"].values())):
                    raise HealthError("DEPENDENCY_FAILED", "failed")
                chain = golden.sha(golden.encode({"previous": chain, "kind": kind, "challenge": challenge,
                    "observed_at": now().isoformat(), "response_sha256": golden.sha(golden.encode(body))}))
            samples += 1
            # Refresh UTC after requests: slow I/O cannot skip time or authorize
            # stale windows. Keep polling through bounded telemetry ingestion.
            current = now().timestamp()
            complete_minutes = min(policy["stabilization_minutes"], int((current - start) // 60))
            if complete_minutes > 0:
                observed_end = start + complete_minutes * 60
                query = urlencode({"api-version": "2023-10-01", "metricnames": "Requests,Http5xx", "interval": "PT1M",
                    "timespan": utc_text(start) + "/" + utc_text(observed_end), "aggregation": "Total", "metricnamespace": "Microsoft.Web/sites", "AutoAdjustTimegrain": "false"})
                try:
                    target = golden.app_resource_id(manifest)
                    telemetry = metrics(request(ARM + target + "/providers/Microsoft.Insights/metrics?" + query, token=access), target, start, complete_minutes, policy)
                except HealthError as error:
                    if error.outcome == "failed" or current >= deadline: raise
                except Exception:
                    if current >= deadline: raise HealthError("TELEMETRY_UNAVAILABLE") from None
                else:
                    if complete_minutes == policy["stabilization_minutes"]:
                        elapsed = monotonic() - clock
                        if elapsed < policy["stabilization_minutes"] * 60 or abs((now().timestamp() - started) - elapsed) > 5 or now().timestamp() > deadline: raise HealthError("TIMING_UNAVAILABLE")
                        checkpoint()
                        if resolve_site(manifest, digest, request, access) != host: raise HealthError("ACTIVE_IMAGE_CHANGED", "failed")
                        if now().timestamp() > deadline or abs((now().timestamp() - started) - (monotonic() - clock)) > 5: raise HealthError("TIMING_UNAVAILABLE")
                        result = {"outcome": "verified", "observation_id": observation_id, "image_sha256": digest, "policy_sha256": release_safety.digest(policy),
                            "checks": ["synthetic", "dependencies", "azure-monitor"], "samples": samples, "window_start": utc_text(start), "window_end": utc_text(end), "telemetry": telemetry, "probe_chain_sha256": chain}
                        if not release_safety.verified_health(result, policy, digest): raise HealthError("TIMING_UNAVAILABLE")
                        return result
            if current >= deadline: raise HealthError("TELEMETRY_UNAVAILABLE")
            sleep(min(policy["poll_seconds"], max(0, deadline - current)))
    except HealthError as error:
        return {"outcome": error.outcome, "failure_code": error.code, "samples": samples}
    except Exception:
        # Includes revoked checkpoints and unavailable dependencies. Never leak
        # transport exception messages, URLs, response bodies or credentials.
        return {"outcome": "unavailable", "failure_code": "HEALTH_UNAVAILABLE", "samples": samples}
