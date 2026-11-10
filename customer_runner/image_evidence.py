"""Verify OCI provenance with the pinned GitHub CLI inside the customer runner."""
import base64
import json
from pathlib import Path
from backend.contracts.golden_customer_plan import sha
from customer_runner.preflight import PreflightError

GH_VERSION = "2.103.3"


def verify(manifest, folder, environ, execute):
    p = manifest["input"]
    workflow = manifest["repository"] + "/" + p.get("build_workflow", ".github/workflows/build.yml")
    result = {"status": "unavailable", "verifier": "gh-" + GH_VERSION, "image_sha256": p["image_sha256"],
        "source_sha": manifest["source_sha"], "signer_workflow": workflow, "failure_code": "TOOLS_UNAVAILABLE"}
    child = dict(environ)
    # No inherited credentials, alternate GitHub host or registry config.
    token = child.pop("V2_GH_TOKEN", "")
    for name in list(child):
        if name.startswith(("GH_", "GITHUB_", "DOCKER_")): child.pop(name)
    if not token or str(child.pop("V2_GH_VERIFIER_READY", "")).lower() != "true": return result, None
    child.update({"GH_TOKEN": token, "GH_HOST": "github.com", "GH_CONFIG_DIR": str(Path(folder) / "gh"),
        "DOCKER_CONFIG": str(Path(folder) / "docker"), "GH_PROMPT_DISABLED": "true"})
    try:
        version = execute(["gh", "version"], folder, child).decode()
        if not version.startswith("gh version " + GH_VERSION + " "): return result, None
        result["failure_code"] = "REGISTRY_UNAVAILABLE"
        azure_env = {k: v for k, v in child.items() if k != "GH_TOKEN"}
        response = json.loads(execute(["az", "acr", "login", "--name", p["registry_name"], "--expose-token", "--output", "json"], folder, azure_env))
        registry = p["registry_name"] + ".azurecr.io"
        access = response.get("accessToken")
        if response.get("loginServer") != registry or not isinstance(access, str) or not 32 <= len(access) <= 32768:
            return result, None
        directory = Path(child["DOCKER_CONFIG"]); directory.mkdir(mode=0o700)
        config = directory / "config.json"
        credential = base64.b64encode(("00000000-0000-0000-0000-000000000000:" + access).encode()).decode()
        config.write_text(json.dumps({"auths": {registry: {"auth": credential}}}), encoding="utf-8"); config.chmod(0o600)
        result.update({"status": "rejected", "failure_code": "ATTESTATION_REJECTED"})
        # Fetch from GitHub's current repository association; no caller bundle,
        # custom roots, regex identity, predicate fields or verification bypass.
        args = ["gh", "attestation", "verify", f"oci://{registry}/{p['image_repository']}@sha256:{p['image_sha256']}",
            "--hostname", "github.com", "--repo", manifest["repository"], "--signer-workflow", workflow,
            "--cert-identity", f"https://github.com/{workflow}@refs/heads/{manifest['branch']}",
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--source-digest", manifest["source_sha"],
            "--signer-digest", manifest["source_sha"], "--source-ref", "refs/heads/" + manifest["branch"],
            "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1", "--limit", "10", "--format", "json"]
        raw = execute(args, folder, child)
        records = json.loads(raw)
        if not isinstance(records, list) or not 1 <= len(records) <= 10 or any(not isinstance(row, dict) or not isinstance(row.get("verificationResult"), dict) or not row["verificationResult"].get("signature") or not row["verificationResult"].get("verifiedTimestamps") or not row["verificationResult"].get("statement") for row in records):
            return result, None
        result.update({"status": "verified", "failure_code": None, "output_sha256": sha(raw)})
        return result, raw
    except (PreflightError, ValueError, KeyError, OSError, UnicodeError):
        return result, None
