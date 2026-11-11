"""Read-only entry point for an exact conditional release rehearsal."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from backend.contracts import conditional_release, golden_customer_plan as golden
from customer_runner import plan, rehearsal
from customer_runner.preflight import PreflightError


PROOF_LIMIT = 131072
KEY_LIMIT = 8192
REHEARSAL_VERIFIER = Path(__file__).with_name("verify_conditional_release.mjs").resolve()


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_json(path, limit):
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    if not raw or len(raw) > limit:
        raise conditional_release.RehearsalRejected("INPUT_SIZE_REJECTED")
    return json.loads(raw, object_pairs_hook=unique_object)


def artifact_hash(path):
    hasher = sha256()
    length = 0
    with path.open("rb") as source:
        while chunk := source.read(128 * 1024):
            length += len(chunk)
            if length > plan.LIMIT:
                raise conditional_release.RehearsalRejected("ARTIFACT_SIZE_REJECTED")
            hasher.update(chunk)
    if length == 0:
        raise conditional_release.RehearsalRejected("ARTIFACT_SIZE_REJECTED")
    return hasher.hexdigest()


def verify_signatures(proofs, trusted):
    with tempfile.TemporaryDirectory(prefix="v2-conditional-rehearsal-") as folder:
        root = Path(folder)
        proofs_path, keys_path = root / "proofs.json", root / "trusted.json"
        proofs_path.write_bytes(golden.encode(proofs))
        keys_path.write_bytes(golden.encode(trusted))
        proofs_path.chmod(0o600)
        keys_path.chmod(0o600)
        env = rehearsal.child_environment(os.environ, root)
        (root / "empty.tfrc").touch()
        try:
            result = plan.command(
                ["node", str(REHEARSAL_VERIFIER), str(proofs_path), str(keys_path)], str(root), env, timeout=15,
            )
        except PreflightError as error:
            reason = "TOOLS_UNAVAILABLE" if error.code == "TOOLS_UNAVAILABLE" else "SIGNATURE_REJECTED"
            raise conditional_release.RehearsalRejected(reason) from None
        if result.strip() != b"verified":
            raise conditional_release.RehearsalRejected("SIGNATURE_REJECTED")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("proofs", "trusted-keys", "observation", "what-if", "saved-plan"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args(argv)
    report = {"mode": "conditional-release-rehearsal", "outcome": "rejected", "azure_writes": False,
              "is_authorization": False, "observation_source": "caller-provided"}
    try:
        proofs = read_json(args.proofs, PROOF_LIMIT)
        trusted = read_json(args.trusted_keys, KEY_LIMIT)
        observation = read_json(args.observation, PROOF_LIMIT)
        verify_signatures(proofs, trusted)
        artifact_hashes = {"what_if_sha256": artifact_hash(args.what_if), "saved_plan_sha256": artifact_hash(args.saved_plan)}
        report.update(conditional_release.check_rehearsal_bindings(proofs, observation, artifact_hashes), outcome="verified")
    except conditional_release.RehearsalRejected as error:
        report["reason"] = str(error)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        report["reason"] = "MALFORMED_PROOF"
    except OSError:
        report["reason"] = "INPUT_UNAVAILABLE"
    print(json.dumps(report, sort_keys=True))
    return int(report["outcome"] != "verified")


if __name__ == "__main__":
    raise SystemExit(main())
