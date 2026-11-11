"""Azure Blob compare-and-set for an exact release pointer."""

from dataclasses import asdict, dataclass
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


SCHEMA = "v2.release-pointer.v1"
ETAG = re.compile(r'"0x[0-9a-fA-F]{8,32}"')
VERSION = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z")
RELEASE_ID = re.compile(r"[a-z][a-z0-9-]{0,39}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
LIMIT = 4096


class StorageUnavailable(Exception):
    """The operation is unavailable or its result requires reconciliation."""


class StalePointer(Exception):
    """The service rejected the requested write precondition."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise StorageUnavailable("Unexpected redirect")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


@dataclass(frozen=True)
class ReleasePointer:
    generation: int
    release: str
    image_digest: str

    def __post_init__(self):
        if type(self.generation) is not int or not 1 <= self.generation < 2**53:
            raise ValueError("Invalid generation")
        if not isinstance(self.release, str) or not RELEASE_ID.fullmatch(self.release):
            raise ValueError("Invalid release identity")
        if not isinstance(self.image_digest, str) or not DIGEST.fullmatch(self.image_digest):
            raise ValueError("Invalid image digest")

    @classmethod
    def decode(cls, raw):
        if len(raw) > LIMIT:
            raise ValueError("Oversized release pointer")
        payload = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(payload, dict) or set(payload) != {"schema", "generation", "release", "image_digest"}:
            raise ValueError("Invalid release pointer fields")
        if payload.pop("schema") != SCHEMA:
            raise ValueError("Unknown release pointer schema")
        return cls(**payload)

    def encode(self):
        return json.dumps({"schema": SCHEMA, **asdict(self)}, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Snapshot:
    pointer: ReleasePointer
    etag: str
    version: str

    def __post_init__(self):
        if not ETAG.fullmatch(self.etag) or not VERSION.fullmatch(self.version):
            raise StorageUnavailable("Azure did not return a strong ETag and version")


class PointerBlob:
    def __init__(self, account, get_token, opener=None):
        if not re.fullmatch(r"[a-z][a-z0-9]{2,23}", account):
            raise ValueError("Invalid Azure Storage account name")
        self.url = f"https://{account}.blob.core.windows.net/pointer/release.json"
        self.get_token = get_token
        self.opener = opener or build_opener(NoRedirect())

    def read(self):
        return self._request("GET")

    def initialize(self, pointer):
        if pointer.generation != 1:
            raise ValueError("Initial release must use generation 1")
        return self._request("PUT", pointer, {"If-None-Match": "*"})

    def promote(self, expected, release, image_digest):
        if (release, image_digest) == (expected.pointer.release, expected.pointer.image_digest):
            raise ValueError("Promotion requires a different release")
        pointer = ReleasePointer(expected.pointer.generation + 1, release, image_digest)
        return self._replace(expected, pointer)

    def rollback(self, promoted, previous):
        if promoted.pointer.generation != previous.pointer.generation + 1:
            raise ValueError("Rollback requires the predecessor of the promoted release")
        return self.promote(promoted, previous.pointer.release, previous.pointer.image_digest)

    def _replace(self, expected, pointer):
        updated = self._request("PUT", pointer, {"If-Match": expected.etag})
        if updated.etag == expected.etag or updated.version == expected.version:
            raise StorageUnavailable("Azure did not confirm a new pointer version")
        return updated

    def _request(self, method, pointer=None, condition=None):
        try:
            headers = {
                "Authorization": "Bearer " + self.get_token(),
                "x-ms-version": "2023-11-03",
                **(condition or {}),
            }
            if method == "PUT":
                headers.update({"x-ms-blob-type": "BlockBlob", "Content-Type": "application/json"})
            request = Request(self.url, headers=headers, data=pointer.encode() if pointer else None, method=method)
            with self.opener.open(request, timeout=8) as response:
                if response.status != (200 if method == "GET" else 201):
                    raise StorageUnavailable("Unexpected Azure Blob response")
                encrypted_header = "x-ms-server-encrypted" if method == "GET" else "x-ms-request-server-encrypted"
                if response.headers.get(encrypted_header, "").casefold() != "true":
                    raise StorageUnavailable("Azure Blob encryption was not confirmed")
                value = ReleasePointer.decode(response.read(LIMIT + 1)) if method == "GET" else pointer
                return Snapshot(value, response.headers.get("ETag", ""), response.headers.get("x-ms-version-id", ""))
        except HTTPError as error:
            with error:
                if method == "PUT" and error.code in {409, 412}:
                    raise StalePointer(f"Azure rejected the pointer precondition (HTTP {error.code})") from None
                raise StorageUnavailable(f"Azure Blob request failed (HTTP {error.code})") from None
        except (URLError, ValueError, OSError) as error:
            raise StorageUnavailable("Azure Blob response unavailable or invalid") from error
