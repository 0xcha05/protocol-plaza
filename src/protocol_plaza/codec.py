"""Deterministic encoding helpers.

Production will use deterministic CBOR. This vertical slice uses canonical JSON so
the signed bytes are easy to inspect and test.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def parse_json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redact_token(token: str) -> str:
    return f"{token[:5]}…{token[-4:]}" if len(token) > 12 else "[redacted]"
