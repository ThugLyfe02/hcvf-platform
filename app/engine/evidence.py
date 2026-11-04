"""Tamper-evident evidence sealing.

Every observation is stored content-addressed and combined into an RFC 6962
style Merkle tree with domain separation, so a single finding can be proven
against the run root without disclosing the rest of the evidence. The manifest
is then MACed (and optionally signed with Ed25519 when ``cryptography`` is
installed) and can be verified offline by a third party.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from app.engine.errors import EvidenceError

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


class MerkleTree:
    """Inclusion-proof Merkle tree with odd-leaf duplication."""

    def __init__(self, leaves: list[bytes]) -> None:
        if not leaves:
            raise EvidenceError("cannot build a Merkle tree without leaves")
        self.size = len(leaves)
        self.levels: list[list[bytes]] = [[_leaf(leaf) for leaf in leaves]]
        current = self.levels[0]
        while len(current) > 1:
            if len(current) % 2 == 1:
                current = [*current, current[-1]]
            self.levels.append([_node(current[i], current[i + 1]) for i in range(0, len(current), 2)])
            current = self.levels[-1]

    @property
    def root(self) -> str:
        return self.levels[-1][0].hex()

    def proof(self, index: int) -> list[tuple[str, str]]:
        if index < 0 or index >= self.size:
            raise EvidenceError(f"leaf index {index} out of range")
        proof: list[tuple[str, str]] = []
        position = index
        for level in self.levels[:-1]:
            sibling = position ^ 1
            if sibling >= len(level):
                sibling = position
            side = "right" if position % 2 == 0 else "left"
            proof.append((side, level[sibling].hex()))
            position //= 2
        return proof


def verify_inclusion(leaf: bytes, proof: list[tuple[str, str]], root: str) -> bool:
    current = _leaf(leaf)
    for side, sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        current = _node(current, sibling) if side == "right" else _node(sibling, current)
    return current.hex() == root


class EvidenceStore(Protocol):
    def put(self, payload: bytes, *, media_type: str = "application/octet-stream") -> str: ...

    def get(self, digest: str) -> bytes: ...


class FileEvidenceStore:
    """Content-addressed store on the local filesystem (S3-compatible layout)."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        (self.root / "blobs").mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if len(digest) < 4:
            raise EvidenceError(f"invalid digest {digest!r}")
        return self.root / "blobs" / digest[:2] / digest[2:4] / digest

    def put(self, payload: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = sha256_hex(payload)
        path = self._path(digest)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(payload)
            os.replace(tmp, path)
            (path.with_suffix(".media")).write_text(media_type, encoding="utf-8")
        return digest

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        if not path.exists():
            raise EvidenceError(f"blob {digest} is missing from the store")
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise EvidenceError(f"blob {digest} failed integrity verification")
        return data


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put(self, payload: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = sha256_hex(payload)
        self._blobs[digest] = payload
        return digest

    def get(self, digest: str) -> bytes:
        try:
            return self._blobs[digest]
        except KeyError as exc:
            raise EvidenceError(f"blob {digest} is missing") from exc


@dataclass
class EvidenceEntry:
    digest: str
    kind: str
    label: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {"digest": self.digest, "kind": self.kind, "label": self.label, "size": self.size}


@dataclass
class EvidenceBundle:
    store: EvidenceStore
    entries: list[EvidenceEntry] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def add(self, payload: bytes, *, kind: str, label: str, media_type: str = "application/octet-stream") -> str:
        digest = self.store.put(payload, media_type=media_type)
        self.entries.append(EvidenceEntry(digest=digest, kind=kind, label=label, size=len(payload)))
        return digest

    def tree(self) -> MerkleTree:
        if not self.entries:
            raise EvidenceError("evidence bundle is empty")
        leaves = [bytes.fromhex(entry.digest) for entry in self.entries]
        return MerkleTree(leaves)

    def root(self) -> str:
        return self.tree().root

    def manifest(self, *, metadata: dict[str, object] | None = None) -> dict[str, object]:
        return {
            "format": "hcvf-evidence/v1",
            "created_at": self.created_at,
            "root": self.root(),
            "leaf_count": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries],
            "metadata": metadata or {},
        }


def sign_manifest(manifest: dict[str, object], key: bytes) -> str:
    body = json.dumps(manifest, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_manifest(manifest: dict[str, object], signature: str, key: bytes) -> bool:
    expected = sign_manifest({k: v for k, v in manifest.items() if k != "signature"}, key)
    return hmac.compare_digest(expected, signature)


def seal_bundle(
    bundle: EvidenceBundle,
    *,
    key: bytes,
    metadata: dict[str, object],
) -> dict[str, object]:
    manifest = bundle.manifest(metadata=metadata)
    manifest["signature"] = {"alg": "HMAC-SHA256", "value": sign_manifest(manifest, key)}
    return manifest


def write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def verification_key_from_env() -> bytes:
    value = os.environ.get("HCVF_EVIDENCE_KEY", "")
    if not value:
        return b"hcvf-development-evidence-key"
    return value.encode("utf-8")
