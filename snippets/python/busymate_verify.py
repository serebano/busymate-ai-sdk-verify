"""Verify the Busymate AI connector actor token (bmai.actor/3, ES256 + JWKS). Needs: pip install cryptography
Usage:
    actor = verify_busymate_actor(request.headers, audience="https://mcp.acme.com", tenant_id="acme", connector_id="conn_1")
    # -> Actor(sub, idp, confirmed, tool, jti, support_session_id); raises BusymateActorError(reason)
"""
import base64, json, threading, time, urllib.request
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

DEFAULT_JWKS_URL = "https://busymate.ai/.well-known/bmai-actor-jwks.json"
ISSUER, TYP, SKEW, MAX_LIFETIME = "https://busymate.ai", "bmai-actor+jwt", 10, 120


class BusymateActorError(Exception):
    def __init__(self, reason: str, message: str = ""):
        super().__init__(message or reason)
        self.reason = reason


@dataclass
class Actor:
    sub: str
    idp: str
    confirmed: bool
    tool: str
    jti: str
    support_session_id: Optional[str] = None


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class MemoryReplayCache:
    """jti -> exp. Use a shared store (Redis SET NX EX) when you run several instances."""

    def __init__(self):
        self._seen, self._lock = {}, threading.Lock()

    def add(self, jti: str, exp: int, now: int) -> bool:
        with self._lock:
            for k in [k for k, e in self._seen.items() if e < now]:
                del self._seen[k]
            if jti in self._seen:
                return False
            self._seen[jti] = exp
            return True


_default_cache = MemoryReplayCache()
_jwks = {"url": None, "keys": {}, "at": 0.0, "refetch": 0.0}


def _keys_from(doc) -> dict:
    out = {}
    for k in (doc or {}).get("keys", []):
        if k.get("kty") != "EC" or k.get("crv") != "P-256" or not k.get("kid"):
            continue
        if k.get("alg") not in (None, "ES256") or k.get("use") not in (None, "sig"):
            continue
        x, y = int.from_bytes(_b64d(k["x"]), "big"), int.from_bytes(_b64d(k["y"]), "big")
        out[k["kid"]] = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    return out


def _fetch(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return _keys_from(json.load(r))
    except Exception as e:  # network, HTTP, JSON
        raise BusymateActorError("jwks_unavailable", str(e))


def _key_for(kid: str, jwks, jwks_url: str):
    if jwks is not None:
        key = _keys_from(jwks).get(kid)
    else:
        now = time.time()
        if _jwks["url"] != jwks_url or now - _jwks["at"] > 600:
            _jwks.update(url=jwks_url, keys=_fetch(jwks_url), at=now, refetch=now)
        key = _jwks["keys"].get(kid)
        if key is None and now - _jwks["refetch"] > 30:  # unknown kid: rotation, refetch (rate-limited)
            _jwks.update(keys=_fetch(jwks_url), at=now, refetch=now)
            key = _jwks["keys"].get(kid)
    if key is None:
        raise BusymateActorError("unknown_kid")
    return key


def actor_token_from(headers) -> Optional[str]:
    """X-Bmai-Actor first, else Authorization: Bearer only when its header typ is bmai-actor+jwt."""
    h = {str(k).lower(): v for k, v in dict(headers).items()}
    x = (h.get("x-bmai-actor") or "").strip()
    if x:
        return x
    a = h.get("authorization") or ""
    if a[:7].lower() == "bearer " and a[7:].strip():
        tok = a[7:].strip()
        try:
            if json.loads(_b64d(tok.split(".")[0])).get("typ") == TYP:
                return tok
        except Exception:
            pass
    return None


def verify_busymate_actor(headers_or_token, *, audience, tenant_id, connector_id, idp=None, tool=None,
                          jwks_url=DEFAULT_JWKS_URL, jwks=None, replay_cache=None, now=None) -> Actor:
    now = int(time.time()) if now is None else int(now)
    token = headers_or_token.strip() if isinstance(headers_or_token, str) else actor_token_from(headers_or_token)
    if not token:
        raise BusymateActorError("missing_token")
    parts = token.split(".")
    if len(parts) != 3:
        raise BusymateActorError("malformed")
    try:
        hdr = json.loads(_b64d(parts[0]))
        if not isinstance(hdr, dict):
            raise ValueError
    except Exception:
        raise BusymateActorError("malformed")
    if hdr.get("alg") != "ES256":
        raise BusymateActorError("bad_alg")
    if hdr.get("typ") != TYP:
        raise BusymateActorError("bad_typ")
    kid = hdr.get("kid")
    if not isinstance(kid, str) or not kid:
        raise BusymateActorError("unknown_kid")
    key = _key_for(kid, jwks, jwks_url)
    try:
        raw = _b64d(parts[2])
        if len(raw) != 64:
            raise InvalidSignature()
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   (parts[0] + "." + parts[1]).encode(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise BusymateActorError("bad_signature")
    try:
        p = json.loads(_b64d(parts[1]))
        if not isinstance(p, dict):
            raise ValueError
    except Exception:
        raise BusymateActorError("malformed")

    if p.get("iss") != ISSUER:
        raise BusymateActorError("bad_issuer")
    aud = p.get("aud")
    if not (aud == audience or (isinstance(aud, list) and aud == [audience])):
        raise BusymateActorError("bad_audience")
    sub, jti, iat, exp, nbf = p.get("sub"), p.get("jti"), p.get("iat"), p.get("exp"), p.get("nbf")
    num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
    if not (isinstance(sub, str) and sub and isinstance(jti, str) and jti and num(iat) and num(exp)):
        raise BusymateActorError("missing_claim")
    if now > exp + SKEW:
        raise BusymateActorError("expired")
    if iat > now + SKEW or (num(nbf) and nbf > now + SKEW):
        raise BusymateActorError("not_yet_valid")
    if exp - iat > MAX_LIFETIME:
        raise BusymateActorError("lifetime_too_long")
    if p.get("tenant_id") != tenant_id:
        raise BusymateActorError("tenant_mismatch")
    if p.get("connector_id") != connector_id:
        raise BusymateActorError("connector_mismatch")
    if idp is not None and p.get("idp") != idp:
        raise BusymateActorError("idp_mismatch")
    if p.get("actor_kind") != "identified":
        raise BusymateActorError("not_identified")
    if tool is not None and p.get("tool") != tool:
        raise BusymateActorError("tool_mismatch")
    if not (replay_cache or _default_cache).add(jti, int(exp), now):
        raise BusymateActorError("replay")
    return Actor(sub=sub, idp=p.get("idp") if isinstance(p.get("idp"), str) else "", confirmed=p.get("confirmed") is True,
                 tool=p.get("tool") if isinstance(p.get("tool"), str) else "", jti=jti,
                 support_session_id=p.get("support_session_id") if isinstance(p.get("support_session_id"), str) else None)


def require_confirmed(actor: Actor, is_write_tool: bool = True) -> None:
    """Money-moving and write tools need the customer's in-chat confirmation."""
    if is_write_tool and not actor.confirmed:
        raise BusymateActorError("confirmation_required")
