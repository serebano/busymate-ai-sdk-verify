// Package busymateverify verifies the Busymate AI connector actor token (bmai.actor/3, ES256 + JWKS).
// Standard library only.
//
//	v := busymateverify.New(busymateverify.Options{Audience: "https://mcp.acme.com", TenantID: "acme", ConnectorID: "conn_1"})
//	actor, err := v.Verify(r.Header)   // errors are *busymateverify.Error with a stable Reason
package busymateverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DefaultJWKSURL = "https://busymate.ai/.well-known/bmai-actor-jwks.json"
	issuer         = "https://busymate.ai"
	typ            = "bmai-actor+jwt"
	skew           = 10
	maxLifetime    = 120
)

// Error carries a stable reason code. Answer 401 with WWW-Authenticate: Bearer error="invalid_token".
type Error struct{ Reason, Msg string }

func (e *Error) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return e.Reason
}
func fail(reason string) error { return &Error{Reason: reason} }

type Actor struct {
	Sub, IDP, Tool, JTI string
	Confirmed           bool
	SupportSessionID    string
}

type Options struct {
	Audience, TenantID, ConnectorID string
	IDP, Tool                       string // optional; empty = not checked
	JWKSURL                         string
	JWKS                            []byte // static JWKS (offline/tests); skips the network
	Now                             func() int64
	HTTPClient                      *http.Client
}

// ReplayCache returns true when jti is new. MemoryReplay is the default; use Redis SET NX EX across instances.
type ReplayCache interface {
	Add(jti string, exp, now int64) bool
}

type MemoryReplay struct {
	mu   sync.Mutex
	seen map[string]int64
}

func (m *MemoryReplay) Add(jti string, exp, now int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]int64{}
	}
	for k, e := range m.seen {
		if e < now {
			delete(m.seen, k)
		}
	}
	if _, ok := m.seen[jti]; ok {
		return false
	}
	m.seen[jti] = exp
	return true
}

type Verifier struct {
	Options
	Replay ReplayCache

	mu      sync.Mutex
	keys    map[string]*ecdsa.PublicKey
	at, ref int64
}

func New(o Options) *Verifier { return &Verifier{Options: o, Replay: &MemoryReplay{}} }

func b64d(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func parseKeys(doc []byte) (map[string]*ecdsa.PublicKey, error) {
	var d struct {
		Keys []struct{ Kty, Crv, X, Y, Kid, Alg, Use string } `json:"keys"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, err
	}
	out := map[string]*ecdsa.PublicKey{}
	for _, k := range d.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" || (k.Alg != "" && k.Alg != "ES256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		x, e1 := b64d(k.X)
		y, e2 := b64d(k.Y)
		if e1 != nil || e2 != nil {
			continue
		}
		out[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	}
	return out, nil
}

func (v *Verifier) fetch() (map[string]*ecdsa.PublicKey, error) {
	url := v.JWKSURL
	if url == "" {
		url = DefaultJWKSURL
	}
	c := v.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	res, err := c.Get(url)
	if err != nil {
		return nil, &Error{"jwks_unavailable", err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, &Error{"jwks_unavailable", fmt.Sprintf("JWKS HTTP %d", res.StatusCode)}
	}
	var raw json.RawMessage
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return nil, &Error{"jwks_unavailable", err.Error()}
	}
	keys, err := parseKeys(raw)
	if err != nil {
		return nil, &Error{"jwks_unavailable", err.Error()}
	}
	return keys, nil
}

func (v *Verifier) keyFor(kid string, now int64) (*ecdsa.PublicKey, error) {
	if v.JWKS != nil {
		keys, err := parseKeys(v.JWKS)
		if err != nil {
			return nil, &Error{"jwks_unavailable", err.Error()}
		}
		if k := keys[kid]; k != nil {
			return k, nil
		}
		return nil, fail("unknown_kid")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys == nil || now-v.at > 600 {
		k, err := v.fetch()
		if err != nil {
			return nil, err
		}
		v.keys, v.at, v.ref = k, now, now
	}
	if k := v.keys[kid]; k != nil {
		return k, nil
	}
	if now-v.ref > 30 { // unknown kid: rotation, refetch (rate-limited)
		k, err := v.fetch()
		if err != nil {
			return nil, err
		}
		v.keys, v.at, v.ref = k, now, now
		if kk := v.keys[kid]; kk != nil {
			return kk, nil
		}
	}
	return nil, fail("unknown_kid")
}

// TokenFrom returns X-Bmai-Actor, else the Authorization Bearer token only when its header typ is bmai-actor+jwt.
func TokenFrom(h http.Header) string {
	if x := strings.TrimSpace(h.Get("X-Bmai-Actor")); x != "" {
		return x
	}
	a := h.Get("Authorization")
	if len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		t := strings.TrimSpace(a[7:])
		if b, err := b64d(strings.SplitN(t, ".", 2)[0]); err == nil {
			var hd struct{ Typ string }
			if json.Unmarshal(b, &hd) == nil && hd.Typ == typ {
				return t
			}
		}
	}
	return ""
}

func num(v any) (float64, bool) { f, ok := v.(float64); return f, ok }

// Verify checks the token in the request headers.
func (v *Verifier) Verify(h http.Header) (*Actor, error) { return v.VerifyToken(TokenFrom(h)) }

func (v *Verifier) VerifyToken(token string) (*Actor, error) {
	now := time.Now().Unix()
	if v.Now != nil {
		now = v.Now()
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fail("missing_token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail("malformed")
	}
	hb, err := b64d(parts[0])
	var hdr map[string]any
	if err != nil || json.Unmarshal(hb, &hdr) != nil || hdr == nil {
		return nil, fail("malformed")
	}
	if hdr["alg"] != "ES256" {
		return nil, fail("bad_alg")
	}
	if hdr["typ"] != typ {
		return nil, fail("bad_typ")
	}
	kid, _ := hdr["kid"].(string)
	if kid == "" {
		return nil, fail("unknown_kid")
	}
	key, err := v.keyFor(kid, now)
	if err != nil {
		return nil, err
	}
	sig, err := b64d(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || len(sig) != 64 || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, fail("bad_signature")
	}
	pb, err := b64d(parts[1])
	var p map[string]any
	if err != nil || json.Unmarshal(pb, &p) != nil || p == nil {
		return nil, fail("malformed")
	}

	if p["iss"] != issuer {
		return nil, fail("bad_issuer")
	}
	okAud := p["aud"] == v.Audience
	if arr, isArr := p["aud"].([]any); isArr && len(arr) == 1 && arr[0] == v.Audience {
		okAud = true
	}
	if !okAud {
		return nil, fail("bad_audience")
	}
	sub, _ := p["sub"].(string)
	jti, _ := p["jti"].(string)
	iat, okIat := num(p["iat"])
	exp, okExp := num(p["exp"])
	if sub == "" || jti == "" || !okIat || !okExp {
		return nil, fail("missing_claim")
	}
	n := float64(now)
	if n > exp+skew {
		return nil, fail("expired")
	}
	nbf, hasNbf := num(p["nbf"])
	if iat > n+skew || (hasNbf && nbf > n+skew) {
		return nil, fail("not_yet_valid")
	}
	if exp-iat > maxLifetime {
		return nil, fail("lifetime_too_long")
	}
	if p["tenant_id"] != v.TenantID {
		return nil, fail("tenant_mismatch")
	}
	if p["connector_id"] != v.ConnectorID {
		return nil, fail("connector_mismatch")
	}
	if v.IDP != "" && p["idp"] != v.IDP {
		return nil, fail("idp_mismatch")
	}
	if p["actor_kind"] != "identified" {
		return nil, fail("not_identified")
	}
	if v.Tool != "" && p["tool"] != v.Tool {
		return nil, fail("tool_mismatch")
	}
	if !v.Replay.Add(jti, int64(exp), now) {
		return nil, fail("replay")
	}
	a := &Actor{Sub: sub, JTI: jti, Confirmed: p["confirmed"] == true}
	a.IDP, _ = p["idp"].(string)
	a.Tool, _ = p["tool"].(string)
	a.SupportSessionID, _ = p["support_session_id"].(string)
	return a, nil
}

// RequireConfirmed: money-moving and write tools need the customer's in-chat confirmation.
func RequireConfirmed(a *Actor, isWriteTool bool) error {
	if isWriteTool && !a.Confirmed {
		return fail("confirmation_required")
	}
	return nil
}
