package busymateverify

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
)

type call struct {
	Headers map[string]string
	Options map[string]any
	Expect  struct {
		Ok     bool
		Reason string
		Actor  map[string]any
	}
}
type vcase struct {
	Name    string
	Options map[string]any
	Calls   []call
}
type vectors struct {
	Now    int64
	Config map[string]any
	JWKS   json.RawMessage `json:"jwks"`
	Cases  []vcase
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/actor-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var V vectors
	if err := json.Unmarshal(raw, &V); err != nil {
		t.Fatal(err)
	}
	for _, c := range V.Cases {
		t.Run(c.Name, func(t *testing.T) {
			cache := &MemoryReplay{}
			for _, k := range c.Calls {
				cfg := map[string]any{}
				for _, m := range []map[string]any{V.Config, c.Options, k.Options} {
					for a, b := range m {
						cfg[a] = b
					}
				}
				s := func(n string) string { x, _ := cfg[n].(string); return x }
				v := New(Options{Audience: s("audience"), TenantID: s("tenant_id"), ConnectorID: s("connector_id"), IDP: s("idp"), Tool: s("tool"),
					JWKS: V.JWKS, Now: func() int64 { return V.Now }})
				v.Replay = cache
				h := http.Header{}
				for a, b := range k.Headers {
					h.Set(a, b)
				}
				a, err := v.Verify(h)
				if k.Expect.Ok {
					if err != nil {
						t.Fatalf("unexpected %v", err)
					}
					e := k.Expect.Actor
					if a.Sub != e["sub"] || a.IDP != e["idp"] || a.Tool != e["tool"] || a.JTI != e["jti"] || a.Confirmed != e["confirmed"] {
						t.Fatalf("actor %+v != %v", a, e)
					}
					if ss, _ := e["supportSessionId"].(string); a.SupportSessionID != ss {
						t.Fatalf("support session %q", a.SupportSessionID)
					}
					ha, _ := e["hostAccount"].(string)
					he, _ := e["hostEnv"].(string)
					hu, _ := e["hostUser"].(string)
					if a.HostAccount != ha || a.HostEnv != he || a.HostUser != hu {
						t.Fatalf("host context %q %q %q", a.HostAccount, a.HostEnv, a.HostUser)
					}
				} else {
					var be *Error
					if !errors.As(err, &be) || be.Reason != k.Expect.Reason {
						t.Fatalf("want %s got %v", k.Expect.Reason, err)
					}
				}
			}
		})
	}
	if err := RequireConfirmed(&Actor{}, true); err == nil {
		t.Fatal("requireConfirmed")
	}
}

// A jti stays remembered until exp + skew, so a replay at exp+5s is refused.
func TestReplayAtExpPlus5(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/actor-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var V vectors
	if err := json.Unmarshal(raw, &V); err != nil {
		t.Fatal(err)
	}
	var token string
	for _, c := range V.Cases {
		if c.Name == "replay" {
			token = c.Calls[0].Headers["X-Bmai-Actor"]
		}
	}
	parts := strings.Split(token, ".")
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct{ Exp int64 }
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatal(err)
	}
	cache := &MemoryReplay{}
	s := func(n string) string { x, _ := V.Config[n].(string); return x }
	at := func(now int64) error {
		v := New(Options{Audience: s("audience"), TenantID: s("tenant_id"), ConnectorID: s("connector_id"),
			JWKS: V.JWKS, Now: func() int64 { return now }})
		v.Replay = cache
		h := http.Header{}
		h.Set("X-Bmai-Actor", token)
		_, err := v.Verify(h)
		return err
	}
	if err := at(claims.Exp - 5); err != nil {
		t.Fatalf("first use: %v", err)
	}
	var be *Error
	if err := at(claims.Exp + 5); !errors.As(err, &be) || be.Reason != "replay" {
		t.Fatalf("replay at exp+5: want replay, got %v", err)
	}
}
