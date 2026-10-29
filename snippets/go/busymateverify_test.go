package busymateverify

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
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
