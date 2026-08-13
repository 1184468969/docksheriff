package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadOnlyRequestsAndNegotiation(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("write-like method %s", r.Method)
		}
		paths = append(paths, r.URL.RequestURI())
		switch r.URL.Path {
		case "/_ping":
			w.Write([]byte("OK"))
		case "/version":
			w.Write([]byte(`{"ApiVersion":"1.50","MinAPIVersion":"1.24"}`))
		case "/v1.48/containers/json":
			w.Write([]byte(`[{"Id":"abc"}]`))
		case "/v1.48/containers/abc/json":
			w.Write([]byte(`{"Name":"/demo","Config":{"Image":"alpine:3","User":"1"},"HostConfig":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, err := c.List(context.Background(), false)
	if err != nil || len(items) != 1 {
		t.Fatalf("list=%v err=%v", items, err)
	}
	if _, err = c.Inspect(context.Background(), "abc"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(paths, " ")
	if !strings.Contains(joined, "all=false") {
		t.Fatalf("requests: %s", joined)
	}
}

func TestEndpointRedaction(t *testing.T) {
	c, err := New("tcp://user:secret@example.test:2375?token=hidden")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.Endpoint(), "secret") || strings.Contains(c.Endpoint(), "token") {
		t.Fatalf("leaked endpoint: %s", c.Endpoint())
	}
	if !c.InsecureTCP() {
		t.Fatal("plain TCP was not identified")
	}
}

func TestVersionNegotiation(t *testing.T) {
	tests := []struct {
		server, min, want string
		fail              bool
	}{{"1.44", "1.24", "1.44", false}, {"1.50", "1.24", "1.48", false}, {"bad", "", "", true}, {"1.50", "1.49", "", true}}
	for _, tt := range tests {
		got, err := negotiateVersion(tt.server, tt.min)
		if (err != nil) != tt.fail || got != tt.want {
			t.Errorf("negotiateVersion(%q,%q)=(%q,%v)", tt.server, tt.min, got, err)
		}
	}
}
