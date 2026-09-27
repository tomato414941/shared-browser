package legacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestCookieSessionConnectsAndReconnects(t *testing.T) {
	active := true
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !active || r.Header.Get("Cookie") != "NEKO_SESSION=valid" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/whoami":
			json.NewEncoder(w).Encode(map[string]any{
				"id": "viewer-session", "profile": map[string]any{"name": "viewer", "is_admin": false},
			})
		case "/api/logout":
			active = false
			json.NewEncoder(w).Encode(true)
		case "/api/protected":
			json.NewEncoder(w).Encode(true)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	handler := New(strings.TrimPrefix(backend.URL, "http://"), "")
	for attempt := 0; attempt < 2; attempt++ {
		r := httptest.NewRequest(http.MethodGet, "http://browser.test/ws", nil)
		r.Header.Set("Cookie", "NEKO_SESSION=valid")
		session := handler.newSession(r)
		if err := session.create("", ""); err != nil {
			t.Fatal(err)
		}
		if session.id != "viewer-session" || session.name != "viewer" || session.isAdmin {
			t.Fatalf("unexpected viewer identity: %s / %s / admin=%v", session.id, session.name, session.isAdmin)
		}
		if err := session.apiReq(http.MethodGet, "/api/protected", nil, nil); err != nil {
			t.Fatal(err)
		}
		session.destroy()
	}
}

func TestExpiredCookieRequiresAuthentication(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer backend.Close()
	r := httptest.NewRequest(http.MethodGet, "http://browser.test/ws", nil)
	r.Header.Set("Cookie", "NEKO_SESSION=expired")
	session := New(strings.TrimPrefix(backend.URL, "http://"), "").newSession(r)
	if err := session.create("", ""); err == nil {
		t.Fatal("expected authentication to fail")
	}
}

func TestWebSocketAuthenticatesOnlyFromItsOwnOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := DefaultUpgrader.Upgrade(w, r, nil)
		if err == nil {
			conn.Close()
		}
	}))
	defer server.Close()
	for _, tc := range []struct {
		name, origin string
		status       int
	}{
		{"same origin", server.URL, http.StatusSwitchingProtocols},
		{"another origin", "https://untrusted.example", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), http.Header{"Origin": {tc.origin}})
			if conn != nil {
				conn.Close()
			}
			if response == nil || response.StatusCode != tc.status {
				t.Fatalf("unexpected handshake: response=%v error=%v", response, err)
			}
			response.Body.Close()
		})
	}
}
