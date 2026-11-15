// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mkopnsrc/traefik-gatekeeper/internal/config"
	"github.com/mkopnsrc/traefik-gatekeeper/internal/state"
	"github.com/mkopnsrc/traefik-gatekeeper/internal/telegram"
)

type fakeApprover struct {
	mu   sync.Mutex
	sent []telegram.Request
}

func (f *fakeApprover) Send(_ context.Context, r telegram.Request) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, r)
	return len(f.sent), nil
}
func (f *fakeApprover) Close(context.Context, int, string) error          { return nil }
func (f *fakeApprover) Answer(context.Context, telegram.Decision, string) {}

type env struct {
	srv     *Server
	h       http.Handler
	appr    *fakeApprover
	allow   string
	cookies []*http.Cookie
	csrf    string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow")
	_ = os.MkdirAll(allow, 0o755)
	cfg := &config.Config{
		BasePath: "/routemein", AllowedHosts: []string{".example.com"},
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Durations:      []time.Duration{30 * time.Minute}, CookieSecure: true,
		RateLimit: 1000, RateBurst: 1000, MaxInFlight: 16, TZ: time.UTC,
	}
	st, err := state.Open(state.Options{AllowlistDir: allow, AllowlistFile: "dyn.yml", StateDir: filepath.Join(dir, "state"),
		Middleware: "dynamic-ipwhitelist", Base: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Durations: cfg.Durations, PendingTTL: 10 * time.Minute, MaxActive: 5, PerIPHour: 3, GlobalHour: 10})
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeApprover{}
	s, err := New(cfg, st, a)
	if err != nil {
		t.Fatal(err)
	}
	return &env{srv: s, h: s.Handler(), appr: a, allow: filepath.Join(allow, "dyn.yml")}
}

// do sends a request as it arrives through traefik: peer 10.1.1.1, client in X-Forwarded-For.
func (e *env) do(t *testing.T, method, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, "http://app.example.com"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://app.example.com")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	} else {
		r = httptest.NewRequest(method, "http://app.example.com"+path, nil)
	}
	r.RemoteAddr = "10.1.1.1:5555"
	r.Header.Set("X-Forwarded-For", "192.0.2.66, 198.51.100.7")
	for k, v := range hdr {
		if k == "Host" {
			r.Host = v
		} else {
			r.Header.Set(k, v)
		}
	}
	for _, c := range e.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	e.cookies = append(e.cookies, w.Result().Cookies()...)
	if m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String()); m != nil {
		e.csrf = m[1]
	}
	return w
}

func TestPageShowsTrustedClientAddress(t *testing.T) {
	e := newEnv(t)
	w := e.do(t, "GET", "/routemein", nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "198.51.100.7") || strings.Contains(w.Body.String(), "192.0.2.66") {
		t.Errorf("page: %d\n%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("CSP missing")
	}
	if w := e.do(t, "GET", "/routemein", nil, map[string]string{"Host": "attacker.example"}); w.Code != 421 {
		t.Errorf("foreign host = %d", w.Code)
	}
	if w := e.do(t, "GET", "/routemein", nil, map[string]string{"Host": "example.com.attacker.example"}); w.Code != 421 {
		t.Errorf("suffix trick = %d", w.Code)
	}
}

func TestRequestNeedsCSRFAndNotifiesOnce(t *testing.T) {
	e := newEnv(t)
	e.do(t, "GET", "/routemein", nil, nil)
	if w := e.do(t, "POST", "/routemein", url.Values{"csrf": {"wrong"}}, nil); w.Code != 403 {
		t.Errorf("bad token = %d", w.Code)
	}
	if w := e.do(t, "POST", "/routemein", url.Values{"csrf": {e.csrf}}, map[string]string{"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"}); w.Code != 403 {
		t.Errorf("cross-site = %d", w.Code)
	}
	if len(e.appr.sent) != 0 {
		t.Fatal("refused requests reached the approver")
	}
	for i := 0; i < 3; i++ { // reloads and double clicks
		if w := e.do(t, "POST", "/routemein", url.Values{"csrf": {e.csrf}}, nil); w.Code != 303 {
			t.Fatalf("request = %d", w.Code)
		}
	}
	if len(e.appr.sent) != 1 || e.appr.sent[0].IP != "198.51.100.7" {
		t.Fatalf("approver got %+v", e.appr.sent)
	}
	w := e.do(t, "GET", "/routemein", nil, nil)
	if !strings.Contains(w.Body.String(), e.appr.sent[0].Code) {
		t.Error("requester doesn't see the code")
	}
	// GET never changes anything.
	e.do(t, "GET", "/routemein/status", nil, nil)
	if len(e.appr.sent) != 1 {
		t.Error("GET sent a request")
	}
}

func TestApprovalWritesAllowlist(t *testing.T) {
	e := newEnv(t)
	e.do(t, "GET", "/routemein", nil, nil)
	e.do(t, "POST", "/routemein", url.Values{"csrf": {e.csrf}}, nil)
	id := e.appr.sent[0].ID
	e.srv.Decide(context.Background(), telegram.Decision{RequestID: id, Approve: true, Duration: 30 * time.Minute, By: 7, ByName: "admin"})
	b, _ := os.ReadFile(e.allow)
	if !strings.Contains(string(b), `"198.51.100.7/32"`) {
		t.Errorf("allowlist:\n%s", b)
	}
	if w := e.do(t, "GET", "/routemein", nil, nil); !strings.Contains(w.Body.String(), "Access granted") {
		t.Error("page doesn't show the grant")
	}
}
