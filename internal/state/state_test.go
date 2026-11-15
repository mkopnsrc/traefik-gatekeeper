// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

package state

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func open(t *testing.T, dir string, c *clock) *Store {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	o := Options{
		AllowlistDir: filepath.Join(dir, "allow"), AllowlistFile: "dynamic-allowlist.yml", StateDir: filepath.Join(dir, "state"),
		Middleware: "dynamic-ipwhitelist", Depth: 1,
		Base:      []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")},
		Durations: []time.Duration{30 * time.Minute, 2 * time.Hour}, PendingTTL: 10 * time.Minute,
		MaxActive: 2, PerIPHour: 2, GlobalHour: 5, Now: c.now,
	}
	_ = os.MkdirAll(o.AllowlistDir, 0o755)
	s, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var ip1, ip2, ip6 = netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::5")

func allowlist(t *testing.T, s *Store) string {
	b, err := s.allow.ReadFile("dynamic-allowlist.yml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRequestApproveExpire(t *testing.T) {
	c := &clock{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	s := open(t, dir, c)
	if a := allowlist(t, s); !strings.Contains(a, `- "10.0.0.0/8"`) || strings.Contains(a, "198.51") {
		t.Fatalf("initial allowlist:\n%s", a)
	}
	r, fresh, err := s.Request(ip1, "app.example.com", "agent")
	if err != nil || !fresh || len(r.Code) != 7 {
		t.Fatalf("request: %v %v %+v", err, fresh, r)
	}
	if r2, fresh2, _ := s.Request(ip1, "app.example.com", "agent"); fresh2 || r2.ID != r.ID {
		t.Error("a second request while pending created a new one")
	}
	if _, err := s.Decide(r.ID, 45*time.Minute, 1); !errors.Is(err, ErrBadDuration) {
		t.Errorf("unlisted duration: %v", err)
	}
	if _, err := s.Decide(r.ID, 30*time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(r.ID, 2*time.Hour, 1); !errors.Is(err, ErrNotPending) {
		t.Errorf("second decision: %v", err)
	}
	a := allowlist(t, s)
	if !strings.Contains(a, `- "198.51.100.7/32"`) || !strings.Contains(a, "depth: 1") || !strings.Contains(a, "dynamic-ipwhitelist:") {
		t.Errorf("approved allowlist:\n%s", a)
	}
	if _, _, err := s.Request(ip1, "app.example.com", "agent"); !errors.Is(err, ErrAllowed) {
		t.Errorf("request while allowed: %v", err)
	}

	// Survives a restart.
	s2 := open(t, dir, c)
	if g := s2.Active(); len(g) != 1 || g[0].IP != ip1 {
		t.Errorf("grants after restart: %+v", g)
	}
	c.t = c.t.Add(31 * time.Minute)
	ended, err := s2.Sweep()
	if err != nil || len(ended) != 1 {
		t.Fatalf("sweep: %v %v", ended, err)
	}
	if strings.Contains(allowlist(t, s2), "198.51") {
		t.Error("expired address still allowed")
	}
}

func TestLimits(t *testing.T) {
	c := &clock{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := open(t, "", c)
	for i := 0; i < 2; i++ {
		r, _, err := s.Request(ip1, "h", "a")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = s.Decide(r.ID, 0, 1) // deny, so the next one is a new request
	}
	if _, _, err := s.Request(ip1, "h", "a"); !errors.Is(err, ErrRateIP) {
		t.Errorf("third request in an hour: %v", err)
	}
	c.t = c.t.Add(61 * time.Minute)
	if _, _, err := s.Request(ip1, "h", "a"); err != nil {
		t.Errorf("after an hour: %v", err)
	}
	// Pending requests expire without a decision.
	r, _, _ := s.Request(ip2, "h", "a")
	c.t = c.t.Add(11 * time.Minute)
	if _, err := s.Decide(r.ID, 30*time.Minute, 1); !errors.Is(err, ErrNotPending) {
		t.Errorf("decision after the pending TTL: %v", err)
	}
}

func TestMaxActiveAndIPv6(t *testing.T) {
	c := &clock{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := open(t, "", c)
	for _, ip := range []netip.Addr{ip1, ip6} {
		r, _, _ := s.Request(ip, "h", "a")
		if _, err := s.Decide(r.ID, 30*time.Minute, 1); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(allowlist(t, s), `- "2001:db8::5/128"`) {
		t.Error("IPv6 address not written as /128")
	}
	r, _, _ := s.Request(ip2, "h", "a")
	if _, err := s.Decide(r.ID, 30*time.Minute, 1); !errors.Is(err, ErrFull) {
		t.Errorf("over MaxActive: %v", err)
	}
}

func TestHostileInputNeverReachesYAML(t *testing.T) {
	c := &clock{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s := open(t, "", c)
	r, _, _ := s.Request(ip1, "x\n  evil: true", strings.Repeat("A", 500)+"\n- 0.0.0.0/0")
	_, _ = s.Decide(r.ID, 30*time.Minute, 1)
	a := allowlist(t, s)
	if strings.Contains(a, "evil") || strings.Contains(a, "0.0.0.0/0") {
		t.Errorf("request text leaked into the allowlist:\n%s", a)
	}
	if len(r.Agent) > 200 {
		t.Error("user agent not truncated")
	}
}

func TestInPlaceWriteKeepsInode(t *testing.T) {
	c := &clock{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow")
	_ = os.MkdirAll(allow, 0o755)
	f := filepath.Join(allow, "dyn.yml")
	_ = os.WriteFile(f, []byte("old\n"), 0o644)
	before, _ := os.Stat(f)
	s, err := Open(Options{AllowlistDir: allow, AllowlistFile: "dyn.yml", StateDir: filepath.Join(dir, "st"),
		Middleware: "m", Base: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Durations: []time.Duration{time.Hour}, PendingTTL: time.Hour, MaxActive: 1, PerIPHour: 1, GlobalHour: 1,
		Now: c.now, InPlace: true})
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ := s.Request(ip1, "h", "a")
	if _, err := s.Decide(r.ID, time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(f)
	if !os.SameFile(before, after) {
		t.Error("in-place mode replaced the file instead of rewriting it")
	}
	b, _ := os.ReadFile(f)
	if !strings.Contains(string(b), "198.51.100.7/32") {
		t.Errorf("content: %s", b)
	}
	if ents, _ := os.ReadDir(allow); len(ents) != 1 {
		t.Errorf("left extra files: %v", ents)
	}
}
