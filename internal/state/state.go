// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

// Package state keeps access requests and approved addresses, persists them,
// and writes the traefik ipAllowList file that grants access.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrAllowed     = errors.New("this address is already allowed")
	ErrRateIP      = errors.New("too many requests from this address; try again later")
	ErrRateGlobal  = errors.New("too many requests right now; try again later")
	ErrNotPending  = errors.New("this request is no longer waiting for a decision")
	ErrFull        = errors.New("the maximum number of allowed addresses is reached")
	ErrBadDuration = errors.New("that duration is not one of the allowed choices")

	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
)

type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Denied   Status = "denied"
	Expired  Status = "expired" // no decision in time
)

type Request struct {
	ID      string     `json:"id"`
	IP      netip.Addr `json:"ip"`
	Host    string     `json:"host"`
	Agent   string     `json:"agent"`
	Code    string     `json:"code"`
	Created time.Time  `json:"created"`
	Status  Status     `json:"status"`
	Decided time.Time  `json:"decided,omitzero"`
	Until   time.Time  `json:"until,omitzero"`
	By      int64      `json:"by,omitempty"`
	Message int        `json:"message,omitempty"` // Telegram message ID
}

type Grant struct {
	IP      netip.Addr `json:"ip"`
	Until   time.Time  `json:"until"`
	Request string     `json:"request"`
}

type Options struct {
	AllowlistDir, AllowlistFile, StateDir string
	Middleware                            string
	Depth                                 int
	Base                                  []netip.Prefix
	Durations                             []time.Duration
	PendingTTL                            time.Duration
	MaxActive, PerIPHour, GlobalHour      int
	Now                                   func() time.Time // nil = time.Now
	// InPlace rewrites the allowlist file in one write instead of renaming a
	// temporary file over it: needed when the file itself is bind-mounted
	// (traefik doesn't watch sub-directories, so it must sit in traefik's
	// configuration directory, and a mounted file can't be renamed over).
	InPlace bool
}

type Store struct {
	opt   Options
	allow *os.Root
	st    *os.Root
	now   func() time.Time

	mu       sync.Mutex
	requests map[string]*Request
	grants   map[netip.Addr]*Grant
	hits     map[netip.Addr][]time.Time
	global   []time.Time
}

type persisted struct {
	Requests []*Request `json:"requests"`
	Grants   []*Grant   `json:"grants"`
}

func Open(o Options) (*Store, error) {
	if !nameRe.MatchString(o.Middleware) {
		return nil, fmt.Errorf("invalid middleware name %q", o.Middleware)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$`).MatchString(o.AllowlistFile) {
		return nil, fmt.Errorf("invalid allowlist file name %q", o.AllowlistFile)
	}
	allow, err := os.OpenRoot(o.AllowlistDir)
	if err != nil {
		return nil, fmt.Errorf("allowlist dir: %w", err)
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return nil, err
	}
	st, err := os.OpenRoot(o.StateDir)
	if err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Store{opt: o, allow: allow, st: st, now: o.Now,
		requests: map[string]*Request{}, grants: map[netip.Addr]*Grant{}, hits: map[netip.Addr][]time.Time{}}
	if b, err := st.ReadFile("state.json"); err == nil {
		var p persisted
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("state.json: %w", err)
		}
		for _, r := range p.Requests {
			s.requests[r.ID] = r
		}
		for _, g := range p.Grants {
			s.grants[g.IP] = g
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	return s, s.syncLocked()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // no 0/O, 1/I/L

func newCode() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b[:3]) + "-" + string(b[3:])
}

func recent(ts []time.Time, now time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < time.Hour {
			out = append(out, t)
		}
	}
	return out
}

// Request records an access request from ip. If one is already pending for
// ip it is returned instead (fresh is false), so reloading never re-notifies.
func (s *Store) Request(ip netip.Addr, host, agent string) (r *Request, fresh bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked()
	if g, ok := s.grants[ip]; ok && g.Until.After(now) {
		return s.requests[g.Request], false, ErrAllowed
	}
	if p := s.pendingFor(ip); p != nil {
		return p, false, nil
	}
	s.hits[ip] = recent(s.hits[ip], now)
	s.global = recent(s.global, now)
	if len(s.hits[ip]) >= s.opt.PerIPHour {
		return nil, false, ErrRateIP
	}
	if len(s.global) >= s.opt.GlobalHour {
		return nil, false, ErrRateGlobal
	}
	if len(s.hits) > 50_000 { // bound memory under a flood of new addresses
		s.hits = map[netip.Addr][]time.Time{}
	}
	s.hits[ip] = append(s.hits[ip], now)
	s.global = append(s.global, now)
	if len(agent) > 200 {
		agent = agent[:200]
	}
	r = &Request{ID: randHex(16), IP: ip, Host: host, Agent: agent, Code: newCode(), Created: now, Status: Pending}
	s.requests[r.ID] = r
	return r, true, s.saveLocked()
}

func (s *Store) pendingFor(ip netip.Addr) *Request {
	for _, r := range s.requests {
		if r.IP == ip && r.Status == Pending {
			return r
		}
	}
	return nil
}

// Latest returns the newest request from ip and its grant expiry, if any.
func (s *Store) Latest(ip netip.Addr) (*Request, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	var latest *Request
	for _, r := range s.requests {
		if r.IP == ip && (latest == nil || r.Created.After(latest.Created)) {
			latest = r
		}
	}
	var until time.Time
	if g, ok := s.grants[ip]; ok {
		until = g.Until
	}
	if latest != nil {
		c := *latest
		latest = &c
	}
	return latest, until
}

func (s *Store) SetMessage(id string, msg int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.requests[id]; ok {
		r.Message = msg
		_ = s.saveLocked()
	}
}

// Decide approves (d > 0) or denies (d == 0) a pending request.
func (s *Store) Decide(id string, d time.Duration, by int64) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked()
	r, ok := s.requests[id]
	if !ok || r.Status != Pending {
		if ok {
			c := *r
			return &c, ErrNotPending
		}
		return nil, ErrNotPending
	}
	if d > 0 {
		allowed := false
		for _, x := range s.opt.Durations {
			allowed = allowed || x == d
		}
		if !allowed {
			return nil, ErrBadDuration
		}
		if _, exists := s.grants[r.IP]; !exists && len(s.grants) >= s.opt.MaxActive {
			return nil, ErrFull
		}
		r.Status, r.Until = Approved, now.Add(d)
		s.grants[r.IP] = &Grant{IP: r.IP, Until: r.Until, Request: r.ID}
	} else {
		r.Status = Denied
	}
	r.Decided, r.By = now, by
	if err := s.syncLocked(); err != nil {
		return nil, err
	}
	c := *r
	return &c, s.saveLocked()
}

// Sweep expires old requests and grants and rewrites the allowlist if needed.
// It returns grants that ended in this sweep.
func (s *Store) Sweep() ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ended := s.sweepLocked()
	if len(ended) == 0 {
		return nil, nil
	}
	if err := s.syncLocked(); err != nil {
		return ended, err
	}
	return ended, s.saveLocked()
}

func (s *Store) sweepLocked() []Grant {
	now := s.now()
	var ended []Grant
	for ip, g := range s.grants {
		if !g.Until.After(now) {
			ended = append(ended, *g)
			delete(s.grants, ip)
		}
	}
	for id, r := range s.requests {
		if r.Status == Pending && now.Sub(r.Created) > s.opt.PendingTTL {
			r.Status, r.Decided = Expired, now
		}
		if r.Status != Pending && now.Sub(r.Created) > 48*time.Hour {
			if _, live := s.grants[r.IP]; !live || s.grants[r.IP].Request != id {
				delete(s.requests, id)
			}
		}
	}
	return ended
}

// Active lists current grants, soonest expiry first.
func (s *Store) Active() []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Grant
	for _, g := range s.grants {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

func (s *Store) saveLocked() error {
	p := persisted{}
	for _, r := range s.requests {
		p.Requests = append(p.Requests, r)
	}
	for _, g := range s.grants {
		p.Grants = append(p.Grants, g)
	}
	b, err := json.MarshalIndent(p, "", " ")
	if err != nil {
		return err
	}
	return atomicWrite(s.st, "state.json", b, 0o600)
}

// Render returns the traefik dynamic configuration for the current grants.
func (s *Store) render() []byte {
	var b strings.Builder
	b.WriteString("# Managed by traefik-gatekeeper: approved addresses are added and removed here.\n")
	b.WriteString("# Changes made by hand are overwritten.\n")
	fmt.Fprintf(&b, "http:\n  middlewares:\n    %s:\n      ipAllowList:\n", s.opt.Middleware)
	if s.opt.Depth > 0 {
		fmt.Fprintf(&b, "        ipStrategy:\n          depth: %d\n", s.opt.Depth)
	}
	b.WriteString("        sourceRange:\n")
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			fmt.Fprintf(&b, "          - %q\n", p)
		}
	}
	for _, p := range s.opt.Base {
		add(p.String())
	}
	var ips []netip.Addr
	for ip := range s.grants {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	for _, ip := range ips {
		add(netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	return []byte(b.String())
}

// syncLocked writes the allowlist file when its content would change.
func (s *Store) syncLocked() error {
	want := s.render()
	if cur, err := s.allow.ReadFile(s.opt.AllowlistFile); err == nil && string(cur) == string(want) {
		return nil
	}
	if s.opt.InPlace {
		return writeInPlace(s.allow, s.opt.AllowlistFile, want)
	}
	return atomicWrite(s.allow, s.opt.AllowlistFile, want, 0o644)
}

// writeInPlace replaces an existing file's content with a single write.
func writeInPlace(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	return errors.Join(werr, serr, f.Close())
}

// atomicWrite writes a temporary file next to name and renames it over name,
// so traefik never reads a partly written file.
func atomicWrite(root *os.Root, name string, data []byte, mode os.FileMode) error {
	tmp := "." + name + "." + randHex(6) + ".tmp"
	if err := root.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}

// Event is one line of audit.log.
type Event struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"` // request, approve, deny, expire, rejected-press, error
	IP      string    `json:"ip,omitempty"`
	Host    string    `json:"host,omitempty"`
	Request string    `json:"request,omitempty"`
	Until   time.Time `json:"until,omitzero"`
	By      string    `json:"by,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

var auditMu sync.Mutex

// Audit appends an event to audit.log in the state directory.
func (s *Store) Audit(e Event) {
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := s.st.OpenFile("audit.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
}
