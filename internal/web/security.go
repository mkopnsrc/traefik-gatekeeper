// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxBody = 16 << 10 // the only form has two short fields

// clientIP returns the caller's address. X-Forwarded-For is used only when the
// direct peer is a trusted proxy, and then the rightmost untrusted address in
// it wins, so a client can't choose its own address by sending the header.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !isTrusted(peer) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer // malformed header: don't guess
		}
		a = a.Unmap()
		if !isTrusted(a) {
			return a
		}
	}
	return peer
}

// limiter is a token bucket per client address.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perSecond float64, burst int) *limiter {
	l := &limiter{rate: perSecond, burst: float64(burst), buckets: map[netip.Addr]*bucket{}}
	go func() {
		for range time.Tick(time.Minute) {
			l.mu.Lock()
			for k, b := range l.buckets {
				if time.Since(b.last) > 10*time.Minute {
					delete(l.buckets, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

func (l *limiter) allow(a netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[a]
	if !ok {
		if len(l.buckets) > 100_000 { // memory cap under a flood of new addresses
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[a] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type ctxKey int

const keyIP ctxKey = iota

func (s *Server) ip(r *http.Request) netip.Addr {
	a, _ := r.Context().Value(keyIP).(netip.Addr)
	return a
}

// protect wraps every request: panic recovery, logging, limits, Host check and
// security headers.
func (s *Server) protect(next http.Handler) http.Handler {
	inflight := make(chan struct{}, s.cfg.MaxInFlight)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ip := clientIP(r, s.cfg.TrustedProxies)
		rw := &statusWriter{ResponseWriter: w, status: 200}
		defer func() {
			if v := recover(); v != nil {
				slog.Error("panic", "err", v, "path", r.URL.Path)
				http.Error(rw, "internal error", http.StatusInternalServerError)
			}
			slog.Info("request", "ip", ip.String(), "method", r.Method, "path", r.URL.Path,
				"status", rw.status, "ms", time.Since(start).Milliseconds())
		}()
		h := rw.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		if r.URL.Path == "/healthz" { // container health check, any Host
			next.ServeHTTP(rw, r)
			return
		}
		if !s.hostAllowed(r.Host) {
			http.Error(rw, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		if !s.limit.allow(ip) {
			rw.Header().Set("Retry-After", "5")
			http.Error(rw, "too many requests", http.StatusTooManyRequests)
			return
		}
		select {
		case inflight <- struct{}{}:
			defer func() { <-inflight }()
		default:
			http.Error(rw, "busy", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(rw, r.Body, maxBody)
		next.ServeHTTP(rw, r.WithContext(withIP(r, ip)))
	})
}

func (s *Server) hostAllowed(host string) bool { return s.cfg.HostAllowed(host) }

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// ---- CSRF --------------------------------------------------------------------
// Double-submit token: a random value in a SameSite=Strict, HttpOnly cookie that
// every form repeats in a hidden field. On top of that the request must come
// from this site (Origin, or Sec-Fetch-Site), so a link or a form on another
// site can never change anything.

func (s *Server) csrfCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-gk-csrf"
	}
	return "gk-csrf"
}

// csrfToken returns the client's token, setting the cookie on first use.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(s.csrfCookieName()); err == nil && len(c.Value) == 43 {
		return c.Value
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name: s.csrfCookieName(), Value: tok, Path: "/",
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: 12 * 3600,
	})
	return tok
}

func (s *Server) sameOrigin(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		// Browsers send Origin on every POST; fall back to Sec-Fetch-Site only.
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host) && s.hostAllowed(u.Host)
}

// guard protects a state-changing handler: POST only, same origin and a
// valid CSRF token. Request limits per address are kept by the state store.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.sameOrigin(r) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		c, err := r.Cookie(s.csrfCookieName())
		if err != nil || len(c.Value) != 43 ||
			subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) != 1 {
			http.Error(w, "invalid or missing CSRF token: reload the page", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
