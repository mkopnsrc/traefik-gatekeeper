// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

// Package web serves the access request page and handles approvals.
package web

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/mkopnsrc/traefik-gatekeeper/internal/config"
	"github.com/mkopnsrc/traefik-gatekeeper/internal/state"
	"github.com/mkopnsrc/traefik-gatekeeper/internal/telegram"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Approver delivers requests to whoever decides (Telegram).
type Approver interface {
	Send(ctx context.Context, r telegram.Request) (int, error)
	Close(ctx context.Context, msgID int, result string) error
	Answer(ctx context.Context, d telegram.Decision, text string)
}

type Server struct {
	cfg   *config.Config
	store *state.Store
	appr  Approver
	tpl   *template.Template
	limit *limiter
}

func New(cfg *config.Config, st *state.Store, appr Approver) (*Server, error) {
	funcs := template.FuncMap{
		"localtime": func(t time.Time) string { return t.In(cfg.TZ).Format("Jan 2, 15:04 MST") },
		"left": func(t time.Time) string {
			d := time.Until(t).Round(time.Minute)
			switch {
			case d < time.Minute:
				return "less than a minute"
			case d < time.Hour:
				return fmt.Sprintf("%d min", int(d/time.Minute))
			case d%time.Hour == 0:
				return fmt.Sprintf("%d h", int(d/time.Hour))
			default:
				return fmt.Sprintf("%d h %d min", int(d/time.Hour), int(d%time.Hour/time.Minute))
			}
		},
	}
	tpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, store: st, appr: appr, tpl: tpl, limit: newLimiter(cfg.RateLimit, cfg.RateBurst)}, nil
}

func (s *Server) Handler() http.Handler {
	b := s.cfg.BasePath
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET "+b+"/static/", http.StripPrefix(b+"/static/", cacheStatic(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET "+b, s.page)
	mux.HandleFunc("GET "+b+"/status", s.status)
	mux.HandleFunc("POST "+b, s.guard(s.request))
	return s.protect(mux)
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

func withIP(r *http.Request, ip netip.Addr) context.Context {
	return context.WithValue(r.Context(), keyIP, ip)
}

type view struct {
	Base    string
	CSRF    string
	IP      string
	Host    string
	Req     *state.Request
	Until   time.Time
	Allowed bool
	Error   string
	Partial bool
}

func (s *Server) view(w http.ResponseWriter, r *http.Request) view {
	ip := s.ip(r)
	v := view{Base: s.cfg.BasePath, IP: ip.String(), Host: r.Host}
	v.Req, v.Until = s.store.Latest(ip)
	v.Allowed = v.Until.After(time.Now())
	if w != nil {
		v.CSRF = s.csrfToken(w, r)
	}
	return v
}

func (s *Server) render(w http.ResponseWriter, name string, code int, v view) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, v); err != nil {
		slog.Error("template", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = buf.WriteTo(w)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	v := s.view(w, r)
	switch r.URL.Query().Get("e") { // fixed messages only, never reflected text
	case "rate":
		v.Error = "Too many requests. Try again later."
	case "notify":
		v.Error = "The request could not be delivered to the approver. Try again later."
	}
	s.render(w, "page.html", 200, v)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	v := s.view(nil, r)
	v.Partial = true
	s.render(w, "status", 200, v)
}

func (s *Server) request(w http.ResponseWriter, r *http.Request) {
	ip := s.ip(r)
	back := s.cfg.BasePath
	req, fresh, err := s.store.Request(ip, r.Host, r.UserAgent())
	switch {
	case errors.Is(err, state.ErrAllowed):
	case errors.Is(err, state.ErrRateIP), errors.Is(err, state.ErrRateGlobal):
		s.store.Audit(state.Event{Action: "rate-limited", IP: ip.String(), Host: r.Host, Detail: err.Error()})
		back += "?e=rate"
	case err != nil:
		slog.Error("request", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	case fresh:
		s.store.Audit(state.Event{Action: "request", IP: ip.String(), Host: r.Host, Request: req.ID})
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		msg, err := s.appr.Send(ctx, telegram.Request{ID: req.ID, Host: req.Host, IP: ip.String(),
			Code: req.Code, Agent: req.Agent, Durations: s.cfg.Durations})
		if err != nil {
			slog.Error("notify approver", "err", err)
			s.store.Audit(state.Event{Action: "error", Request: req.ID, Detail: err.Error()})
			back += "?e=notify"
		} else {
			s.store.SetMessage(req.ID, msg)
		}
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// Decide handles a validated button press from the approver.
func (s *Server) Decide(ctx context.Context, d telegram.Decision) {
	dur := time.Duration(0)
	if d.Approve {
		dur = d.Duration
	}
	r, err := s.store.Decide(d.RequestID, dur, d.By)
	who := fmt.Sprintf("%s (%d)", d.ByName, d.By)
	switch {
	case errors.Is(err, state.ErrNotPending):
		s.appr.Answer(ctx, d, "This request is no longer waiting (decided or expired).")
		if r != nil {
			_ = s.appr.Close(ctx, d.Message, fmt.Sprintf("Request %s was already %s.", r.Code, r.Status))
		}
		return
	case err != nil:
		s.appr.Answer(ctx, d, err.Error())
		s.store.Audit(state.Event{Action: "error", Request: d.RequestID, By: who, Detail: err.Error()})
		return
	}
	if r.Status == state.Approved {
		s.appr.Answer(ctx, d, "Allowed until "+r.Until.In(s.cfg.TZ).Format("15:04"))
		_ = s.appr.Close(ctx, d.Message, fmt.Sprintf("Allowed %s (%s, code %s) until %s, by %s.",
			r.IP, r.Host, r.Code, r.Until.In(s.cfg.TZ).Format("2006-01-02 15:04 MST"), d.ByName))
		s.store.Audit(state.Event{Action: "approve", IP: r.IP.String(), Host: r.Host, Request: r.ID, Until: r.Until, By: who})
	} else {
		s.appr.Answer(ctx, d, "Denied")
		_ = s.appr.Close(ctx, d.Message, fmt.Sprintf("Denied %s (%s, code %s), by %s.", r.IP, r.Host, r.Code, d.ByName))
		s.store.Audit(state.Event{Action: "deny", IP: r.IP.String(), Host: r.Host, Request: r.ID, By: who})
	}
}

// Rejected logs a button press that failed validation (wrong person or chat).
func (s *Server) Rejected(d telegram.Decision, err error) {
	s.store.Audit(state.Event{Action: "rejected-press", By: fmt.Sprintf("%s (%d)", d.ByName, d.By), Detail: err.Error()})
}

// Sweep removes expired grants every interval until ctx ends.
func (s *Server) Sweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ended, err := s.store.Sweep()
			if err != nil {
				slog.Error("sweep", "err", err)
			}
			for _, g := range ended {
				s.store.Audit(state.Event{Action: "expire", IP: g.IP.String(), Request: g.Request, Until: g.Until})
			}
		}
	}
}
