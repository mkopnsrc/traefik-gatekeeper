// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

// Package config reads the gatekeeper's settings from the environment.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen   string
	BasePath string // the path traefik routes here on every protected host, e.g. /routemein

	// Hosts the request page answers for: exact names or ".example.com" suffixes.
	AllowedHosts []string
	// Proxies whose X-Forwarded-For is trusted (traefik's network).
	TrustedProxies []netip.Prefix

	// The traefik dynamic file this app owns, inside AllowlistDir.
	AllowlistDir     string
	AllowlistFile    string
	MiddlewareName   string
	AllowlistInPlace bool           // GK_ALLOWLIST_WRITE=inplace
	IPStrategyDepth  int            // ipStrategy.depth written into the middleware; 0 = none
	BaseRanges       []netip.Prefix // always allowed (written first)

	StateDir string // state.json and audit.log

	Durations  []time.Duration // choices offered to the approver, ascending
	PendingTTL time.Duration   // how long a request waits for a decision
	MaxActive  int             // approved addresses at once
	PerIPHour  int             // requests per address per hour
	GlobalHour int             // requests per hour in total (protects the approver's phone)

	TelegramTokenFile string
	TelegramChatID    int64
	TelegramApprovers []int64 // user IDs allowed to press the buttons
	TelegramAPI       string  // base URL; changed only in tests

	CookieSecure bool
	RateLimit    float64
	RateBurst    int
	MaxInFlight  int
	TZ           *time.Location
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func list(k, def string) []string {
	var out []string
	for _, s := range strings.Split(env(k, def), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func prefixes(k, def string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range list(k, def) {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			a, err2 := netip.ParseAddr(p)
			if err2 != nil {
				return nil, fmt.Errorf("%s: %q is not an address or CIDR", k, p)
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

func ints(k string) ([]int64, error) {
	var out []int64
	for _, s := range list(k, "") {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a number", k, s)
		}
		out = append(out, n)
	}
	return out, nil
}

// Load reads the settings; invalid values stop the app instead of being ignored.
func Load() (*Config, error) {
	c := &Config{
		Listen:            env("GK_LISTEN", ":5000"),
		BasePath:          strings.TrimRight(env("GK_BASE_PATH", "/routemein"), "/"),
		AllowedHosts:      list("GK_ALLOWED_HOSTS", ""),
		AllowlistDir:      env("GK_ALLOWLIST_DIR", "/allowlist"),
		AllowlistFile:     env("GK_ALLOWLIST_FILE", "dynamic-allowlist.yml"),
		MiddlewareName:    env("GK_MIDDLEWARE", "dynamic-ipwhitelist"),
		StateDir:          env("GK_STATE_DIR", "/state"),
		TelegramTokenFile: env("GK_TELEGRAM_TOKEN_FILE", "/run/secrets/telegram_token"),
		TelegramAPI:       strings.TrimRight(env("GK_TELEGRAM_API", "https://api.telegram.org"), "/"),
	}
	var err error
	if !strings.HasPrefix(c.BasePath, "/") || strings.ContainsAny(c.BasePath, "?#") {
		return nil, errors.New("GK_BASE_PATH must be a path like /routemein")
	}
	if len(c.AllowedHosts) == 0 {
		return nil, errors.New("GK_ALLOWED_HOSTS is required (e.g. .example.com)")
	}
	for i, h := range c.AllowedHosts {
		c.AllowedHosts[i] = strings.ToLower(h)
	}
	if c.TrustedProxies, err = prefixes("GK_TRUSTED_PROXIES", ""); err != nil {
		return nil, err
	}
	if c.BaseRanges, err = prefixes("GK_BASE_RANGES", "127.0.0.1/32"); err != nil {
		return nil, err
	}
	switch env("GK_ALLOWLIST_WRITE", "rename") {
	case "rename":
	case "inplace":
		c.AllowlistInPlace = true
	default:
		return nil, errors.New("GK_ALLOWLIST_WRITE: rename or inplace")
	}
	if c.IPStrategyDepth, err = strconv.Atoi(env("GK_IPSTRATEGY_DEPTH", "0")); err != nil || c.IPStrategyDepth < 0 {
		return nil, errors.New("GK_IPSTRATEGY_DEPTH: want a number >= 0")
	}
	for _, d := range list("GK_DURATIONS", "30m,2h,8h") {
		v, err := time.ParseDuration(d)
		if err != nil || v < time.Minute || v > 7*24*time.Hour {
			return nil, fmt.Errorf("GK_DURATIONS: %q must be between 1m and 168h", d)
		}
		c.Durations = append(c.Durations, v)
	}
	slices.Sort(c.Durations)
	c.Durations = slices.Compact(c.Durations)
	if len(c.Durations) > 4 {
		return nil, errors.New("GK_DURATIONS: at most 4 choices (one button row)")
	}
	if c.PendingTTL, err = time.ParseDuration(env("GK_PENDING_TTL", "10m")); err != nil || c.PendingTTL < time.Minute {
		return nil, errors.New("GK_PENDING_TTL: want a duration >= 1m")
	}
	num := func(k, def string, min int) (int, error) {
		n, err := strconv.Atoi(env(k, def))
		if err != nil || n < min {
			return 0, fmt.Errorf("%s: want a number >= %d", k, min)
		}
		return n, nil
	}
	if c.MaxActive, err = num("GK_MAX_ACTIVE", "50", 1); err != nil {
		return nil, err
	}
	if c.PerIPHour, err = num("GK_REQUESTS_PER_IP_HOUR", "3", 1); err != nil {
		return nil, err
	}
	if c.GlobalHour, err = num("GK_REQUESTS_PER_HOUR", "30", 1); err != nil {
		return nil, err
	}
	if c.RateBurst, err = num("GK_RATE_BURST", "30", 1); err != nil {
		return nil, err
	}
	if c.MaxInFlight, err = num("GK_MAX_IN_FLIGHT", "64", 1); err != nil {
		return nil, err
	}
	if c.RateLimit, err = strconv.ParseFloat(env("GK_RATE_LIMIT", "5"), 64); err != nil || c.RateLimit <= 0 {
		return nil, errors.New("GK_RATE_LIMIT: want requests per second > 0")
	}
	if c.TelegramChatID, err = strconv.ParseInt(env("GK_TELEGRAM_CHAT_ID", ""), 10, 64); err != nil {
		return nil, errors.New("GK_TELEGRAM_CHAT_ID is required (the chat that receives requests)")
	}
	if c.TelegramApprovers, err = ints("GK_TELEGRAM_APPROVERS"); err != nil {
		return nil, err
	}
	if len(c.TelegramApprovers) == 0 {
		return nil, errors.New("GK_TELEGRAM_APPROVERS is required (Telegram user IDs allowed to approve)")
	}
	if c.CookieSecure, err = strconv.ParseBool(env("GK_COOKIE_SECURE", "true")); err != nil {
		return nil, fmt.Errorf("GK_COOKIE_SECURE: %w", err)
	}
	if c.TZ, err = time.LoadLocation(env("TZ", "UTC")); err != nil {
		return nil, fmt.Errorf("TZ: %w", err)
	}
	return c, nil
}

// HostAllowed matches a Host header against AllowedHosts.
func (c *Config) HostAllowed(host string) bool {
	host = strings.ToLower(host)
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	for _, h := range c.AllowedHosts {
		if strings.HasPrefix(h, ".") {
			if strings.HasSuffix(host, h) && len(host) > len(h) {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}
