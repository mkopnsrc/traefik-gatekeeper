// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

// Package telegram sends access requests to a chat with approve/deny buttons
// and receives the button presses by long polling (outbound only: no webhook,
// no public approve URL).
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	base      string // https://api.telegram.org/bot<token>; never logged
	chat      int64
	approvers []int64
	hc        *http.Client
}

// New reads the bot token from tokenFile.
func New(api, tokenFile string, chat int64, approvers []int64) (*Client, error) {
	b, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("telegram token file: %w", errors.Unwrap(err))
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" || strings.ContainsAny(tok, "/ ?#") {
		return nil, errors.New("telegram token file: empty or malformed")
	}
	return &Client{base: api + "/bot" + tok, chat: chat, approvers: approvers,
		hc: &http.Client{Timeout: 70 * time.Second}}, nil
}

// call posts a method and decodes its result. Errors never contain the URL
// (it holds the token).
func (c *Client) call(ctx context.Context, method string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/"+method, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram %s: bad request", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return fmt.Errorf("telegram %s: HTTP %d", method, resp.StatusCode)
	}
	if !r.OK {
		return fmt.Errorf("telegram %s: %s", method, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// Request is what the approver sees.
type Request struct {
	ID, Host, IP, Code, Agent string
	Durations                 []time.Duration
}

type button struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

func esc(s string) string { return html.EscapeString(s) }

func label(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return strconv.Itoa(int(d/(24*time.Hour))) + " d"
	case d%time.Hour == 0:
		return strconv.Itoa(int(d/time.Hour)) + " h"
	default:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	}
}

// Send posts a request with one button per duration plus Deny; it returns
// the message ID.
func (c *Client) Send(ctx context.Context, r Request) (int, error) {
	text := fmt.Sprintf("<b>Access request</b>\nHost: <code>%s</code>\nAddress: <code>%s</code>\nCode: <b>%s</b>\nBrowser: %s\n\nThe requester sees the same code. Approve only if they match.",
		esc(r.Host), esc(r.IP), esc(r.Code), esc(r.Agent))
	var row []button
	for _, d := range r.Durations {
		row = append(row, button{"Allow " + label(d), "a|" + r.ID + "|" + strconv.Itoa(int(d/time.Minute))})
	}
	row = append(row, button{"Deny", "d|" + r.ID})
	var msg struct {
		ID int `json:"message_id"`
	}
	err := c.call(ctx, "sendMessage", map[string]any{
		"chat_id": c.chat, "text": text, "parse_mode": "HTML",
		"link_preview_options": map[string]bool{"is_disabled": true},
		"reply_markup":         map[string]any{"inline_keyboard": [][]button{row}},
	}, &msg)
	return msg.ID, err
}

// Close removes the buttons of a request message and replies with the result
// (plain text, escaped here).
func (c *Client) Close(ctx context.Context, msgID int, result string) error {
	if msgID == 0 {
		return c.Notify(ctx, esc(result))
	}
	err := c.call(ctx, "editMessageReplyMarkup", map[string]any{
		"chat_id": c.chat, "message_id": msgID, "reply_markup": map[string]any{"inline_keyboard": [][]button{}},
	}, nil)
	return errors.Join(err, c.call(ctx, "sendMessage", map[string]any{
		"chat_id": c.chat, "text": esc(result),
		"reply_parameters": map[string]any{"message_id": msgID, "allow_sending_without_reply": true},
	}, nil))
}

// Notify sends a plain message (results, expiries).
func (c *Client) Notify(ctx context.Context, text string) error {
	return c.call(ctx, "sendMessage", map[string]any{
		"chat_id": c.chat, "text": text, "parse_mode": "HTML",
		"link_preview_options": map[string]bool{"is_disabled": true},
	}, nil)
}

// Decision is a validated button press.
type Decision struct {
	RequestID string
	Approve   bool
	Duration  time.Duration
	By        int64
	ByName    string
	Message   int
	answer    string // callback query ID
}

type update struct {
	ID       int `json:"update_id"`
	Callback *struct {
		ID   string `json:"id"`
		From struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			First    string `json:"first_name"`
		} `json:"from"`
		Message *struct {
			ID   int `json:"message_id"`
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
		Data string `json:"data"`
	} `json:"callback_query"`
}

// parse checks a button press: right chat, an approver, well-formed data.
func (c *Client) parse(u update) (Decision, error) {
	cb := u.Callback
	if cb == nil || cb.Message == nil {
		return Decision{}, errors.New("not a button press")
	}
	d := Decision{By: cb.From.ID, ByName: cb.From.Username, Message: cb.Message.ID, answer: cb.ID}
	if d.ByName == "" {
		d.ByName = cb.From.First
	}
	if cb.Message.Chat.ID != c.chat {
		return d, errors.New("button press from another chat")
	}
	if !slices.Contains(c.approvers, cb.From.ID) {
		return d, errors.New("not an approver")
	}
	parts := strings.Split(cb.Data, "|")
	switch {
	case len(parts) == 3 && parts[0] == "a":
		m, err := strconv.Atoi(parts[2])
		if err != nil || m <= 0 {
			return d, errors.New("bad duration")
		}
		d.Approve, d.Duration = true, time.Duration(m)*time.Minute
	case len(parts) == 2 && parts[0] == "d":
	default:
		return d, errors.New("bad button data")
	}
	d.RequestID = parts[1]
	if len(d.RequestID) != 32 {
		return d, errors.New("bad request id")
	}
	return d, nil
}

// Answer acknowledges a button press with a short toast.
func (c *Client) Answer(ctx context.Context, d Decision, text string) {
	_ = c.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": d.answer, "text": text}, nil)
}

// Poll receives button presses until ctx ends. Presses that fail validation
// are answered with "not allowed" and passed to onRejected for the audit log.
func (c *Client) Poll(ctx context.Context, onDecision func(Decision), onRejected func(Decision, error), onError func(error)) {
	offset := 0
	for ctx.Err() == nil {
		var ups []update
		err := c.call(ctx, "getUpdates", map[string]any{
			"offset": offset, "timeout": 50, "allowed_updates": []string{"callback_query"},
		}, &ups)
		if err != nil {
			if ctx.Err() == nil {
				onError(err)
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
				}
			}
			continue
		}
		for _, u := range ups {
			offset = u.ID + 1
			d, err := c.parse(u)
			if err != nil {
				if u.Callback != nil {
					c.Answer(ctx, d, "Not allowed.")
					onRejected(d, err)
				}
				continue
			}
			onDecision(d)
		}
	}
}
