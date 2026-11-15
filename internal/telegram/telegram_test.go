// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

package telegram

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const token = "123456:SECRET-token"

type fake struct {
	mu    sync.Mutex
	calls map[string][]map[string]any
	ups   []map[string]any
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/bot"+token+"/") {
		http.Error(w, `{"ok":false,"description":"Unauthorized"}`, 401)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, "/bot"+token+"/")
	var in map[string]any
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &in)
	f.mu.Lock()
	f.calls[method] = append(f.calls[method], in)
	var result any = true
	switch method {
	case "sendMessage":
		result = map[string]any{"message_id": 42}
	case "getUpdates":
		result = f.ups
		f.ups = nil
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func client(t *testing.T, api string) *Client {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(p, []byte(token+"\n"), 0o600)
	c, err := New(api, p, -100, []int64{7})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func press(id int, chat, from int64, data string) map[string]any {
	return map[string]any{"update_id": id, "callback_query": map[string]any{
		"id": "cb", "data": data, "from": map[string]any{"id": from, "username": "u"},
		"message": map[string]any{"message_id": 42, "chat": map[string]any{"id": chat}},
	}}
}

func TestSendEscapesAndDisablesPreviews(t *testing.T) {
	f := &fake{calls: map[string][]map[string]any{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := client(t, srv.URL)
	id, err := c.Send(context.Background(), Request{ID: strings.Repeat("a", 32), Host: "<b>h</b>", IP: "198.51.100.7",
		Code: "ABC-DEF", Agent: "<script>", Durations: []time.Duration{30 * time.Minute, 2 * time.Hour}})
	if err != nil || id != 42 {
		t.Fatalf("send: %v %d", err, id)
	}
	m := f.calls["sendMessage"][0]
	text := m["text"].(string)
	if strings.Contains(text, "<script>") || !strings.Contains(text, "&lt;b&gt;h&lt;/b&gt;") {
		t.Errorf("not escaped: %s", text)
	}
	if m["link_preview_options"].(map[string]any)["is_disabled"] != true {
		t.Error("link previews not disabled")
	}
	kb := m["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	if len(kb) != 3 || kb[0].(map[string]any)["callback_data"] != "a|"+strings.Repeat("a", 32)+"|30" {
		t.Errorf("buttons: %v", kb)
	}
}

func TestPollValidatesPresses(t *testing.T) {
	f := &fake{calls: map[string][]map[string]any{}}
	id := strings.Repeat("b", 32)
	f.ups = []map[string]any{
		press(1, -100, 7, "a|"+id+"|120"), // approver, right chat
		press(2, -100, 8, "a|"+id+"|120"), // not an approver
		press(3, -999, 7, "a|"+id+"|120"), // other chat
		press(4, -100, 7, "a|"+id+"|x"),   // malformed
		press(5, -100, 7, "d|"+id),        // deny
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := client(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	var got []Decision
	var rejected int
	go c.Poll(ctx, func(d Decision) {
		got = append(got, d)
		if len(got) == 2 {
			cancel()
		}
	}, func(Decision, error) { rejected++ }, func(error) {})
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond)
	if len(got) != 2 || !got[0].Approve || got[0].Duration != 2*time.Hour || got[1].Approve {
		t.Errorf("decisions: %+v", got)
	}
	if rejected != 3 {
		t.Errorf("rejected %d presses, want 3", rejected)
	}
}

func TestErrorsNeverContainToken(t *testing.T) {
	c := client(t, "http://127.0.0.1:1") // nothing listens
	_, err := c.Send(context.Background(), Request{ID: strings.Repeat("c", 32)})
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), token) {
		t.Errorf("error leaks the token: %v", err)
	}
}
