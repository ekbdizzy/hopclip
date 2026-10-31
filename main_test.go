package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSealOpen(t *testing.T) {
	id, key := keys(make([]byte, 32))
	otherID, otherKey := keys(bytes.Repeat([]byte{1}, 32))
	now := time.Now()
	blob := seal(key, id, now, []byte("hello"))

	if got, err := open(key, id, now, blob); err != nil || string(got) != "hello" {
		t.Fatalf("roundtrip: %q, %v", got, err)
	}
	tampered := bytes.Clone(blob)
	tampered[len(tampered)-1] ^= 1
	rejected := func(_ []byte, err error) bool { return err != nil }
	if !rejected(open(key, id, now, tampered)) {
		t.Error("tampered blob accepted")
	}
	if !rejected(open(key, otherID, now, blob)) {
		t.Error("blob moved to another slot accepted")
	}
	if !rejected(open(otherKey, id, now, blob)) {
		t.Error("wrong secret accepted")
	}
	if !rejected(open(key, id, now.Add(ttl+skew+time.Second), blob)) {
		t.Error("replayed blob accepted")
	}
	if !rejected(open(key, id, now, blob[:5])) {
		t.Error("truncated blob accepted")
	}
}

func TestCheckText(t *testing.T) {
	for in, want := range map[string]string{ // "" = ok
		"ls -la\r\n\techo ok\n":          "",
		"echo hi\x1b]52;c;ZXZpbA==\x07":  "err", // escape sequence that sets the clipboard
		"echo safe\rrm -rf ~":            "err", // \r hides the first part on screen
		"\xff\xfe":                       "err", // binary
		"access = \u202euser\u2066 only": "warn",
	} {
		warn, err := checkText([]byte(in))
		got := ""
		if err != nil {
			got = "err"
		} else if warn != "" {
			got = "warn"
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestRelay(t *testing.T) {
	s := newStore()
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	id := strings.Repeat("ab", 16)
	do := func(method, path string, body []byte) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if r := do("PUT", "/"+id, []byte("blob")); r.StatusCode != 204 {
		t.Fatalf("put: %s", r.Status)
	}
	r := do("GET", "/"+id, nil)
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || string(body) != "blob" || r.Header.Get("Expires") == "" {
		t.Fatalf("get: %s %q", r.Status, body)
	}
	if r := do("PUT", "/NOT-AN-ID", []byte("x")); r.StatusCode != 400 {
		t.Errorf("bad id: %s", r.Status)
	}
	if r := do("PUT", "/"+id, make([]byte, maxSize+overhead+1)); r.StatusCode != 413 {
		t.Errorf("too big: %s", r.Status)
	}
	s.mu.Lock()
	s.used = maxStore
	s.mu.Unlock()
	if r := do("PUT", "/"+strings.Repeat("cd", 16), []byte("x")); r.StatusCode != 503 {
		t.Errorf("relay full: %s", r.Status)
	}
	s.mu.Lock()
	s.m[id] = entry{[]byte("old"), time.Now().Add(-time.Second)}
	s.writes["127.0.0.1"] = writesPerMin
	s.mu.Unlock()
	if r := do("GET", "/"+id, nil); r.StatusCode != 404 {
		t.Errorf("expired: %s", r.Status)
	}
	if r := do("PUT", "/"+id, []byte("x")); r.StatusCode != 429 {
		t.Errorf("rate limit: %s", r.Status)
	}
}
