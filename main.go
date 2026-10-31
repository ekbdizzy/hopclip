// hop: copy on one machine, paste on another. End-to-end encrypted, gone after 5 minutes.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	ttl      = 5 * time.Minute
	skew     = time.Minute // allowed clock difference between machines
	maxSize  = 1 << 20     // 1 MB of clipboard data
	overhead = 8 + 12 + 16 // timestamp + GCM nonce + GCM tag

	maxStore     = 64 << 20 // total blob memory on the relay; the server has 1 GB RAM
	writesPerMin = 30       // copies per client IP
)

const usage = `hop - copy on one machine, paste on another (end-to-end encrypted, gone after 5 min)

  hop init           create a secret on your first machine
  hop join           pair another machine (asks for the secret)
  hop c              copy the clipboard, or piped stdin, to the relay
  hop p              paste to the clipboard, or to stdout when redirected
  hop serve [addr]   run the relay (default localhost:8080)

  HOPCLIP_URL        relay address (default http://localhost:8080)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "c", "copy":
		err = cmdCopy()
	case "p", "paste":
		err = cmdPaste()
	case "init":
		err = cmdInit()
	case "join":
		err = cmdJoin()
	case "serve":
		addr := "localhost:8080"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		err = serve(addr)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}
}

// --- client ---

var client = &http.Client{Timeout: 30 * time.Second}

func relayURL(id string) string {
	base := os.Getenv("HOPCLIP_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	return strings.TrimSuffix(base, "/") + "/" + id
}

func cmdCopy() error {
	id, key, err := loadKeys()
	if err != nil {
		return err
	}
	var data []byte
	if redirected(os.Stdin) {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, maxSize+1))
	} else {
		data, err = clipRead()
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("nothing to copy")
	}
	if len(data) > maxSize {
		return fmt.Errorf("too big, max is %s", size(maxSize))
	}
	req, _ := http.NewRequest(http.MethodPut, relayURL(id), bytes.NewReader(seal(key, id, time.Now(), data)))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w (is `hop serve` running?)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("relay: %s", bytes.TrimSpace(msg))
	}
	fmt.Fprintf(os.Stderr, "✓ %s copied (expires in %v)\n", size(len(data)), ttl)
	return nil
}

func cmdPaste() error {
	id, key, err := loadKeys()
	if err != nil {
		return err
	}
	resp, err := client.Get(relayURL(id))
	if err != nil {
		return fmt.Errorf("%w (is `hop serve` running?)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("nothing to paste (expired, or not copied yet)")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relay: %s", resp.Status)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+overhead+1))
	if err != nil {
		return err
	}
	data, err := open(key, id, time.Now(), blob)
	if err != nil {
		return err
	}
	if redirected(os.Stdout) {
		_, err = os.Stdout.Write(data)
		return err
	}
	warn, err := checkText(data)
	if err != nil {
		return err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, "⚠", warn)
	}
	_, set := clipCmds()
	if set == nil { // no clipboard (SSH, headless): print instead
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := clipWrite(set, data); err != nil {
		return err
	}
	exp, _ := http.ParseTime(resp.Header.Get("Expires"))
	fmt.Fprintf(os.Stderr, "✓ %s → clipboard (expires in %v)\n", size(len(data)), time.Until(exp).Round(time.Second))
	return nil
}

// redirected reports whether f is a pipe or a file. A terminal, /dev/null or
// no stdin at all (launched from a hotkey) means: use the clipboard.
func redirected(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeNamedPipe != 0 || fi.Mode().IsRegular())
}

// checkText guards text headed for a terminal or the clipboard; redirected
// output stays raw bytes. Control characters can hide or run commands in a
// terminal (escape sequences, \r overwriting the line); bidi and invisible
// characters make the text you see differ from the text you run.
func checkText(b []byte) (warn string, err error) {
	if !utf8.Valid(b) {
		return "", errors.New("binary data, use: hop p > file")
	}
	for _, r := range strings.ReplaceAll(string(b), "\r\n", "\n") {
		switch {
		case r == '\n' || r == '\t':
		case unicode.IsControl(r):
			return "", fmt.Errorf("contains control character %U, use: hop p > file", r)
		case unicode.Is(unicode.Bidi_Control, r), r == 0x200B, r == 0x2060, r == 0xFEFF, r >= 0xE0000 && r <= 0xE007F:
			warn = fmt.Sprintf("contains invisible or bidi character %U, check it before running", r)
		}
	}
	return warn, nil
}

func size(n int) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

// --- clipboard ---

// clipCmds returns the commands that read and write the system clipboard,
// or nils when there is none (SSH session, headless server).
func clipCmds() (get, set []string) {
	switch runtime.GOOS {
	case "darwin":
		return []string{"pbpaste"}, []string{"pbcopy"}
	case "windows":
		// ponytail: untested on Windows. Forces UTF-8 both ways; content still only goes through stdin.
		return []string{"powershell", "-NoProfile", "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; [Console]::Out.Write((Get-Clipboard -Raw))"},
			[]string{"powershell", "-NoProfile", "-Command", "[Console]::InputEncoding=[Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())"}
	}
	if os.Getenv("WAYLAND_DISPLAY") != "" && has("wl-copy") {
		return []string{"wl-paste", "--no-newline"}, []string{"wl-copy"}
	}
	if os.Getenv("DISPLAY") != "" {
		if has("xclip") {
			return []string{"xclip", "-selection", "clipboard", "-o"}, []string{"xclip", "-selection", "clipboard"}
		}
		if has("xsel") {
			return []string{"xsel", "--clipboard", "--output"}, []string{"xsel", "--clipboard", "--input"}
		}
	}
	return nil, nil
}

func has(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func clipRead() ([]byte, error) {
	get, _ := clipCmds()
	if get == nil {
		return nil, errors.New("no clipboard here, pipe data in: hop c < file")
	}
	out, err := exec.Command(get[0], get[1:]...).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return nil, fmt.Errorf("clipboard empty or unreadable: %s", bytes.TrimSpace(ee.Stderr))
	}
	return out, err
}

// clipWrite passes data only through stdin, never as an argument, so no shell
// ever interprets it. Stdout stays unset: xclip and wl-copy leave a background
// process owning the clipboard, which would hold a pipe open forever.
func clipWrite(set []string, data []byte) error {
	cmd := exec.Command(set[0], set[1:]...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// --- pairing ---

func cmdInit() error {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	if err := saveSecret(secret); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Paired. On each other machine run `hop join` and enter this secret:")
	fmt.Println(base64.RawURLEncoding.EncodeToString(secret))
	return nil
}

// cmdJoin reads the secret from a hidden prompt, not an argument: arguments
// show up in `ps` and shell history.
func cmdJoin() error {
	var line []byte
	var err error
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "secret: ")
		line, err = term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
	} else {
		line, err = io.ReadAll(io.LimitReader(os.Stdin, 1024))
	}
	if err != nil {
		return err
	}
	secret, err := decodeSecret(string(line))
	if err != nil {
		return err
	}
	if err := saveSecret(secret); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ paired")
	return nil
}

func secretPath() (string, error) {
	dir, err := os.UserConfigDir()
	return filepath.Join(dir, "hopclip", "secret"), err
}

func decodeSecret(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("invalid secret")
	}
	return b, nil
}

// saveSecret never overwrites: losing the secret unpairs this machine.
func saveSecret(secret []byte) error {
	p, err := secretPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("already paired, delete %s to re-pair", p)
	}
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.RawURLEncoding.EncodeToString(secret)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadKeys() (id string, key []byte, err error) {
	p, err := secretPath()
	if err != nil {
		return "", nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, errors.New("not paired: run `hop init` on your first machine, `hop join` on the others")
	}
	if err != nil {
		return "", nil, err
	}
	secret, err := decodeSecret(string(b))
	if err != nil {
		return "", nil, err
	}
	id, key = keys(secret)
	return id, key, nil
}

// --- crypto ---

// keys derives the relay slot id and the encryption key from the shared
// secret. The relay only ever sees the id.
func keys(secret []byte) (id string, key []byte) {
	i := sha256.Sum256(append([]byte("hopclip-id:"), secret...))
	k := sha256.Sum256(append([]byte("hopclip-key:"), secret...))
	return hex.EncodeToString(i[:16]), k[:]
}

func newGCM(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key) // key is always 32 bytes, can't fail
	aead, _ := cipher.NewGCM(block)
	return aead
}

// seal encrypts timestamp+data. The timestamp stops replays of old pastes; the
// slot id is bound as additional data, so a blob moved to another slot won't open.
func seal(key []byte, id string, now time.Time, data []byte) []byte {
	aead := newGCM(key)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	plain := binary.BigEndian.AppendUint64(nil, uint64(now.Unix()))
	return aead.Seal(nonce, nonce, append(plain, data...), []byte(id))
}

var errTampered = errors.New("can't decrypt: wrong secret, or the data was tampered with")

func open(key []byte, id string, now time.Time, blob []byte) ([]byte, error) {
	aead := newGCM(key)
	n := aead.NonceSize()
	if len(blob) < n {
		return nil, errTampered
	}
	plain, err := aead.Open(nil, blob[:n], blob[n:], []byte(id))
	if err != nil || len(plain) < 8 {
		return nil, errTampered
	}
	age := now.Sub(time.Unix(int64(binary.BigEndian.Uint64(plain)), 0))
	if age > ttl+skew || age < -skew {
		return nil, fmt.Errorf("rejected: copied %v ago, max is %v (replayed, or machine clocks differ)", age.Round(time.Second), ttl)
	}
	return plain[8:], nil
}

// --- relay ---

var validID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type entry struct {
	data []byte
	exp  time.Time
}

// store keeps blobs in memory: they live 5 minutes, so losing them on restart is fine.
type store struct {
	mu     sync.Mutex
	m      map[string]entry
	used   int            // bytes held in m
	writes map[string]int // copies per client IP in the current minute
	window time.Time
}

func newStore() *store { return &store{m: map[string]entry{}, writes: map[string]int{}} }

func serve(addr string) error {
	s := newStore()
	log.Printf("hop relay on http://%s", addr)
	srv := &http.Server{Addr: addr, Handler: s.handler(), ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	return srv.ListenAndServe()
}

func (s *store) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /{id}", s.put)
	mux.HandleFunc("GET /{id}", s.get)
	return mux
}

// ponytail: no auth until GitHub login lands; the memory cap and per-IP limit keep strangers from exhausting the server.
func (s *store) put(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	// ponytail: RemoteAddr is the client while nothing proxies the relay; behind Caddy, use X-Forwarded-For.
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.mu.Lock()
	if time.Since(s.window) > time.Minute {
		s.writes, s.window = map[string]int{}, time.Now()
	}
	s.writes[ip]++
	limited := s.writes[ip] > writesPerMin
	s.mu.Unlock()
	if limited {
		http.Error(w, "too many copies, wait a minute", http.StatusTooManyRequests)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSize+overhead))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		http.Error(w, "too big", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	now := time.Now()
	s.mu.Lock()
	// ponytail: full sweep on every PUT is O(entries); move to a ticker goroutine once there are many users.
	for k, e := range s.m {
		if now.After(e.exp) {
			s.used -= len(e.data)
			delete(s.m, k)
		}
	}
	grow := len(data) - len(s.m[id].data)
	full := s.used+grow > maxStore
	if !full {
		s.used += grow
		s.m[id] = entry{data, now.Add(ttl)}
	}
	s.mu.Unlock()
	if full {
		http.Error(w, "relay full, try again in a few minutes", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *store) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	e, ok := s.m[r.PathValue("id")]
	s.mu.Unlock()
	if !ok || time.Now().After(e.exp) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Expires", e.exp.UTC().Format(http.TimeFormat))
	w.Write(e.data)
}
