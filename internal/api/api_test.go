package api

import (
	"agentexec/internal/audit"
	"agentexec/internal/model"
	"agentexec/internal/policy"
	"agentexec/internal/service"
	"agentexec/internal/store"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const aliceToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const bobToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type backend struct{}

func (backend) Run(context.Context, model.Task) (model.Result, error) {
	return model.Result{State: model.Succeeded, ExitCode: 0}, nil
}
func (backend) Close() error { return nil }
func testHandler(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	a, _ := audit.Open(filepath.Join(dir, "audit.jsonl"))
	s, _ := store.New(filepath.Join(dir, "records"), 8)
	m, err := service.New(policy.Default(), backend{}, s, a, service.Options{Workers: 1, MaxInFlight: 2, RetainedJobs: 8})
	if err != nil {
		t.Fatal(err)
	}
	var tokens []Token
	for principal, token := range map[string]string{"alice": aliceToken, "bob": bobToken} {
		h := sha256.Sum256([]byte(token))
		tokens = append(tokens, Token{principal, hex.EncodeToString(h[:])})
	}
	auth, err := NewAuth(TokenFile{tokens})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close(context.Background()); a.Close() })
	return New(m, auth)
}
func request(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAuthenticationAndInputValidation(t *testing.T) {
	h := testHandler(t)
	tests := []struct {
		body, token string
		status      int
	}{{`{"argv":["/bin/sh"]}`, "", 401}, {`{"argv":["/bin/sh"]}`, strings.Repeat("z", 43), 401}, {`{"argv":["/bin/sh"],"argv":["/bad"]}`, aliceToken, 400}, {`{"argv":["/bin/sh"],"env":{"SECRET":"x"}}`, aliceToken, 400}, {`{"argv":["/bin/sh"],"files":{"../x":"oops"}}`, aliceToken, 400}, {strings.Repeat("x", (1<<20)+1), aliceToken, 413}}
	for _, tc := range tests {
		w := request(h, "POST", "/v1/jobs", tc.body, tc.token)
		if w.Code != tc.status {
			t.Fatalf("got %d want %d: %s", w.Code, tc.status, w.Body)
		}
	}
}
func TestJobOwnershipAndHeaders(t *testing.T) {
	h := testHandler(t)
	w := request(h, "POST", "/v1/jobs", `{"argv":["/bin/sh"]}`, aliceToken)
	if w.Code != 202 {
		t.Fatal(w.Body)
	}
	var j model.Job
	json.Unmarshal(w.Body.Bytes(), &j)
	if w.Header().Get("Location") != "/v1/jobs/"+j.ID || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing response headers")
	}
	for _, method := range []string{"GET", "DELETE"} {
		if got := request(h, method, "/v1/jobs/"+j.ID, "", bobToken); got.Code != 404 {
			t.Fatal("cross-principal access")
		}
	}
	if got := request(h, "GET", "/v1/jobs/../secrets", "", aliceToken); got.Code != 404 {
		t.Fatal(got.Code)
	}
}
func TestOriginRequestsRejected(t *testing.T) {
	h := testHandler(t)
	r := httptest.NewRequest("GET", "/v1/jobs", nil)
	r.Header.Set("Authorization", "Bearer "+aliceToken)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
