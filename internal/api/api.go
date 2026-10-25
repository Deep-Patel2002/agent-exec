package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"agentexec/internal/model"
	"agentexec/internal/service"
	"agentexec/internal/store"
	"agentexec/internal/strictjson"
)

type Handler struct {
	manager *service.Manager
	auth    *Auth
}

func New(manager *service.Manager, auth *Auth) http.Handler { return &Handler{manager, auth} }
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, message string) {
	write(w, status, map[string]string{"error": message})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		problem(w, 503, "random source unavailable")
		return
	}
	requestID := hex.EncodeToString(id[:])
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if p := recover(); p != nil {
			slog.Error("HTTP handler panic", "request_id", requestID)
			problem(w, 500, "internal error")
		}
		slog.Debug("request completed", "request_id", requestID, "method", r.Method, "duration_ms", time.Since(start).Milliseconds())
	}()
	if r.URL.RawQuery != "" {
		problem(w, 400, "query parameters are not supported")
		return
	}
	if r.URL.Path == "/livez" && r.Method == http.MethodGet {
		write(w, 200, map[string]string{"status": "alive"})
		return
	}
	if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Origin") != "" {
		problem(w, 401, "bearer authentication required")
		return
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		problem(w, 401, "bearer authentication required")
		return
	}
	principal, ok := h.auth.Authenticate(strings.TrimPrefix(header, "Bearer "))
	if !ok {
		problem(w, 401, "invalid credential")
		return
	}
	if r.URL.Path == "/readyz" && r.Method == http.MethodGet {
		s := h.manager.Stats()
		if !s.Ready {
			problem(w, 503, "service unavailable")
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
		return
	}
	if r.URL.Path == "/metrics" && r.Method == http.MethodGet {
		s := h.manager.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "agentexec_in_flight %d\nagentexec_retained_jobs %d\nagentexec_submitted_total %d\nagentexec_completed_total %d\n", s.InFlight, s.Retained, s.Submitted, s.Completed)
		return
	}
	if r.URL.Path == "/v1/jobs" {
		switch r.Method {
		case http.MethodPost:
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				problem(w, 415, "application/json required")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			data, err := io.ReadAll(r.Body)
			if err != nil {
				problem(w, 413, "request exceeds 1 MiB")
				return
			}
			var request model.Request
			if err := strictjson.Decode(data, &request); err != nil {
				problem(w, 400, "invalid JSON: "+err.Error())
				return
			}
			j, err := h.manager.Submit(principal, request)
			if err != nil {
				switch {
				case errors.Is(err, service.ErrBusy):
					w.Header().Set("Retry-After", "1")
					problem(w, 429, err.Error())
				case errors.Is(err, service.ErrUnavailable):
					problem(w, 503, err.Error())
				default:
					problem(w, 400, err.Error())
				}
				return
			}
			w.Header().Set("Location", "/v1/jobs/"+j.ID)
			write(w, 202, j)
			return
		case http.MethodGet:
			write(w, 200, map[string]any{"jobs": h.manager.List(principal)})
			return
		default:
			w.Header().Set("Allow", "GET, POST")
			problem(w, 405, "method not allowed")
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/v1/jobs/") {
		jobID := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
		if !store.ValidID(jobID) {
			problem(w, 404, "job not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			j, err := h.manager.Get(principal, jobID)
			if err != nil {
				problem(w, 404, "job not found")
				return
			}
			write(w, 200, j)
			return
		case http.MethodDelete:
			err := h.manager.Cancel(principal, jobID)
			if errors.Is(err, service.ErrNotFound) {
				problem(w, 404, "job not found")
				return
			}
			if err != nil {
				problem(w, 503, "service unavailable")
				return
			}
			write(w, 202, map[string]string{"status": "cancellation_requested"})
			return
		default:
			w.Header().Set("Allow", "GET, DELETE")
			problem(w, 405, "method not allowed")
			return
		}
	}
	problem(w, 404, "not found")
}
