package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentexec/internal/api"
	"agentexec/internal/model"
	"agentexec/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "init-token" {
		return initToken(os.Args[2:])
	}
	base := flag.String("url", "http://127.0.0.1:8080", "loopback service URL")
	tokenPath := flag.String("token-file", ".local/auth/client.token", "client credential file")
	flag.Parse()
	u, err := url.Parse(*base)
	if err != nil {
		return err
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("client requires an explicit http://loopback-IP:port URL")
	}
	info, err := os.Stat(*tokenPath)
	if err != nil {
		return err
	}
	if info.Size() > 256 {
		return errors.New("invalid credential file")
	}
	token, err := os.ReadFile(*tokenPath)
	if err != nil {
		return err
	}
	secret := strings.TrimSpace(string(token))
	if len(secret) < 32 {
		return errors.New("invalid credential")
	}
	args := flag.Args()
	if len(args) < 1 {
		return errors.New("usage: agent-exec [-token-file FILE] {submit FILE|get ID|wait ID|cancel ID|list}")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, path string, data []byte) ([]byte, error) {
		req, err := http.NewRequest(method, *base+path, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
		}
		return b, nil
	}
	var data []byte
	switch args[0] {
	case "submit":
		if len(args) != 2 {
			return errors.New("submit requires a JSON request filename")
		}
		info, err := os.Stat(args[1])
		if err != nil {
			return err
		}
		if info.Size() > 1<<20 {
			return errors.New("request file exceeds 1 MiB")
		}
		request, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		data, err = call("POST", "/v1/jobs", request)
		if err != nil {
			return err
		}
	case "get", "cancel", "wait":
		if len(args) != 2 || !store.ValidID(args[1]) {
			return errors.New("a valid job ID is required")
		}
		method := "GET"
		if args[0] == "cancel" {
			method = "DELETE"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		for {
			data, err = call(method, "/v1/jobs/"+args[1], nil)
			if err != nil {
				return err
			}
			if args[0] != "wait" {
				break
			}
			var j model.Job
			if err := json.Unmarshal(data, &j); err != nil {
				return err
			}
			if j.State.Terminal() {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	case "list":
		data, err = call("GET", "/v1/jobs", nil)
		if err != nil {
			return err
		}
	default:
		return errors.New("unknown command")
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func initToken(args []string) error {
	f := flag.NewFlagSet("init-token", flag.ContinueOnError)
	dir := f.String("dir", ".local/auth", "private output directory")
	principal := f.String("principal", "local", "credential owner")
	if err := f.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		return err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(token))
	db := api.TokenFile{Tokens: []api.Token{{Principal: *principal, SHA256: hex.EncodeToString(hash[:])}}}
	if _, err := api.NewAuth(db); err != nil {
		return err
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	for _, name := range []string{"client.token", "tokens.json"} {
		if _, err := os.Lstat(filepath.Join(*dir, name)); !os.IsNotExist(err) {
			return errors.New("refusing to overwrite existing credential files")
		}
	}
	for _, item := range []struct {
		name string
		data []byte
	}{{"tokens.json", append(data, '\n')}, {"client.token", []byte(token + "\n")}} {
		file, err := os.OpenFile(filepath.Join(*dir, item.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = file.Write(item.data)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	fmt.Printf("Created credential files in %s (secret was not printed).\n", *dir)
	return nil
}
