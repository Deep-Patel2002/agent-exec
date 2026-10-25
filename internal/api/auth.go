package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"regexp"

	"agentexec/internal/strictjson"
)

type Token struct {
	Principal string `json:"principal"`
	SHA256    string `json:"sha256"`
}
type TokenFile struct {
	Tokens []Token `json:"tokens"`
}
type credential struct {
	principal string
	hash      [32]byte
}
type Auth struct{ tokens []credential }

var principalPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$`)

func LoadAuth(path string) (*Auth, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 32768 {
		return nil, errors.New("invalid token database")
	}
	if err := checkPrivateFile(info); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f TokenFile
	if err := strictjson.Decode(data, &f); err != nil {
		return nil, err
	}
	return NewAuth(f)
}
func NewAuth(f TokenFile) (*Auth, error) {
	if len(f.Tokens) < 1 || len(f.Tokens) > 64 {
		return nil, errors.New("token database requires 1-64 credentials")
	}
	a := &Auth{}
	seen := map[string]bool{}
	for _, t := range f.Tokens {
		b, err := hex.DecodeString(t.SHA256)
		if err != nil || len(b) != 32 || !principalPattern.MatchString(t.Principal) || seen[hex.EncodeToString(b)] {
			return nil, errors.New("invalid credential or duplicate token")
		}
		seen[hex.EncodeToString(b)] = true
		c := credential{principal: t.Principal}
		copy(c.hash[:], b)
		a.tokens = append(a.tokens, c)
	}
	return a, nil
}
func (a *Auth) Authenticate(token string) (string, bool) {
	if len(token) < 32 || len(token) > 256 {
		return "", false
	}
	hash := sha256.Sum256([]byte(token))
	principal := ""
	matched := false
	for _, c := range a.tokens {
		if subtle.ConstantTimeCompare(c.hash[:], hash[:]) == 1 {
			principal = c.principal
			matched = true
		}
	}
	return principal, matched
}
