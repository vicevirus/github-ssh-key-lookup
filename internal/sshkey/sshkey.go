package sshkey

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/local/github-ssh-index/internal/model"
)

func Parse(value string) (model.PublicKey, error) {
	public, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(value)))
	if err != nil {
		return model.PublicKey{}, fmt.Errorf("parse OpenSSH public key: %w", err)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return model.PublicKey{}, errors.New("provide exactly one OpenSSH public key")
	}
	blob := public.Marshal()
	digest := sha256.Sum256(blob)
	return model.PublicKey{
		Fingerprint: append([]byte(nil), digest[:]...),
		Text:        "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]),
		Type:        public.Type(),
		Canonical:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))),
	}, nil
}

func NormalizeFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "SHA256:") {
		key, err := Parse(value)
		if err != nil {
			return "", err
		}
		return key.Text, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	if err != nil {
		return "", fmt.Errorf("invalid SHA256 fingerprint: %w", err)
	}
	if len(raw) != sha256.Size {
		return "", errors.New("invalid SHA256 fingerprint length")
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(raw), nil
}
