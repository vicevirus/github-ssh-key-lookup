package sshkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/local/github-ssh-index/internal/model"
)

func Parse(value string) (model.PublicKey, error) {
	public, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(value)))
	if err != nil {
		if fallback, fallbackErr := parseRFC4253RSA(value); fallbackErr == nil {
			return fallback, nil
		}
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

// parseRFC4253RSA accepts RFC 4253 RSA public keys whose exponent cannot be
// represented by x/crypto/ssh. RFC 4253 encodes e and n as arbitrary-size
// mpints; x/crypto/ssh intentionally applies a narrower 24-bit exponent cap.
// We only need the canonical blob and fingerprint for indexing, not a Go
// crypto/rsa.PublicKey, so retaining a strictly framed key is safe here.
func parseRFC4253RSA(value string) (model.PublicKey, error) {
	line := strings.TrimSpace(value)
	if strings.ContainsAny(line, "\r\n") {
		return model.PublicKey{}, errors.New("provide exactly one OpenSSH public key")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "ssh-rsa" {
		return model.PublicKey{}, errors.New("not an RFC 4253 RSA public key")
	}
	blob, err := decodeSSHBlob(fields[1])
	if err != nil {
		return model.PublicKey{}, err
	}
	if len(blob) > 64<<10 {
		return model.PublicKey{}, errors.New("SSH public key blob is too large")
	}
	offset := 0
	algorithm, err := readSSHField(blob, &offset)
	if err != nil || string(algorithm) != fields[0] {
		return model.PublicKey{}, errors.New("SSH public key algorithm mismatch")
	}
	exponentBytes, err := readSSHField(blob, &offset)
	if err != nil {
		return model.PublicKey{}, errors.New("invalid RSA exponent field")
	}
	modulusBytes, err := readSSHField(blob, &offset)
	if err != nil || offset != len(blob) {
		return model.PublicKey{}, errors.New("invalid RSA modulus field")
	}
	if err := validatePositiveMPInt(exponentBytes); err != nil {
		return model.PublicKey{}, errors.New("invalid RSA public exponent")
	}
	if err := validatePositiveMPInt(modulusBytes); err != nil {
		return model.PublicKey{}, errors.New("invalid RSA modulus")
	}
	digest := sha256.Sum256(blob)
	return model.PublicKey{
		Fingerprint: append([]byte(nil), digest[:]...),
		Text:        "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]),
		Type:        fields[0],
		Canonical:   fields[0] + " " + base64.StdEncoding.EncodeToString(blob),
	}, nil
}

func decodeSSHBlob(encoded string) ([]byte, error) {
	blob, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err == nil {
		return blob, nil
	}
	blob, rawErr := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if rawErr != nil {
		return nil, fmt.Errorf("invalid SSH public key Base64: %w", err)
	}
	return blob, nil
}

func readSSHField(blob []byte, offset *int) ([]byte, error) {
	if *offset < 0 || len(blob)-*offset < 4 {
		return nil, errors.New("truncated SSH field length")
	}
	length := uint64(binary.BigEndian.Uint32(blob[*offset : *offset+4]))
	*offset += 4
	if length > uint64(len(blob)-*offset) {
		return nil, errors.New("truncated SSH field")
	}
	end := *offset + int(length)
	field := blob[*offset:end]
	*offset = end
	return field, nil
}

func validatePositiveMPInt(encoded []byte) error {
	if len(encoded) == 0 || encoded[0]&0x80 != 0 {
		return errors.New("mpint is not positive")
	}
	if len(encoded) > 1 && encoded[0] == 0 && encoded[1]&0x80 == 0 {
		return errors.New("mpint has redundant leading zero")
	}
	if len(encoded) == 1 && encoded[0] == 0 {
		return errors.New("mpint is zero")
	}
	return nil
}

func NormalizeFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) >= len("SHA256:") &&
		strings.EqualFold(value[:len("SHA256:")], "SHA256:") {
		return normalizeSHA256Digest(value[len("SHA256:"):])
	}

	if len(value) == 43 || (len(value) == 44 && strings.HasSuffix(value, "=")) {
		return normalizeSHA256Digest(value)
	}

	key, err := Parse(value)
	if err != nil {
		return "", err
	}
	return key.Text, nil
}

func normalizeSHA256Digest(encoded string) (string, error) {
	var (
		raw []byte
		err error
	)
	switch {
	case len(encoded) == 43:
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
	case len(encoded) == 44 && strings.HasSuffix(encoded, "="):
		raw, err = base64.StdEncoding.DecodeString(encoded)
	default:
		return "", errors.New("invalid SHA256 fingerprint length")
	}
	if err != nil {
		return "", fmt.Errorf("invalid SHA256 fingerprint: %w", err)
	}
	if len(raw) != sha256.Size {
		return "", errors.New("invalid SHA256 fingerprint length")
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(raw), nil
}
