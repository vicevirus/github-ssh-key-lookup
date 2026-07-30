package sshkey

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	public, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(public))
}

func TestParseIgnoresCommentAndOptions(t *testing.T) {
	key := strings.TrimSpace(testKey(t))
	plain, err := Parse(key + " laptop")
	if err != nil {
		t.Fatal(err)
	}
	withOptions, err := Parse(`from="10.0.0.1",no-agent-forwarding ` + key + " server")
	if err != nil {
		t.Fatal(err)
	}
	if plain.Text != withOptions.Text || plain.Canonical != withOptions.Canonical {
		t.Fatalf("equivalent keys differ: %#v %#v", plain, withOptions)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	key, err := Parse(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	digest := strings.TrimPrefix(key.Text, "SHA256:")
	for name, input := range map[string]string{
		"canonical":        key.Text,
		"bare":             digest,
		"padded":           digest + "=",
		"lowercase prefix": "sha256:" + digest,
		"complete key":     testKey(t),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := NormalizeFingerprint(input)
			if err != nil {
				t.Fatal(err)
			}
			if got != key.Text {
				t.Fatalf("got %q want %q", got, key.Text)
			}
		})
	}

	for name, input := range map[string]string{
		"short prefixed": "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte("short")),
		"invalid bare":   strings.Repeat("!", 43),
		"extra padding":  digest + "==",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeFingerprint(input); err == nil {
				t.Fatalf("accepted invalid fingerprint %q", input)
			}
		})
	}
}

func TestParseRejectsMultipleKeys(t *testing.T) {
	key := testKey(t)
	if _, err := Parse(key + "\n" + key); err == nil {
		t.Fatal("accepted multiple public keys")
	}
}
