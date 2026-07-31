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

func TestParseRFC4253RSAWithLargeExponent(t *testing.T) {
	const unusualRSA = "ssh-rsa AAAAB3NzaC1yc2EAAAAJAsokcuriAAABAAABAQDhas4u48SN8004rJFz2w8W3VVABgV0kMLJqRq6vj5p+q1tFxXJFt/E1hRl5vpFPUqPh7uZ1nnYHkfM9sDmKCrq9r9KyX+i1+DaEHabP4QsXt2W/5fcxHswJHWReTRa7dA4wHo9iFW27rMHk32OSAvIy3y8bTSuD8PFeuhjTouONHNFwEaJudX3FuqGy7ZQzF6yrf5WrYYrZpQXPyiGjv8E3b9wr2HeT9mr1R8rPukKV23dLRfLERXXdbzK8Wcw0AcDmMXWGhnaC2q7fwoUEq6XO+ArHmaV0OmCrb3R2pW1tXY3VrwXpSxXMd4lrrrRd6sKroHZmQOfMCWfdgBx62KT"
	key, err := Parse(unusualRSA + " vanity-comment")
	if err != nil {
		t.Fatal(err)
	}
	if key.Type != "ssh-rsa" {
		t.Fatalf("type = %q", key.Type)
	}
	if key.Text != "SHA256:cifKeaoLTezpRRdYtMNnPURa3L//wT4gS3pC0S7KSB0" {
		t.Fatalf("fingerprint = %q", key.Text)
	}
	if key.Canonical != unusualRSA {
		t.Fatalf("canonical key changed: %q", key.Canonical)
	}
}

func TestRFC4253RSAFallbackRejectsBrokenFraming(t *testing.T) {
	for _, key := range []string{
		"ssh-rsa not-valid-base64",
		"ssh-rsa AAAAB3NzaC1yc2EAAAAJAsokcuriAAABAAABAQ",
		"ssh-ed25519 AAAAB3NzaC1yc2EAAAAJAsokcuriAAABAAABAQ",
	} {
		if _, err := Parse(key); err == nil {
			t.Fatalf("accepted broken key %q", key)
		}
	}
}
