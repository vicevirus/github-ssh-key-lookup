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
	got, err := NormalizeFingerprint(key.Text)
	if err != nil {
		t.Fatal(err)
	}
	if got != key.Text {
		t.Fatalf("got %q want %q", got, key.Text)
	}
	if _, err := NormalizeFingerprint("SHA256:" + base64.RawStdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("accepted short fingerprint")
	}
}

func TestParseRejectsMultipleKeys(t *testing.T) {
	key := testKey(t)
	if _, err := Parse(key + "\n" + key); err == nil {
		t.Fatal("accepted multiple public keys")
	}
}
