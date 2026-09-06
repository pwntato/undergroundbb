package crypto

import "testing"

func TestEd25519RoundTrip(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("GROUP#g1:POST#2026-09-05#a1b2:gen3")

	sig, err := Sign(priv, ContextPost, message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, ContextPost, message, sig) {
		t.Fatal("Verify: valid signature rejected")
	}
}

func TestEd25519WrongContextFails(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("shared bytes that could mean two different things")

	sig, err := Sign(priv, ContextLoginChallenge, message)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, ContextPost, message, sig) {
		t.Fatal("Verify: a login-challenge signature verified as a post signature")
	}
	if Verify(pub, ContextRoleGrant, message, sig) {
		t.Fatal("Verify: a login-challenge signature verified as a role-grant signature")
	}
}

func TestEd25519WrongMessageFails(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(priv, ContextPost, []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, ContextPost, []byte("tampered"), sig) {
		t.Fatal("Verify: signature over a different message verified")
	}
}

func TestEd25519WrongKeyFails(t *testing.T) {
	pub1, _, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, priv2, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("message")
	sig, err := Sign(priv2, ContextPost, message)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub1, ContextPost, message, sig) {
		t.Fatal("Verify: signature verified against the wrong public key")
	}
}

func TestEd25519SignRejectsMalformedKey(t *testing.T) {
	if _, err := Sign(nil, ContextPost, []byte("message")); err == nil {
		t.Fatal("Sign with a nil private key: want error, got nil")
	}
	if _, err := Sign(make([]byte, 5), ContextPost, []byte("message")); err == nil {
		t.Fatal("Sign with a 5-byte private key: want error, got nil")
	}
}

func TestEd25519MalformedSignatureFails(t *testing.T) {
	pub, _, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, ContextPost, []byte("message"), []byte("not a real signature")) {
		t.Fatal("Verify: malformed signature verified")
	}
}
