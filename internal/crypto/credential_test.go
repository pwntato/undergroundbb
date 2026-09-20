package crypto

import "testing"

// TestVectorCredentialWrap (vectors_test.go) pins the exact encoding against
// a fixed vector shared with the TypeScript implementation. These
// additional cases cover properties the vector alone doesn't: that the
// encoding is stable for repeated calls, and that it actually varies with
// both inputs -- not just that the two fixed vector values happen to differ.

func TestCredentialWrapAADDeterministic(t *testing.T) {
	a := CredentialWrapAAD("user-1", CredentialCopyProfile)
	b := CredentialWrapAAD("user-1", CredentialCopyProfile)
	if string(a) != string(b) {
		t.Fatalf("CredentialWrapAAD is not deterministic: %q != %q", a, b)
	}
}

func TestCredentialWrapAADVariesByCopy(t *testing.T) {
	profile := CredentialWrapAAD("user-1", CredentialCopyProfile)
	recovery := CredentialWrapAAD("user-1", CredentialCopyRecovery)
	if string(profile) == string(recovery) {
		t.Fatalf("CredentialWrapAAD(user-1, PROFILE) == CredentialWrapAAD(user-1, RECOVERY): %q", profile)
	}
}

func TestCredentialWrapAADVariesByUser(t *testing.T) {
	user1 := CredentialWrapAAD("user-1", CredentialCopyProfile)
	user2 := CredentialWrapAAD("user-2", CredentialCopyProfile)
	if string(user1) == string(user2) {
		t.Fatalf("CredentialWrapAAD(user-1, PROFILE) == CredentialWrapAAD(user-2, PROFILE): %q", user1)
	}
}
