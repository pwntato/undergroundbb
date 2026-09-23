// Package idgen generates the random identifiers this project's schema
// calls for.
//
// docs/DESIGN.md is deliberate that ids are random, not time-ordered (e.g.
// "a ULID sort key leaking millisecond timestamps" was a design defect this
// project specifically corrected) -- so every id here comes from a CSPRNG,
// never a counter or a clock.
package idgen

import (
	"crypto/rand"
	"fmt"
	"regexp"
)

// uuidPattern matches exactly what UUID produces: a well-formed, lowercase
// RFC 4122 version 4 UUID (idgen_test.go's own TestUUIDFormat asserts UUID's
// output against the same shape). Exported through ValidUUID rather than
// this pattern directly, since callers should never need to know the schema
// accepts UUIDs specifically, only whether a candidate id is one.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ValidUUID reports whether s is a well-formed, lowercase RFC 4122 version 4
// UUID -- the shape register.go requires of a client-supplied UserID (see
// registerRequest's own doc comment on why the client, not the server,
// generates this one id: the credential-wrap AAD is bound to it before the
// server is ever called). Uppercase hex and other UUID versions are
// rejected rather than normalized, since accepting a wider shape here than
// UUID itself ever produces would let a client-chosen id look different
// from every server-generated one in a table dump for no benefit.
func ValidUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

// UUID generates a random RFC 4122 version 4 UUID, e.g.
// "f47ac10b-58cc-4372-a567-0e02b2c3d479". It is used for every uuid this
// schema assigns server-side (group, invite, ...) -- 122 bits of CSPRNG
// output is far more than this project needs to rule out collision, and a
// UUID is a familiar, self-describing shape for anyone reading a table dump
// or a log line. The one exception is the user uuid, which the client
// generates itself (see ValidUUID's own doc comment for why) using this same
// shape, just not this function.
func UUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("idgen: generate uuid: %w", err)
	}
	// Version 4: set the version nibble to 0100.
	b[6] = (b[6] & 0x0f) | 0x40
	// Variant: set the two most significant bits of byte 8 to 10.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
