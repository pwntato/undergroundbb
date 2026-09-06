// Package models defines the record types stored in the single DynamoDB table.
//
// The table is single-table design: every record carries PK/SK plus a Type
// discriminator, with GSI1 supporting the secondary access patterns. Concrete
// types land alongside the features that need them (M3 onward); this package
// currently defines only the shape every record shares.
package models

// Record is the field set common to every item in the table. Concrete record
// types embed it.
type Record struct {
	PK   string `dynamodbav:"PK"`
	SK   string `dynamodbav:"SK"`
	Type string `dynamodbav:"Type"`

	// GSI1PK and GSI1SK are set only on records participating in GSI1.
	GSI1PK string `dynamodbav:"GSI1PK,omitempty"`
	GSI1SK string `dynamodbav:"GSI1SK,omitempty"`

	// CreatedAt is an RFC 3339 timestamp.
	CreatedAt string `dynamodbav:"CreatedAt,omitempty"`
}
