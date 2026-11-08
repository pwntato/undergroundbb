package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// The public group directory (#71). docs/DESIGN.md, "Visibility -- private and public groups": a public
// group's META row carries GSI1PK "PUBLIC#<shard>" and GSI1SK "NAME#<name>#<gid>", and nothing else
// writes there, so this Query reads only public groups and no private group could appear in it.
// The shard is fixed at 0 (CreateGroup writes it); a browse over more shards would read each and merge.
const (
	directoryPartition = "PUBLIC#0"
	directoryPrefix    = "NAME#"
)

// DirectoryEntry is one public group as the directory lists it.
type DirectoryEntry struct {
	GroupID     string
	Name        string
	Description string
}

// ValidDirectoryCursor reports whether cursor is a sort key this listing could have issued, under the
// name prefix being searched: "NAME#<name>#<gid>" with the prefix as its start. A cursor outside the
// prefix's range would make DynamoDB refuse the query, so callers check this and answer 400.
func ValidDirectoryCursor(cursor, prefix string) bool {
	if !strings.HasPrefix(cursor, directoryPrefix+prefix) {
		return false
	}
	// The name may itself contain '#', so the gid is the fixed-width tail.
	const gidLen = 36
	if len(cursor) < len(directoryPrefix)+1+gidLen {
		return false
	}
	return cursor[len(cursor)-gidLen-1] == '#' && idgen.ValidUUID(cursor[len(cursor)-gidLen:])
}

// ListPublicGroups returns up to limit public groups whose name starts with prefix (the match is
// case-sensitive and on the name exactly as its creator typed it, because that is the index key), in
// name order, and the cursor for the next page ("" when there is none). Two groups may share a name:
// the gid suffix on the key keeps both in the index, so a listing can hold duplicates.
//
// It reads limit+1 rows so that "there is a next page" is known, not guessed: the page never ends
// with an empty follow-up. The index is eventually consistent, so a group created or renamed a moment
// ago may not show yet.
func (c *Client) ListPublicGroups(ctx context.Context, prefix string, limit int, cursor string) ([]DirectoryEntry, string, error) {
	var start map[string]types.AttributeValue
	if cursor != "" {
		if !ValidDirectoryCursor(cursor, prefix) {
			return nil, "", fmt.Errorf("db: list public groups: malformed cursor")
		}
		gid := cursor[len(cursor)-36:]
		start = map[string]types.AttributeValue{
			"PK":     &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK":     &types.AttributeValueMemberS{Value: "META"},
			"GSI1PK": &types.AttributeValueMemberS{Value: directoryPartition},
			"GSI1SK": &types.AttributeValueMemberS{Value: cursor},
		}
	}
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		IndexName:              aws.String("GSI1"),
		KeyConditionExpression: aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: directoryPartition},
			":sk": &types.AttributeValueMemberS{Value: directoryPrefix + prefix},
		},
		ExclusiveStartKey: start,
		Limit:             aws.Int32(int32(limit + 1)),
	})
	if err != nil {
		return nil, "", fmt.Errorf("db: list public groups: %w", err)
	}
	items := out.Items
	next := ""
	if len(items) > limit {
		// A row beyond the page exists, so there is a next page; the cursor names the last row KEPT.
		items = items[:limit]
		next = gsi1SKOf(items[limit-1])
	}
	entries := make([]DirectoryEntry, 0, len(items))
	for _, it := range items {
		var g models.Group
		if err := attributevalue.UnmarshalMap(it, &g); err != nil {
			return nil, "", fmt.Errorf("db: unmarshal public group: %w", err)
		}
		// Defence in depth: the index is sparse and only public groups write to it, but the page is
		// what a stranger sees, so a row that is not public is never listed.
		if g.Visibility != models.VisibilityPublic {
			continue
		}
		entries = append(entries, DirectoryEntry{
			GroupID:     strings.TrimPrefix(g.PK, "GROUP#"),
			Name:        g.NamePlaintext,
			Description: g.DescriptionPlaintext,
		})
	}
	return entries, next, nil
}

func gsi1SKOf(item map[string]types.AttributeValue) string {
	if v, ok := item["GSI1SK"].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}
