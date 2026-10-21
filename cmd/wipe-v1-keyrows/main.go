// Command wipe-v1-keyrows deletes every v1 PIN# and VERIFIED# row
// (internal/db.WipeV1KeyRows): the one-time migration that goes with the
// pin v2 / verification v2 payloads (#62). Run it once per environment, from a
// shell, after the code that writes v2 rows is deployed; it is idempotent.
//
// It fails safe: WIPE_DRY_RUN defaults to true and only the exact string
// "false" turns deletion on, the same convention as cmd/purge.
//
// Environment: TABLE_NAME (required), WIPE_DRY_RUN, DYNAMODB_ENDPOINT (local only).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/pwntato/undergroundbb/internal/db"
)

func run(ctx context.Context, getenv func(string) string) (db.WipeV1Report, error) {
	table := getenv("TABLE_NAME")
	if table == "" {
		return db.WipeV1Report{}, fmt.Errorf("TABLE_NAME is not set")
	}
	client, err := db.New(ctx, table, getenv("DYNAMODB_ENDPOINT"))
	if err != nil {
		return db.WipeV1Report{}, err
	}
	return client.WipeV1KeyRows(ctx, db.WipeV1Options{DryRun: getenv("WIPE_DRY_RUN") != "false"})
}

func main() {
	report, err := run(context.Background(), os.Getenv)
	out, _ := json.Marshal(report)
	log.Printf("wipe report: %s", out)
	if err != nil {
		log.Fatal(err)
	}
}
