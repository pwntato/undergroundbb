// Command wipe-v1-keyrows deletes every v1 PIN# and VERIFIED# row: the
// one-time migration that goes with the pin v2 / verification v2 payloads
// (#62). Run it once per environment, from a shell with the operator's own AWS
// credentials, after the code that writes v2 rows is deployed; it is
// idempotent. It is not a Lambda and the Lambda roles do not (and must not)
// carry the dynamodb:Scan it needs.
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

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func run(ctx context.Context, getenv func(string) string) (wipeReport, error) {
	table := getenv("TABLE_NAME")
	if table == "" {
		return wipeReport{}, fmt.Errorf("TABLE_NAME is not set")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return wipeReport{}, fmt.Errorf("load aws config: %w", err)
	}
	var clientOpts []func(*dynamodb.Options)
	if endpoint := getenv("DYNAMODB_ENDPOINT"); endpoint != "" {
		clientOpts = append(clientOpts, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	}
	return wipeV1KeyRows(ctx, dynamodb.NewFromConfig(cfg, clientOpts...), table, wipeOptions{dryRun: dryRun(getenv)})
}

// dryRun is true unless WIPE_DRY_RUN is exactly "false".
func dryRun(getenv func(string) string) bool { return getenv("WIPE_DRY_RUN") != "false" }

func main() {
	report, err := run(context.Background(), os.Getenv)
	out, _ := json.Marshal(report)
	log.Printf("wipe report: %s", out)
	if err != nil {
		log.Fatal(err)
	}
}
