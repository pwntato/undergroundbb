// Command rekey-reaction-notifs moves every reaction notification written before the post's day was
// put in its sort key (#68) to the key the code now computes (#69):
// NOTIF#0000-00-00#<hash> becomes NOTIF#0000-00-00#<post day>#<hash>. Run it once per environment,
// from a shell with the operator's own AWS credentials, after the code that writes the new key is
// deployed; it is idempotent. It is not a Lambda and the Lambda roles do not (and must not) carry
// the dynamodb:Scan it needs.
//
// Until it has run, taking back an old reaction does not find its notification (the delete computes
// the new key), so the notification stays until its post expires or is deleted, and the list shows
// it after the newer ones.
//
// It fails safe: REKEY_DRY_RUN defaults to true and only the exact string "false" turns writing on,
// the same convention as cmd/purge and cmd/wipe-v1-keyrows.
//
// Environment: TABLE_NAME (required), REKEY_DRY_RUN, DYNAMODB_ENDPOINT (local only).
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

func run(ctx context.Context, getenv func(string) string) (rekeyReport, error) {
	table := getenv("TABLE_NAME")
	if table == "" {
		return rekeyReport{}, fmt.Errorf("TABLE_NAME is not set")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return rekeyReport{}, fmt.Errorf("load aws config: %w", err)
	}
	var clientOpts []func(*dynamodb.Options)
	if endpoint := getenv("DYNAMODB_ENDPOINT"); endpoint != "" {
		clientOpts = append(clientOpts, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	}
	return rekeyReactionNotifications(ctx, dynamodb.NewFromConfig(cfg, clientOpts...), table, rekeyOptions{dryRun: dryRun(getenv)})
}

// dryRun is true unless REKEY_DRY_RUN is exactly "false".
func dryRun(getenv func(string) string) bool { return getenv("REKEY_DRY_RUN") != "false" }

func main() {
	report, err := run(context.Background(), os.Getenv)
	out, _ := json.Marshal(report)
	log.Printf("rekey report: %s", out)
	if err != nil {
		log.Fatal(err)
	}
}
