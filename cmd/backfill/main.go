// Command backfill coarsens the full-resolution CreatedAt on rows written
// before issue #147, and before #259 for Admission, GenerationKey and Rotation
// rows (internal/backfill). It runs as a Lambda that nothing
// schedules, invoked by hand, or once from a shell when AWS_LAMBDA_FUNCTION_NAME
// is unset, which is how it is run against DynamoDB Local.
//
// It fails safe: BACKFILL_DRY_RUN defaults to true and only the exact string
// "false" turns writing on. An invocation payload may force a dry run
// ({"dryRun": true}) but can never turn writing on.
//
// Environment: TABLE_NAME (required), BACKFILL_DRY_RUN, DYNAMODB_ENDPOINT
// (local only).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/pwntato/undergroundbb/internal/backfill"
)

// event is the optional invocation payload.
type event struct {
	DryRun *bool `json:"dryRun"`
}

// dryRun resolves the run's mode from the environment and the payload.
func dryRun(getenv func(string) string, ev event) bool {
	if ev.DryRun != nil && *ev.DryRun {
		return true
	}
	return getenv("BACKFILL_DRY_RUN") != "false"
}

func run(ctx context.Context, ev event) (backfill.Report, error) {
	table := os.Getenv("TABLE_NAME")
	if table == "" {
		return backfill.Report{}, fmt.Errorf("TABLE_NAME is not set")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return backfill.Report{}, fmt.Errorf("load aws config: %w", err)
	}
	var opts []func(*dynamodb.Options)
	if endpoint := os.Getenv("DYNAMODB_ENDPOINT"); endpoint != "" {
		opts = append(opts, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	}
	report, err := backfill.Run(ctx, dynamodb.NewFromConfig(cfg, opts...), table,
		backfill.Options{DryRun: dryRun(os.Getenv, ev)})
	out, _ := json.Marshal(report)
	log.Printf("backfill report: %s", out)
	return report, err
}

func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(run)
		return
	}
	if _, err := run(context.Background(), event{}); err != nil {
		log.Fatalf("backfill: %v", err)
	}
}
