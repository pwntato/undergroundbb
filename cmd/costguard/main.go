// Command costguard is the cost kill switch: a Lambda subscribed to the
// cost-guard SNS topic (terraform/costguard.tf) that sets the web Lambda's
// reserved concurrency to 0 when a usage alarm or the budget fires. Every
// invocation trips it; the message is only logged, so a malformed one can
// not keep the switch from tripping.
//
// A reserved concurrency of 0 makes Lambda throttle every invocation, so the
// API stops billing for compute and DynamoDB at once while the static site
// (S3 behind CloudFront) stays up. Re-arm it by deploying (terraform
// restores var.web_max_concurrency) or by hand:
//
//	aws lambda put-function-concurrency --function-name <name> --reserved-concurrent-executions 50
//
// Environment: TARGET_FUNCTION (required), the web Lambda's name.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	lambdasvc "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// setConcurrency is the one AWS call the switch makes.
type setConcurrency func(ctx context.Context, function string, limit int32) error

// trip sets the target's reserved concurrency to 0. It never inspects the
// message: whatever woke it up is a reason to stop.
func trip(ctx context.Context, target string, set setConcurrency, ev events.SNSEvent) error {
	if target == "" {
		return fmt.Errorf("TARGET_FUNCTION is not set")
	}
	for _, r := range ev.Records {
		log.Printf("costguard: tripped by %s: %s", r.SNS.TopicArn, r.SNS.Subject)
	}
	if err := set(ctx, target, 0); err != nil {
		return fmt.Errorf("set concurrency of %s to 0: %w", target, err)
	}
	out, _ := json.Marshal(map[string]any{"function": target, "reservedConcurrency": 0})
	log.Printf("costguard: %s", out)
	return nil
}

func main() {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("costguard: %v", err)
	}
	client := lambdasvc.NewFromConfig(cfg)
	set := func(ctx context.Context, function string, limit int32) error {
		_, err := client.PutFunctionConcurrency(ctx, &lambdasvc.PutFunctionConcurrencyInput{
			FunctionName:                 aws.String(function),
			ReservedConcurrentExecutions: aws.Int32(limit),
		})
		return err
	}
	lambda.Start(func(ctx context.Context, ev events.SNSEvent) error {
		return trip(ctx, os.Getenv("TARGET_FUNCTION"), set, ev)
	})
}
