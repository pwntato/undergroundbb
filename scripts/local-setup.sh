#!/usr/bin/env bash
# Waits for DynamoDB Local (started via `docker compose up -d`) to accept
# connections, then creates the undergroundbb table if it doesn't already
# exist. Schema matches DESIGN.md and the `dynamodb` service in
# .github/workflows/test.yml exactly: PK/SK plus GSI1 (GSI1PK/GSI1SK,
# projection ALL), PAY_PER_REQUEST.
#
# Safe to re-run: table creation is skipped, not retried, if the table
# already exists.
set -euo pipefail

ENDPOINT="${DYNAMODB_ENDPOINT:-http://127.0.0.1:8000}"
TABLE="${TABLE_NAME:-undergroundbb}"

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-localuser}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-localpassword}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-west-2}"

echo "waiting for DynamoDB Local at $ENDPOINT..."
for _ in $(seq 1 20); do
  if aws dynamodb list-tables --endpoint-url "$ENDPOINT" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! aws dynamodb list-tables --endpoint-url "$ENDPOINT" >/dev/null 2>&1; then
  echo "DynamoDB Local did not become ready in time. Is 'docker compose up -d' running?" >&2
  exit 1
fi

if aws dynamodb describe-table --endpoint-url "$ENDPOINT" --table-name "$TABLE" >/dev/null 2>&1; then
  echo "table '$TABLE' already exists, skipping create"
  exit 0
fi

echo "creating table '$TABLE'..."
aws dynamodb create-table \
  --endpoint-url "$ENDPOINT" \
  --table-name "$TABLE" \
  --attribute-definitions \
    AttributeName=PK,AttributeType=S \
    AttributeName=SK,AttributeType=S \
    AttributeName=GSI1PK,AttributeType=S \
    AttributeName=GSI1SK,AttributeType=S \
  --key-schema \
    AttributeName=PK,KeyType=HASH \
    AttributeName=SK,KeyType=RANGE \
  --global-secondary-indexes '[{"IndexName":"GSI1","KeySchema":[{"AttributeName":"GSI1PK","KeyType":"HASH"},{"AttributeName":"GSI1SK","KeyType":"RANGE"}],"Projection":{"ProjectionType":"ALL"}}]' \
  --billing-mode PAY_PER_REQUEST \
  >/dev/null

# CI's table (.github/workflows/test.yml) skips this since no feature writes
# a TTL attribute yet, but it's free to enable and matches what #5's
# Terraform table will run in every real deployment.
aws dynamodb update-time-to-live \
  --endpoint-url "$ENDPOINT" \
  --table-name "$TABLE" \
  --time-to-live-specification "Enabled=true,AttributeName=TTL" \
  >/dev/null

echo "table '$TABLE' created"
