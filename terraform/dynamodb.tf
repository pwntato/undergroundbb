# The single table backing everything (docs/DESIGN.md's schema). Matches
# scripts/local-setup.sh's DynamoDB Local table and the `dynamodb` service
# CI creates in .github/workflows/test.yml, except for the two properties
# that only matter against the real service: point-in-time recovery and TTL
# actually running.
#
# Name derives from terraform.workspace, not a free-form variable (#11) --
# resolves to "undergroundbb-prod" for the one workspace in use; any other
# workspace fails plan at locals.tf's domain lookup (see the README's
# "Deploying" section for how to select one).
resource "aws_dynamodb_table" "main" {
  name         = "undergroundbb-${terraform.workspace}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

  # Enforced by the service, not just Terraform's plan -- also blocks a
  # console/CLI delete, and unlike `lifecycle.prevent_destroy` it doesn't
  # block a legitimate `terraform destroy` of everything else. Matters more
  # with workspaces (#11): the table name is ambient state (not
  # visible in the destroy command itself), so a `destroy` run against the
  # wrong selected workspace is a real, easy mistake to make.
  deletion_protection_enabled = true

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    projection_type = "ALL"

    # key_schema replaces the index's hash_key/range_key, deprecated in
    # provider v6 (#96). The table's own hash_key/range_key are not.
    key_schema {
      attribute_name = "GSI1PK"
      key_type       = "HASH"
    }

    key_schema {
      attribute_name = "GSI1SK"
      key_type       = "RANGE"
    }
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  # Message expiration (#78) and notification cleanup rely on this running
  # for real, unlike the local/CI tables, where nothing writes a TTL value
  # yet and it's enabled only so the schema matches ahead of that landing.
  ttl {
    attribute_name = "TTL"
    enabled        = true
  }
}

output "table_name" {
  value = aws_dynamodb_table.main.name
}
