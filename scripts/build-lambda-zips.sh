#!/usr/bin/env bash
# Builds lambda.zip and purge.zip at the repo root, the artifacts
# terraform/lambda.tf and terraform/purge.tf hash into source_code_hash.
#
# The zips are byte-for-byte reproducible: the hash only changes when the Go
# code they are built from does, so a push that touches nothing under cmd/ or
# internal/ plans no Lambda update (#98). What each step removes:
#   -buildvcs=false  Go stamps the git revision and time into every binary
#                    built inside a checkout, so each commit would differ.
#   -trimpath        keeps the checkout's absolute path out of the binary.
#   CGO_ENABLED=0    a cross build already has cgo off, but a native
#                    linux/arm64 build would default it on and link a
#                    different, dynamic binary.
#   chmod + touch    pin the mode (umask-dependent) and the file time that
#                    zip records; actions/checkout writes fresh mtimes.
#   zip -X           drops the extra fields (extended timestamps, uid/gid).
set -euo pipefail

cd "$(dirname "$0")/.."
root=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

build_zip() { # <package> <output zip>
  local pkg=$1 out=$2
  mkdir "$work/${out%.zip}"
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o "$work/${out%.zip}/bootstrap" "$pkg"
  chmod 755 "$work/${out%.zip}/bootstrap"
  touch -t 202001010000 "$work/${out%.zip}/bootstrap"
  rm -f "$root/$out"
  (cd "$work/${out%.zip}" && zip -X -q "$root/$out" bootstrap)
}

build_zip ./cmd/lambda lambda.zip
build_zip ./cmd/purge purge.zip
