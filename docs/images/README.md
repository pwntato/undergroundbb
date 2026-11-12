# Screenshots

The images here are taken from the running app by a script, so they can be regenerated when the screens change instead of going stale. They are used by `docs/USER_GUIDE.md`.

The script is `web/e2e-docs/screenshots.spec.ts`. It signs up two people (`alice` and `bob`) on a **local** copy of the app, so it needs an **empty database** each time, and it must never be pointed at a deployed site.

```sh
# 1. An empty database. -inMemory means removing the container clears it.
docker run -d --rm --name ubb-docs-ddb -p 8766:8000 amazon/dynamodb-local:latest \
  -jar DynamoDBLocal.jar -inMemory -sharedDb
DYNAMODB_ENDPOINT=http://127.0.0.1:8766 TABLE_NAME=undergroundbb ./scripts/local-setup.sh

# 2. The API on :3000 (same variables as in the README's local development section,
#    with DYNAMODB_ENDPOINT pointing at :8766).
export AWS_ACCESS_KEY_ID=localuser AWS_SECRET_ACCESS_KEY=localpassword AWS_DEFAULT_REGION=us-west-2
export DYNAMODB_ENDPOINT=http://127.0.0.1:8766 TABLE_NAME=undergroundbb
export SESSION_SECRET=$(openssl rand -hex 32)
go run ./cmd/local

# 3. The frontend on :5173, then the script (in other terminals).
cd web && npm run dev
cd web && npx playwright test -c playwright.docs.config.ts

# 4. Clean up.
docker rm -f ubb-docs-ddb
```

The pictures are 1100 by 760 pixels in the default theme (Refined Terminal). Keep each one under about 100 KB. A screenshot that shows an account's data uses throwaway accounts on the empty local database, never a real one.
