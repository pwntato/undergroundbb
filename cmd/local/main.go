// Command local runs the API over plain HTTP for development.
//
// It serves the same handlers as cmd/lambda, so behaviour matches production
// apart from the transport. DYNAMODB_ENDPOINT points it at DynamoDB Local.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/handlers"
)

func main() {
	ctx := context.Background()
	cfg := config.FromEnv()

	dbClient, err := db.New(ctx, cfg.TableName, os.Getenv("DYNAMODB_ENDPOINT"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}

	mux := http.NewServeMux()
	handlers.New(cfg, dbClient).RegisterRoutes(mux)

	addr := ":" + config.StringEnvOrDefault("PORT", "3000")
	log.Printf("%s listening on %s", cfg.SiteName, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
