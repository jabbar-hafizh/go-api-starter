.DEFAULT_GOAL := help
SHELL := /bin/bash

# sqlc, oapi-codegen and goose are pinned in go.mod via tool directives, so
# `go tool <name>` uses identical versions on every machine with no global
# install and no PATH changes.

.PHONY: help
help: ## List commands
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: generate
generate: generate-sql generate-api ## Run all codegen

.PHONY: generate-sql
generate-sql: ## Generate database code from SQL
	go tool sqlc generate

.PHONY: generate-api
generate-api: ## Generate types and server from OpenAPI
	go tool oapi-codegen -config oapi.yaml docs/openapi.yaml

.PHONY: build
build: ## Compile to ./bin/api
	go build -o bin/api ./cmd/api

.PHONY: run
run: ## Run the server with .env
	set -a && source .env && set +a && go run ./cmd/api

.PHONY: test
test: ## Run all tests
	go test -race -count=1 ./...

.PHONY: cover
cover: ## Tests with coverage, excluding generated code
	go test -race -count=1 -coverprofile=coverage.out ./...
	@grep -vE '/internal/(db/gen|openapi)/' coverage.out > coverage.filtered.out
	go tool cover -func=coverage.filtered.out | tail -1
	go tool cover -html=coverage.filtered.out -o coverage.html
	@rm -f coverage.filtered.out

.PHONY: lint
lint: ## Run the linter
	golangci-lint run

.PHONY: fmt
fmt: ## Format the code
	golangci-lint fmt

.PHONY: verify
verify: ## The same gates CI runs
	go build ./...
	go tool sqlc diff
	golangci-lint run
	go test -race -count=1 ./...

.PHONY: docker-build
docker-build: ## Build the app image
	docker compose build api

.PHONY: up
up: ## Run app and Postgres in Docker
	docker compose up -d --build --wait

.PHONY: down
down: ## Stop everything, keep the data
	docker compose down

.PHONY: logs
logs: ## Follow the app logs
	docker compose logs -f api

.PHONY: db-up
db-up: ## Start Postgres and wait until healthy
	docker compose up -d --wait postgres

.PHONY: db-down
db-down: ## Stop Postgres, keep the data
	docker compose down

.PHONY: db-reset
db-reset: ## Drop Postgres and its data
	docker compose down -v

.PHONY: migrate-status
migrate-status: ## Show migration status
	set -a && source .env && set +a && go tool goose -dir internal/db/migrations postgres "$$POSTGRES_DSN" status
