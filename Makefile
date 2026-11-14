# Agentic SOC – developer shortcuts. Run `make help` for the list.
.DEFAULT_GOAL := help
PYTEST_FAST := -m "not integration and not llm and not slow"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install Python dependencies (uv)
	uv sync

lint: ## Lint and check formatting
	uv run ruff check src tests
	uv run ruff format --check src tests

fmt: ## Auto-format and fix lint issues
	uv run ruff format src tests
	uv run ruff check --fix src tests

test: ## Fast unit tests
	uv run pytest $(PYTEST_FAST)

test-all: ## All tests, including integration/LLM/slow ones
	uv run pytest

COMPOSE := docker compose -f deploy/docker-compose.yml

up: ## Start the infrastructure (Redpanda, TimescaleDB)
	$(COMPOSE) up -d --wait

down: ## Stop the infrastructure
	$(COMPOSE) down

test-integration: ## Integration tests against the docker compose stack
	SOC_KAFKA_URL=kafka://localhost:19092 \
	SOC_PG_URL=postgresql+psycopg://soc:soc@localhost:15432/soc \
	uv run pytest -m integration

.PHONY: help install lint fmt test test-all up down test-integration
