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

.PHONY: help install lint fmt test test-all
