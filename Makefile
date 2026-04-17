.PHONY: install dev test lint type-check scan clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"

test: ## Run tests
	pytest -v --cov=securecommit --cov-report=term-missing

lint: ## Run linter
	ruff check src/ tests/

lint-fix: ## Run linter with auto-fix
	ruff check src/ tests/ --fix

type-check: ## Run type checker
	mypy src/securecommit/ --ignore-missing-imports

scan: ## Run SecureCommit on the project itself
	python -m securecommit scan src/

scan-sarif: ## Generate SARIF report
	python -m securecommit scan src/ --format sarif --output securecommit.sarif

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
