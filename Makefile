.PHONY: install
install: ## Install the virtual environment and install the pre-commit hooks
	@echo "🚀 Creating virtual environment using uv"
	@uv sync
	@uv run pre-commit install

.PHONY: check
check: ## Run code quality tools.
	@echo "🚀 Checking lock file consistency with 'pyproject.toml'"
	@uv lock --locked
	@echo "🚀 Linting code: Running pre-commit"
	@uv run pre-commit run -a
	@echo "🚀 Checking for obsolete dependencies: Running deptry"
	@uv run deptry .

.PHONY: test
test: ## Test the code with pytest
	@echo "🚀 Testing code: Running pytest"
	@uv run python -m pytest --cov --cov-config=pyproject.toml --cov-report=xml -vv -s

.PHONY: test-integration
test-integration: ## Run integration tests (real protocol servers, no Docker)
	@echo "🚀 Running integration tests"
	@uv run --group integration python -m pytest -m integration -o "addopts=" -vv -s

.PHONY: test-docker
test-docker: ## Run Docker integration tests (requires Docker)
	@echo "🐳 Running Docker integration tests"
	@uv run --group docker python -m pytest -m docker -o "addopts=" -vv -s

.PHONY: test-all
test-all: ## Run all tests (unit + integration + Docker)
	@echo "🚀 Running all tests"
	@uv run --group integration --group docker python -m pytest -o "addopts=" --cov --cov-config=pyproject.toml --cov-report=xml -vv -s

.PHONY: build
build: clean-build ## Build wheel file
	@echo "🚀 Creating wheel file"
	@uvx --from build pyproject-build --installer uv

.PHONY: clean-build
clean-build: ## Clean build artifacts
	@rm -rf dist build *.egg-info

.PHONY: clean
clean: clean-build ## Remove build, test, and cache artifacts
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.py[co]" -delete 2>/dev/null || true
	@rm -rf .pytest_cache .coverage coverage.xml htmlcov .mypy_cache .ruff_cache .hypothesis
	@echo "✨ Clean complete"

.PHONY: clean-docker
clean-docker: ## Stop and remove Docker test containers and volumes
	@echo "🐳 Cleaning Docker test environment"
	@docker compose -f tests/docker/docker-compose.yml down -v --remove-orphans 2>/dev/null || true
	@echo "✨ Docker clean complete"

.PHONY: clean-all
clean-all: clean clean-docker ## Remove all artifacts including tox, docs, and Docker
	@rm -rf .tox .nox site
	@echo "✨ Deep clean complete"

.PHONY: publish
publish: ## Publish a release to PyPI.
	@echo "🚀 Publishing."
	@uvx twine upload --repository-url https://upload.pypi.org/legacy/ dist/*

.PHONY: build-and-publish
build-and-publish: build publish ## Build and publish.

.PHONY: docs-test
docs-test: ## Test if documentation can be built without warnings or errors
	@uv run mkdocs build -s

.PHONY: docs
docs: ## Build and serve the documentation
	@uv run mkdocs serve

.PHONY: help
help:
	@uv run python -c "import re; \
	[[print(f'\033[36m{m[0]:<20}\033[0m {m[1]}') for m in re.findall(r'^([a-zA-Z_-]+):.*?## (.*)$$', open(makefile).read(), re.M)] for makefile in ('$(MAKEFILE_LIST)').strip().split()]"

.PHONY: install-claude-desktop
install-claude-desktop: ## Install the desktop application
	@uv sync
	@python dev/install_claude_desktop.py

.DEFAULT_GOAL := help
