# ─────────────────────────────────────────────────────────────────────────────
#  CVEs Enterprise System — Developer Makefile
#  All targets are documented. Run `make help` for an overview.
# ─────────────────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
SHELL         := bash
.SHELLFLAGS   := -euo pipefail -c

# ── Configurable ──────────────────────────────────────────────────────────────
UV              ?= uv
RUFF            ?= $(UV) run ruff
MYPY            ?= $(UV) run mypy
PYTEST          ?= $(UV) run pytest
REGISTRY        ?= ghcr.io
IMAGE_ORG       ?= $(shell git config --get user.name | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
TAG             ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
NAMESPACE_STG   ?= cves-staging
NAMESPACE_PROD  ?= cves-production

SERVICES := \
	scan-orchestrator \
	discovery-engine \
	runtime-analysis-engine \
	js-intelligence-engine \
	exposure-validation-engine \
	asset-graph-engine \
	ai-correlation-layer \
	reporting-engine \
	dashboard

# ─────────────────────────────────────────────────────────────────────────────
# HELP
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}' | sort

# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: install
install: ## Install all workspace packages in dev mode
	$(UV) sync --all-extras --dev

.PHONY: install-tools
install-tools: ## Install standalone CLI tools (ruff, mypy, bandit, semgrep, etc.)
	$(UV) tool install ruff
	$(UV) tool install mypy
	$(UV) tool install "bandit[toml]"
	$(UV) tool install semgrep
	$(UV) tool install pip-audit
	$(UV) tool install pip-licenses
	$(UV) tool install locust
	$(UV) tool install pytest-benchmark

.PHONY: update
update: ## Update all dependencies (uv lock)
	$(UV) lock --upgrade

# ─────────────────────────────────────────────────────────────────────────────
# CODE QUALITY
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: format
format: ## Auto-format code with ruff
	$(RUFF) format .

.PHONY: lint
lint: ## Lint with ruff (no fix)
	$(RUFF) format --check .
	$(RUFF) check --output-format=concise .

.PHONY: lint-fix
lint-fix: ## Lint + auto-fix safe issues
	$(RUFF) format .
	$(RUFF) check --fix .

.PHONY: type
type: ## Type-check all workspace packages with mypy
	$(MYPY) \
		libs/db-base/src \
		libs/event-schemas/src \
		libs/kafka-client/src \
		libs/observability/src \
		libs/security/src \
		services/scan-orchestrator/src \
		services/discovery-engine/src \
		services/runtime-analysis-engine/src \
		services/js-intelligence-engine/src \
		services/exposure-validation-engine/src \
		services/asset-graph-engine/src \
		services/ai-correlation-layer/src \
		services/reporting-engine/src \
		--config-file pyproject.toml

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: security
security: bandit semgrep audit ## Run all security scans

.PHONY: bandit
bandit: ## Python SAST with bandit
	$(UV) run bandit -r libs/ services/ \
		--severity-level medium \
		--confidence-level medium \
		-x "*/tests/*,*/test_*.py,*/conftest.py,*/migrations/*"

.PHONY: semgrep
semgrep: ## Rule-based SAST with semgrep
	semgrep scan \
		--config "p/python" \
		--config "p/owasp-top-ten" \
		--config "p/secrets" \
		--exclude "tests/" \
		--exclude "*/migrations/*" \
		.

.PHONY: audit
audit: ## Dependency vulnerability audit (pip-audit)
	$(UV) export --format requirements-txt --all-extras > /tmp/all-requirements.txt
	pip-audit -r /tmp/all-requirements.txt --vulnerability-service osv

.PHONY: licenses
licenses: ## Check dependency licence compliance
	pip-licenses --format=json --with-urls --output-file=licenses.json
	@python - <<'EOF'
	import json, sys
	BLOCKED = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
	data = json.load(open("licenses.json"))
	violations = [p for p in data if p.get("License") in BLOCKED]
	if violations:
	    print("BLOCKED licences:")
	    for v in violations: print(f"  {v['Name']} {v['Version']}: {v['License']}")
	    sys.exit(1)
	print("Licence check passed.")
	EOF

.PHONY: secrets
secrets: ## Scan for leaked secrets with gitleaks
	gitleaks detect --source . --verbose

# ─────────────────────────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: test
test: test-unit test-integration ## Run all tests

.PHONY: test-unit
test-unit: ## Unit, async, contract, event-driven tests (no infra required)
	$(PYTEST) \
		-m "unit or async_svc or contract or event_driven" \
		--tb=short \
		--cov \
		--cov-report=term-missing \
		-q

.PHONY: test-integration
test-integration: ## Integration tests (requires running infra — see make infra-up)
	$(PYTEST) \
		-m "integration" \
		--tb=short \
		-q

.PHONY: test-e2e
test-e2e: ## Playwright E2E tests (requires dashboard running)
	$(PYTEST) \
		-m "e2e" \
		--tb=short \
		-v

.PHONY: test-performance
test-performance: ## Run pytest-benchmark micro-benchmarks
	$(PYTEST) \
		tests/performance/test_serialization_benchmark.py \
		--benchmark-only \
		--benchmark-sort=mean \
		--benchmark-min-rounds=500 \
		-v

.PHONY: load-test
load-test: ## Locust load test (opens web UI at http://localhost:8089)
	locust -f tests/performance/locustfile.py \
		--host http://localhost:8000 \
		--web-port 8089

.PHONY: load-test-headless
load-test-headless: ## Locust headless (50 users, 60s)
	locust -f tests/performance/locustfile.py \
		--host http://localhost:8000 \
		--headless -u 50 -r 10 --run-time 60s

.PHONY: coverage
coverage: ## Generate HTML coverage report
	$(PYTEST) \
		-m "unit or async_svc or contract or event_driven" \
		--cov \
		--cov-report=html:htmlcov \
		--cov-report=term-missing \
		-q
	@echo "Coverage report: htmlcov/index.html"

.PHONY: coverage-gate
coverage-gate: ## Fail if coverage < 80%
	$(PYTEST) \
		-m "unit or async_svc or contract or event_driven" \
		--cov \
		--cov-fail-under=80 \
		-q --no-header

# ─────────────────────────────────────────────────────────────────────────────
# INFRASTRUCTURE (local dev)
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: infra-up
infra-up: ## Start local infra (Postgres, Redis, Kafka, Neo4j, Minio)
	docker compose -f docker-compose.infra.yml up -d
	@echo "Waiting for Postgres..."
	@until docker compose -f docker-compose.infra.yml exec -T postgres pg_isready -U cves 2>/dev/null; do sleep 1; done
	@echo "Infra ready."

.PHONY: infra-down
infra-down: ## Stop local infra
	docker compose -f docker-compose.infra.yml down

.PHONY: infra-reset
infra-reset: ## Stop local infra and remove all volumes
	docker compose -f docker-compose.infra.yml down -v

.PHONY: logs
logs: ## Tail logs for a specific service: make logs SVC=scan-orchestrator
	docker compose -f docker-compose.infra.yml logs -f $(SVC)

# ─────────────────────────────────────────────────────────────────────────────
# DOCKER / BUILD
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: build
build: ## Build all service images locally
	@for svc in $(SERVICES); do \
		echo "━━━ Building $$svc ━━━"; \
		docker build \
			-f services/$$svc/Dockerfile \
			-t $(REGISTRY)/$(IMAGE_ORG)/cves-$$svc:$(TAG) \
			. ; \
	done

.PHONY: build-svc
build-svc: ## Build a single service: make build-svc SVC=scan-orchestrator
	docker build \
		-f services/$(SVC)/Dockerfile \
		-t $(REGISTRY)/$(IMAGE_ORG)/cves-$(SVC):$(TAG) \
		.

.PHONY: scan-image
scan-image: ## Trivy scan a single image: make scan-image SVC=scan-orchestrator
	trivy image $(REGISTRY)/$(IMAGE_ORG)/cves-$(SVC):$(TAG)

.PHONY: sbom
sbom: ## Generate SBOM for a single image (SPDX + CycloneDX): make sbom SVC=scan-orchestrator
	syft $(REGISTRY)/$(IMAGE_ORG)/cves-$(SVC):$(TAG) \
		--output spdx-json=sbom-$(SVC)-spdx.json \
		--output cyclonedx-json=sbom-$(SVC)-cyclonedx.json
	@echo "SBOMs: sbom-$(SVC)-spdx.json, sbom-$(SVC)-cyclonedx.json"

# ─────────────────────────────────────────────────────────────────────────────
# KUBERNETES
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: k8s-apply-staging
k8s-apply-staging: ## Apply all manifests to staging namespace
	kubectl apply -f k8s/namespaces.yaml
	kubectl apply -f k8s/rbac/ --recursive
	kubectl apply -f k8s/networkpolicies/ --recursive
	@for svc in $(SERVICES); do \
		if [ -d "k8s/services/$$svc" ]; then \
			kubectl apply -f k8s/services/$$svc/ --namespace=$(NAMESPACE_STG); \
		fi; \
	done

.PHONY: k8s-rollout-status
k8s-rollout-status: ## Check rollout status for all deployments in staging
	@for svc in $(SERVICES); do \
		if kubectl get deployment $$svc --namespace=$(NAMESPACE_STG) &>/dev/null; then \
			echo "━━━ $$svc ━━━"; \
			kubectl rollout status deployment/$$svc --namespace=$(NAMESPACE_STG) --timeout=60s || true; \
		fi; \
	done

.PHONY: k8s-images
k8s-images: ## List all container images running in the cluster
	kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort

# ─────────────────────────────────────────────────────────────────────────────
# RELEASE
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: release-patch
release-patch: ## Bump patch version and push tag (triggers production deploy)
	@CURRENT=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//') ; \
	IFS='.' read -r MAJOR MINOR PATCH <<< "$$CURRENT" ; \
	NEW="v$$MAJOR.$$MINOR.$$((PATCH+1))" ; \
	echo "Tagging $$NEW" ; \
	git tag -a "$$NEW" -m "Release $$NEW" ; \
	git push origin "$$NEW"

.PHONY: release-minor
release-minor: ## Bump minor version and push tag
	@CURRENT=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//') ; \
	IFS='.' read -r MAJOR MINOR PATCH <<< "$$CURRENT" ; \
	NEW="v$$MAJOR.$$((MINOR+1)).0" ; \
	echo "Tagging $$NEW" ; \
	git tag -a "$$NEW" -m "Release $$NEW" ; \
	git push origin "$$NEW"

.PHONY: release-major
release-major: ## Bump major version and push tag
	@CURRENT=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//') ; \
	IFS='.' read -r MAJOR MINOR PATCH <<< "$$CURRENT" ; \
	NEW="v$$((MAJOR+1)).0.0" ; \
	echo "Tagging $$NEW" ; \
	git tag -a "$$NEW" -m "Release $$NEW" ; \
	git push origin "$$NEW"

# ─────────────────────────────────────────────────────────────────────────────
# CI SIMULATION (run CI pipeline locally)
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: ci
ci: lint type security test coverage-gate ## Run full CI locally (lint + type + security + tests)
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo " Local CI passed ✓"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

.PHONY: pre-push
pre-push: format lint type test-unit ## Quick pre-push check (format + lint + types + unit tests)
