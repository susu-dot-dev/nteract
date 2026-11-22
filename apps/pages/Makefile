# Pages local development commands. Run `make help`.
#
# Pages is not in the pnpm workspace: it has its own npm lockfile, builds with
# esbuild and runs under `celld`. See README.md ("Run locally") and AGENTS.md.
# This Makefile is a thin front for the npm scripts, plus the full-stack
# sign-in loop against a local authsu and the susu_landing frontend.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Sibling checkouts of the other two halves of the stack. Override on the
# command line: `make full-stack AUTHSU_DIR=~/src/authsu`.
AUTHSU_DIR   ?= $(HOME)/code/authsu
FRONTEND_DIR ?= $(HOME)/code/susu_landing

# Ports. A local authsu trusts exactly http://localhost:9894 as Pages
# (internal/resource/resource.go in authsu), and its UI_ORIGIN is the frontend's
# origin, http://localhost:3000. Neither may move. scripts/dev.mjs enforces the
# Pages one when PAGES_AUTHSU_URL is local.
PAGES_PORT    := 9894
AUTHSU_PORT   := 8787
FRONTEND_PORT := 3000
AUTHSU_URL    := http://localhost:$(AUTHSU_PORT)

# Local state. celld keeps documents under dist/.celld, and dist/.dev.vars is
# rewritten by `npm run dev` on every start.
PAGES_STATE := dist/.celld

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z0-9_-]+:.*## /{printf "  \033[1m%-16s\033[0m %s\n",$$1,$$2}' $(MAKEFILE_LIST)

# ---- setup ------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Verify node, npm and celld are installed (celld 0.6.3, Node 22.13+)
	@fail=0; \
	for t in node npm celld; do \
	  command -v $$t >/dev/null || { echo "missing required tool: $$t"; fail=1; }; done; \
	[ $$fail -eq 0 ] || exit 1; \
	node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=13)?0:1)' \
	  || { echo "node $$(node -v) is older than 22.13"; exit 1; }; \
	cv="$$(celld --version | awk '{print $$2}')"; \
	[ "$$cv" = "0.6.3" ] || { echo "celld $$cv != pinned 0.6.3"; exit 1; }

.PHONY: setup
setup: check-tools ## Fetch the pinned upstream source and install locked dependencies
	npm run setup

# ---- build / local dev ------------------------------------------------------

.PHONY: build
build: ## Build the Pages Worker and viewer into dist/
	npm run build

# Rebuild only when a source file is newer than the last build. Mirrors the
# "rebuild after source changes" rule in README.md without a manual check.
.PHONY: build-if-stale
build-if-stale:
	@if [ ! -f dist/index.js ] || [ -n "$$(find worker viewer model sync shared scripts identity-provider.mjs mcp.mjs -type f \( -name '*.mjs' -o -name '*.ts' -o -name '*.tsx' -o -name '*.css' \) ! -name '*.test.*' -newer dist/index.js -print -quit)" ]; then \
	  echo "dist/ is missing or older than its sources: building"; $(MAKE) build; \
	else echo "dist/ is current"; fi

.PHONY: dev
dev: check-services build-if-stale ## Run Pages on :9894, signing in with the local authsu (:8787) and frontend (:3000)
	PAGES_AUTHSU_URL=$(AUTHSU_URL) npm run dev

.PHONY: setup-local
setup-local: setup-authsu-local ## Prepare the full local stack: authsu secrets + D1 schema, then a Pages build
	@$(MAKE) build-if-stale
	@echo "Pages writes dist/.dev.vars itself on 'make dev' (scripts/dev.mjs)."

.PHONY: db-reset
db-reset: ## Delete local Pages state (documents and sessions under dist/.celld). Local only.
	rm -rf $(PAGES_STATE)

# ---- the other two halves ---------------------------------------------------
# These run authsu's own make targets so there is one definition of how each
# is brought up. authsu's `dev` and the frontend's `dev` block, so they are
# meant for their own terminals; `full-stack` below starts them for you.

.PHONY: setup-authsu-local
setup-authsu-local: ## One-time authsu setup: .dev.vars secrets and the local D1 schema
	$(MAKE) -C $(AUTHSU_DIR) setup-local migrate-local

.PHONY: authsu-reset
authsu-reset: ## Delete authsu's local database and re-apply migrations (drops every local account and passkey)
	$(MAKE) -C $(AUTHSU_DIR) db-reset migrate-local

.PHONY: authsu-dev
authsu-dev: ## Run authsu on :8787 (blocks; own terminal)
	$(MAKE) -C $(AUTHSU_DIR) dev

.PHONY: frontend-dev
frontend-dev: ## Run the susu_landing frontend on :3000 (blocks; own terminal)
	cd $(FRONTEND_DIR) && pnpm dev

# ---- full stack -------------------------------------------------------------

.PHONY: status
status: ## Show what is listening on the three ports
	@for p in $(FRONTEND_PORT):frontend $(AUTHSU_PORT):authsu $(PAGES_PORT):pages; do \
	  port=$${p%%:*}; name=$${p##*:}; \
	  if curl -s -m2 -o /dev/null http://localhost:$$port/; then echo "  up    $$name :$$port"; \
	  else echo "  down  $$name :$$port"; fi; done

.PHONY: check-services
check-services: ## Fail unless authsu (:8787) and the frontend (:3000) answer
	@fail=0; \
	curl -fsS -m5 $(AUTHSU_URL)/.well-known/openid-configuration >/dev/null \
	  || { echo "authsu is not answering on $(AUTHSU_URL): run 'make authsu-dev' (or 'make full-stack')"; fail=1; }; \
	curl -fsS -m5 -o /dev/null http://localhost:$(FRONTEND_PORT)/ \
	  || { echo "frontend is not answering on :$(FRONTEND_PORT): run 'make frontend-dev' (or 'make full-stack')"; fail=1; }; \
	exit $$fail

.PHONY: full-stack
full-stack: check-tools setup-authsu-local build-if-stale ## Start authsu, the frontend and Pages together (Ctrl-C stops all three)
	@trap 'kill 0' INT TERM EXIT; \
	( $(MAKE) -C $(AUTHSU_DIR) dev DEV_UI_PORT=$(FRONTEND_PORT) ) & \
	( cd $(FRONTEND_DIR) && pnpm dev ) & \
	for i in $$(seq 1 60); do \
	  curl -fsS -m2 $(AUTHSU_URL)/.well-known/openid-configuration >/dev/null 2>&1 && break; sleep 1; done; \
	PAGES_AUTHSU_URL=$(AUTHSU_URL) npm run dev & \
	wait

# ---- verification -----------------------------------------------------------

.PHONY: test
test: ## Unit tests
	npm test

.PHONY: test-contract
test-contract: ## Sync contract tests
	npm run test:contract

.PHONY: e2e
e2e: ## Browser suites (ARGS="sharing wordgard" to pick suites)
	npm run e2e -- $(ARGS)

.PHONY: clean
clean: ## Remove the build output so the next `make build` is full (keeps local state; see db-reset)
	rm -f dist/index.js dist/build-receipt.json
