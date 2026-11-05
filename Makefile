.DEFAULT_GOAL:=help
-include .makerc

# --- Config ------------------------------------------------------------------

GOMODS=$(shell find . -type f -name go.mod -not -path './tmp/*')
# Newline hack for error output
define br


endef

# --- Targets -----------------------------------------------------------------

# This allows us to accept extra arguments
%: .mise .lefthook go.work
	@:

.PHONY: .mise
# Install dependencies
.mise:
ifeq (, $(shell command -v mise))
	$(error $(br)$(br)Please ensure you have 'mise' installed and activated!$(br)$(br)  $$ brew update$(br)  $$ brew install mise$(br)$(br)See the documentation: https://mise.jdx.dev/getting-started.html)
endif
	@mise install

.PHONY: .lefthook
# Configure git hooks for lefthook
.lefthook:
	@lefthook install --reset-hooks-path

# Ensure go.work file
go.work:
	@echo "〉initializing go work"
	@go work init && go work use -r . && go work sync

### Tasks

.PHONY: check
## Run lint & tests
check: tidy generate lint test audit

.PHONY: tidy
## Run go mod tidy
tidy: go.work
	@echo "〉go mod tidy"
	@$(foreach mod,$(GOMODS), (cd $(dir $(mod)) && echo "📂 $(dir $(mod))" && go mod tidy) &&) true
	@go work use -r . && go work sync

.PHONY: lint
## Run linter
lint:
	@echo "〉golangci-lint run"
	@$(foreach mod,$(GOMODS), (cd $(dir $(mod)) && echo "📂 $(dir $(mod))" && golangci-lint run) &&) true

.PHONY: lint.fix
## Run golangci-lint & fix
lint.fix:
	@echo "〉golangci-lint run fix"
	@$(foreach mod,$(GOMODS), (cd $(dir $(mod)) && echo "📂 $(dir $(mod))" && golangci-lint run --fix) &&) true

.PHONY: generate
## Run go generate
generate: go.work
	@echo "〉go generate"
	@go generate work

.PHONY: test
## Run tests
test: go.work
	@echo "〉go test"
	@GO_TEST_TAGS=-skip go test -tags=safe -shuffle=on -coverprofile=coverage.out work

.PHONY: test.race
## Run tests with -race
test.race: go.work
	@echo "〉go test with -race"
	@GO_TEST_TAGS=-skip go test -tags=safe -shuffle=on -coverprofile=coverage.out -race work

.PHONY: test.update
## Run tests with -update
test.update: go.work
	@echo "〉go test with -update"
	@GO_TEST_TAGS=-skip go test -tags=safe --shuffle=on coverprofile=coverage.out -update work

.PHONY: test.bench
## Run tests with -bench
test.bench: go.work
	@echo "〉go bench"
	@GO_TEST_TAGS=-skip go test -tags=safe -bench=. -benchmem work

### Dependencies

.PHONY: audit
## Run security audit
audit:
	@echo "〉security audit"
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@go govulncheck ./...

.PHONY: outdated
## Show outdated direct dependencies
outdated:
	@echo "〉mise"
	@mise outdated -l --local
	@echo "〉go mod outdated"
	@find . -name 'go.mod' -exec dirname {} \; | xargs -I {} sh -c 'cd {} && go list -u -m -json all' \; | go-mod-outdated -update -direct

.PHONY: upgrade
## Show outdated direct dependencies
upgrade: go.work
	@echo "〉go mod upgrade"
	@$(foreach mod,$(GOMODS), (cd $(dir $(mod)) && echo "📂 $(dir $(mod))" && go get -u ./...) &&) true
	@$(MAKE) tidy

### Release

.PHONY: tag.submodules
## Create tags for submodules TAG=1.0.0
tag.submodules:
	@echo "$(TAG)" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "❌ TAG must be vX.Y.Z format"; exit 1; }
	@git rev-parse "$(TAG)" >/dev/null 2>&1 || { echo "❌ Tag $(TAG) does not exist"; exit 1; }
	@echo "🔖 Creating submodule tags..."
	@find . -type f -name 'go.mod' -mindepth 2 -not -path './vendor/*' -exec sh -c 'dir=$$(dirname {} | sed "s|^\./||"); tag="$$dir/$(TAG)"; git rev-parse "$$tag" >/dev/null 2>&1 || { echo "🔖 $$tag"; git tag "$$tag"; }' \;
	@echo "🔖 Pushing tags..."
	@git push origin --tags

### Documentation

.PHONY: docs
## Serve the vitepress docs locally
docs:
	@echo "〉starting docs"
	@cd docs && bun install && bun run dev

.PHONY: docs.build
## Build the vitepress docs
docs.build:
	@echo "〉building docs"
	@cd docs && bun install && bun run build

.PHONY: godocs
## Serve go docs
godocs:
	@echo "〉starting go docs"
	@go doc -http

### Sandbox

SANDBOX_COMPOSE=docker compose -f examples/sandbox/docker-compose.yaml
SANDBOX_APP=cd examples && go run ./nativeapp
SANDBOX_KCADM=$(SANDBOX_COMPOSE) exec -T keycloak /opt/keycloak/bin/kcadm.sh
SANDBOX_KCADM_CFG=--config /tmp/kcadm.config
SANDBOX_USER?=alice

.PHONY: sandbox.up
## Start the sandbox (keycloak + mongo) and wait until healthy
sandbox.up:
	@echo "〉starting keycloak and mongo"
	@$(SANDBOX_COMPOSE) up -d --wait
	@echo "〉keycloak admin: http://localhost:8081  (admin / admin)"

.PHONY: sandbox.down
## Stop the sandbox (keycloak + mongo) and remove volumes
sandbox.down:
	@echo "〉stopping keycloak and mongo"
	@$(SANDBOX_COMPOSE) down -v

.PHONY: sandbox.status
## Show the sandbox containers and their health
sandbox.status:
	@$(SANDBOX_COMPOSE) ps

.PHONY: sandbox.logs
## Follow the sandbox container logs (ARGS=keycloak|mongo)
sandbox.logs:
	@$(SANDBOX_COMPOSE) logs -f $(ARGS)

.PHONY: sandbox.run
## Run the sandbox demo app against keycloak
sandbox.run:
	@echo "〉starting sandbox demo at http://localhost:8080"
	@cd examples && go run ./sandbox

.PHONY: sandbox.app
## Native client: login, whoami, refresh, revoke (ARGS=-scenario=...)
sandbox.app:
	@$(SANDBOX_APP) $(ARGS)

.PHONY: sandbox.app.check
## Native client: protocol checks that need no login
sandbox.app.check:
	@$(SANDBOX_APP) -scenario=check

.PHONY: sandbox.app.reuse
## Native client: an old refresh token replayed after grace revokes the session
sandbox.app.reuse:
	@$(SANDBOX_APP) -scenario=reuse

.PHONY: sandbox.app.concurrent
## Native client: two concurrent refreshes both succeed
sandbox.app.concurrent:
	@$(SANDBOX_APP) -scenario=concurrent

.PHONY: sandbox.app.outage
## Native client: IdP down answers 503 and keeps the session (interactive)
sandbox.app.outage:
	@$(SANDBOX_APP) -scenario=outage

.PHONY: sandbox.app.signout
## Native client: an IdP-side sign-out ends the session (interactive)
sandbox.app.signout:
	@$(SANDBOX_APP) -scenario=signout

.PHONY: sandbox.app.restart
## Native client: a session survives a restart of the demo app (interactive)
sandbox.app.restart:
	@$(SANDBOX_APP) -scenario=restart

.PHONY: sandbox.idp.stop
## Stop keycloak only, to simulate an IdP outage
sandbox.idp.stop:
	@echo "〉stopping keycloak"
	@$(SANDBOX_COMPOSE) stop keycloak

.PHONY: sandbox.idp.start
## Start keycloak again and wait until healthy
sandbox.idp.start:
	@echo "〉starting keycloak"
	@$(SANDBOX_COMPOSE) up -d --wait keycloak

.PHONY: sandbox.idp.signout
## End a user's offline session at keycloak (SANDBOX_USER=alice)
sandbox.idp.signout:
	@echo "〉revoking $(SANDBOX_USER)'s offline tokens for gosso-oidc"
	@$(SANDBOX_KCADM) config credentials --server http://localhost:8080 --realm master --user admin --password admin $(SANDBOX_KCADM_CFG)
	@id=$$($(SANDBOX_KCADM) get users -r gosso-sandbox -q username=$(SANDBOX_USER) -q exact=true --fields id --format csv --noquotes $(SANDBOX_KCADM_CFG)) && \
		test -n "$$id" && $(SANDBOX_KCADM) delete users/$$id/consents/gosso-oidc -r gosso-sandbox $(SANDBOX_KCADM_CFG)

.PHONY: sandbox.mongo
## Show the native broker's codes, sessions and indexes in mongo
sandbox.mongo:
	@$(SANDBOX_COMPOSE) exec -T mongo mongosh gosso_sandbox --quiet --eval ' \
		print("codes:    " + db.gosso_native_codes.countDocuments()); \
		print("sessions: " + db.gosso_native_sessions.countDocuments()); \
		printjson(db.gosso_native_sessions.find({}, {_id: 0, id: 1, clientID: 1, "subject.externalID": 1, attributes: 1, rotatedAt: 1, expiresAt: 1, "idpRefreshToken.keyID": 1}).toArray()); \
		print("indexes:"); \
		printjson(db.gosso_native_codes.getIndexes().map(i => i.key)); \
		printjson(db.gosso_native_sessions.getIndexes().map(i => i.key));'

.PHONY: sandbox.certs
## Regenerate the sandbox SP cert pair (dev only)
sandbox.certs:
	@echo "🔏 regenerating sandbox SP cert"
	@mkdir -p examples/sandbox/certs
	@openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
		-keyout examples/sandbox/certs/sp.key \
		-out examples/sandbox/certs/sp.crt \
		-subj "/CN=gosso-sandbox"

### Utils

.PHONY: help
## Show help text
help:
	@echo "gosso\n"
	@echo "Usage:\n  make [task]"
	@awk '{ \
		if($$0 ~ /^### /){ \
			if(help) printf "%-23s %s\n\n", cmd, help; help=""; \
			printf "\n%s:\n", substr($$0,5); \
		} else if($$0 ~ /^[a-zA-Z0-9._-]+:/){ \
			cmd = substr($$0, 1, index($$0, ":")-1); \
			if(help) printf "  %-23s %s\n", cmd, help; help=""; \
		} else if($$0 ~ /^##/){ \
			help = help ? help "\n                        " substr($$0,3) : substr($$0,3); \
		} else if(help){ \
			print "\n                        " help "\n"; help=""; \
		} \
	}' $(MAKEFILE_LIST)
