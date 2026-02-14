VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
DIST    := dist

TARGETS := x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin
BINS    := oxmon-agent oxmon-server

# Friendly platform names for release artifacts
define get_friendly_name
$(shell echo "$(1)" | sed \
	-e 's/x86_64-unknown-linux-gnu/x86_64-linux/' \
	-e 's/aarch64-unknown-linux-gnu/aarch64-linux/' \
	-e 's/x86_64-apple-darwin/x86_64-macos/' \
	-e 's/aarch64-apple-darwin/aarch64-macos/')
endef

.PHONY: build test clean release $(TARGETS)

build:
	cargo build --release

test:
	cargo test --workspace

clean:
	cargo clean
	rm -rf $(DIST)

# --- Cross-compilation targets ---

x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu:
	cross build --release --target $@

x86_64-apple-darwin aarch64-apple-darwin:
	cargo build --release --target $@

# --- Package a single target: make package TARGET=<triple> ---

TARGET ?=
package:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make package TARGET=<triple>"; exit 1; fi
	@mkdir -p $(DIST)
	@FRIENDLY=$$(echo "$(TARGET)" | sed \
		-e 's/x86_64-unknown-linux-gnu/x86_64-linux/' \
		-e 's/aarch64-unknown-linux-gnu/aarch64-linux/' \
		-e 's/x86_64-apple-darwin/x86_64-macos/' \
		-e 's/aarch64-apple-darwin/aarch64-macos/'); \
	for bin in $(BINS); do \
		src="target/$(TARGET)/release/$$bin"; \
		if [ -f "$$src" ]; then \
			tar czf $(DIST)/$$bin-$(VERSION)-$$FRIENDLY.tar.gz -C target/$(TARGET)/release $$bin; \
			echo "Packaged $(DIST)/$$bin-$(VERSION)-$$FRIENDLY.tar.gz"; \
		fi; \
	done

# --- Build + package all targets ---

release: $(TARGETS)
	@for t in $(TARGETS); do \
		$(MAKE) package TARGET=$$t; \
	done

# --- Docker multi-arch images ---

DOCKER_REGISTRY ?= ghcr.io/your-org
docker-agent:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-f Dockerfile.agent -t $(DOCKER_REGISTRY)/oxmon-agent:$(VERSION) --push .

docker-server:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-f Dockerfile.server -t $(DOCKER_REGISTRY)/oxmon-server:$(VERSION) --push .
