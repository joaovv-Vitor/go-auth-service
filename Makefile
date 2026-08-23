GO ?= go
DIST ?= dist
GOOS ?= linux
GOARCH ?= amd64

GO_BUILD_FLAGS := -trimpath -buildvcs=false -mod=readonly
GO_LDFLAGS := -buildid=

.PHONY: build checksums verify-reproducible verify-container

build:
	mkdir -p "$(DIST)"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GO_BUILD_FLAGS) -ldflags="$(GO_LDFLAGS)" -o "$(DIST)/auth-service" ./cmd/api
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GO_BUILD_FLAGS) -ldflags="$(GO_LDFLAGS)" -o "$(DIST)/migrate" ./cmd/migrate

checksums: build
	cd "$(DIST)" && sha256sum auth-service migrate > SHA256SUMS

verify-reproducible:
	@first_dir="$$(mktemp -d)"; \
	second_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$first_dir" "$$second_dir"' EXIT; \
	$(MAKE) --no-print-directory build DIST="$$first_dir" >/dev/null; \
	$(MAKE) --no-print-directory build DIST="$$second_dir" >/dev/null; \
	cmp "$$first_dir/auth-service" "$$second_dir/auth-service"; \
	cmp "$$first_dir/migrate" "$$second_dir/migrate"; \
	(cd "$$first_dir" && sha256sum auth-service migrate)

verify-container:
	@first_image="$$(mktemp --suffix=.oci.tar)"; \
	second_image="$$(mktemp --suffix=.oci.tar)"; \
	source_date_epoch="$$(git log -1 --format=%ct)"; \
	trap 'rm -f "$$first_image" "$$second_image"' EXIT; \
	docker buildx build --no-cache --provenance=false --sbom=false \
		--build-arg SOURCE_DATE_EPOCH="$$source_date_epoch" \
		--output "type=oci,dest=$$first_image,rewrite-timestamp=true" . >/dev/null; \
	docker buildx build --no-cache --provenance=false --sbom=false \
		--build-arg SOURCE_DATE_EPOCH="$$source_date_epoch" \
		--output "type=oci,dest=$$second_image,rewrite-timestamp=true" . >/dev/null; \
	cmp "$$first_image" "$$second_image"; \
	sha256sum "$$first_image"
