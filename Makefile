GO        ?= go
COVER_MIN ?= 85
FUZZTIME  ?= 30s
PKGS      := ./...

.PHONY: all build test race cover check vet fmt-check fuzz bench demo clean

all: check build

build:
	$(GO) build -o bin/tamperlog ./cmd/tamperlog

vet:
	$(GO) vet $(PKGS)

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race $(PKGS)

# Coverage is measured across all packages (-coverpkg) under the race detector.
cover:
	$(GO) test -race -coverpkg=$(PKGS) -coverprofile=coverage.out $(PKGS)
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	echo "total coverage: $$total% (minimum $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { exit (t+0 < m+0) }' || { echo "coverage below $(COVER_MIN)%"; exit 1; }

# The acceptance gate: formatting, vet, all tests with -race, coverage >= 85%.
check: fmt-check vet cover

FUZZ_TARGETS := \
	./entry:FuzzDecodeEntry \
	./storage:FuzzParseFrame \
	./checkpoint:FuzzDecodeCheckpoint \
	.:FuzzDecodeInclusionBundle \
	.:FuzzDecodeConsistencyBundle

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; fn=$${t##*:}; \
		echo "== $$fn ($$pkg) for $(FUZZTIME)"; \
		$(GO) test $$pkg -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME) || exit 1; \
	done

# Benchmarks run in a disk-backed directory: on tmpfs fsync is a no-op and the
# fsync numbers would be meaningless.
BENCH_DIR ?= $(CURDIR)/.benchtmp
bench:
	@mkdir -p $(BENCH_DIR)
	@echo "bench dir: $(BENCH_DIR) ($$(findmnt -no FSTYPE -T $(BENCH_DIR) 2>/dev/null || echo unknown))"
	TMPDIR=$(BENCH_DIR) $(GO) test -run '^$$' -bench . -benchtime 2s ./bench/

demo: build
	./scripts/demo.sh

clean:
	rm -rf bin coverage.out
