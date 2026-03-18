# Makefile for walrus-go-ffi
#
# Targets:
#   make rust         – Build the Rust static library (release)
#   make rust-debug   – Build the Rust static library (debug)
#   make go-test      – Run Go tests (requires rust target to exist)
#   make go-build     – Build the example binary
#   make clean        – Remove build artefacts
#   make all          – rust + go-build

RUST_DIR      := walrus-bridge
GO_DIR        := ./
EXAMPLE_DIR   := ./example
LIB_NAME      := libwalrus_go_ffi.a
RUST_RELEASE  := $(RUST_DIR)/target/release/$(LIB_NAME)
RUST_DEBUG    := $(RUST_DIR)/target/debug/$(LIB_NAME)
LIB_DST       := $(GO_DIR)/$(LIB_NAME)

.PHONY: all rust rust-debug go-build go-test clean

all: rust go-build

# ── Rust ──────────────────────────────────────────────────────────────────────

rust:
	cd $(RUST_DIR) && CXXFLAGS="-include cstdint" JEMALLOC_NODEPS=1 cargo build --release
	cp $(RUST_RELEASE) $(LIB_DST)
	@echo "✓  Static library → $(LIB_DST)"

rust-debug:
	cd $(RUST_DIR) && cargo build
	cp $(RUST_DEBUG) $(LIB_DST)
	@echo "✓  Static library (debug) → $(LIB_DST)"

# ── Go ────────────────────────────────────────────────────────────────────────

go-build: $(LIB_DST)
	cd $(EXAMPLE_DIR) && CGO_LDFLAGS="-L. -lwalrus_go_ffi -lstdc++ -ldl -lpthread -lm" go build -v ./...
	@echo "✓  Example binary built"

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	cd $(RUST_DIR) && cargo clean
	rm -f $(LIB_DST)
	rm -f $(EXAMPLE_DIR)/example

# ── Useful diagnostics ────────────────────────────────────────────────────────

symbols:
	nm -gU $(LIB_DST) | grep walrus_
