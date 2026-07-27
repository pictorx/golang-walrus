# Makefile for walrus-sui-ffi
#
# Targets:
#   make rust              – Build Rust static library (release, host linux/amd64)
#   make rust-debug        – Build Rust static library (debug, host)
#   make rust-android      – Build Rust static library for Android arm64
#   make stage-android     – Stage libc++_static.a / libc++abi.a from NDK
#                            into project root for cgo to find at link time
#   make package-android    – rust-android + stage-android + fyne-cross, in the
#                            correct order, in one command. See the
#                            "Android packaging" section below.
#   make font              – Subset CreatoDisplay-Regular.otf down to a broad
#                            Latin+punctuation+currency Unicode range (see
#                            the "Font subsetting" section below for why)
#   make build              – PRODUCTION Go build. No pprof, stripped debug
#                            symbols (-ldflags="-s -w"). The only target
#                            that should ever be packaged/shipped.
#   make build-debug        – DEVELOPMENT/PROFILING Go build. Embeds
#                            net/http/pprof (-tags pprof). Never distribute
#                            a binary built with this target.
#   make verify-no-pprof    – Fails loudly if pprof symbols are found in the
#                            production binary. Run automatically by `make
#                            build`; safe to run standalone too.
#   make clean             – Remove build artefacts and staged libs
#   make symbols           – List exported symbols in host static library
#   make symbols-android   – List exported symbols in Android static library
#   make check-android-ndk – Verify NDK linker is present
#
# Android prerequisites:
#   1. rustup target add aarch64-linux-android
#   2. NDK_HOME set, e.g.:
#        export NDK_HOME=$$HOME/Android/Sdk/ndk/30.0.14904198
#
# The Rust crate lives in ./walrus-bridge (Cargo.toml is there, not at the
# project root — see WALRUS_BRIDGE_DIR below).
# Header: walrus_go_ffi.h.
#
# Output libraries:
#   Linux  : walrus-bridge/target/release/libwalrus_go_ffi.a
#   Android: walrus-bridge/target/aarch64-linux-android/release/libwalrus_go_ffi.a

LIB_NAME      := libwalrus_go_ffi.a

# The Rust crate lives in ./walrus-bridge, not the project root — every
# cargo invocation below must cd into it first, and every output path must
# be prefixed with it. (Previously missing entirely, causing "could not
# find Cargo.toml" errors when running `make rust` from the project root.)
WALRUS_BRIDGE_DIR := walrus-bridge

LIB_LINK_NAME := $(LIB_NAME:lib%.a=%)

APP_NAME      := app

# ── Android packaging ─────────────────────────────────────────────────────
APP_ID := com.pictorx.pictorx
ICON   := ./Icon.png

# ── Font subsetting (R6-M-2) ──────────────────────────────────────────────
# Cuts CreatoDisplay-Regular.otf down to a broad-but-safe Unicode range instead
# of scanning source code for exact strings — no manual re-running required when
# UI copy changes, and it robustly covers arbitrary user-uploaded filenames
# (Western European languages, accents, punctuation, currency) without needing
# to know what those filenames actually are ahead of time.
#
# The $(FONT_SUBSET): $(FONT_SRC) dependency line means `make` only re-runs
# pyftsubset when the source font file itself changes (checked via file
# mtime) — on every other build this target is a no-op, so there is no
# ongoing cost to keeping this wired into the default build path.
#
# Unicode ranges included:
#   U+0020–024F  Basic Latin + Latin-1 Supplement + Latin Extended-A/B
#                (covers English, French, German, Spanish, Portuguese,
#                Nordic languages, Polish, Czech, and most Western
#                European filenames/accented characters)
#   U+2000–206F  General Punctuation (em/en dash, ellipsis, curly quotes)
#   U+20A0–20CF  Currency symbols (€, £, ¥, etc.)
#
# Deliberately NOT included (safe to cut for this app): Cyrillic, Greek,
# Arabic, Hebrew, CJK, Devanagari and other non-Latin scripts; math
# operators; the font's likely large set of stylistic alternates,
# ligatures, and small-caps variants that a professional display font
# ships with but this app never invokes via any OpenType feature.
#
# Requires: fonttools (pyftsubset) and fyne CLI (fyne bundle)
FONT_SRC    := CreatoDisplay-Regular.otf
FONT_SUBSET := CreatoDisplay-Regular.subset.otf
FONT_BUNDLE := bundled_font.go

# ── Library output paths ──────────────────────────────────────────────────────
RUST_RELEASE  := $(WALRUS_BRIDGE_DIR)/target/release/$(LIB_NAME)
RUST_DEBUG    := $(WALRUS_BRIDGE_DIR)/target/debug/$(LIB_NAME)

# ── Android configuration ─────────────────────────────────────────────────────
ANDROID_API      := 21
NDK_HOME         ?= $(ANDROID_NDK_HOME)
NDK_TOOLCHAIN    := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin
NDK_SYSROOT      := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot
NDK_ARM64_LIBDIR := $(NDK_SYSROOT)/usr/lib/aarch64-linux-android

ARM64_TARGET  := aarch64-linux-android
ARM64_LINKER  := $(NDK_TOOLCHAIN)/$(ARM64_TARGET)$(ANDROID_API)-clang
ARM64_OUT     := $(WALRUS_BRIDGE_DIR)/target/$(ARM64_TARGET)/release/$(LIB_NAME)

.PHONY: all rust rust-debug rust-android stage-android package-android font \
        build build-debug verify-no-pprof \
        clean symbols symbols-android check-android-ndk

all: rust

# ── Font subset + Fyne bundle ─────────────────────────────────────────────────

$(FONT_SUBSET): $(FONT_SRC)
	pyftsubset $(FONT_SRC) \
		--output-file=$(FONT_SUBSET) \
		--unicodes="U+0020-024F,U+2000-206F,U+20A0-20CF" \
		--layout-features='*' \
		--glyph-names \
		--symbol-cmap \
		--legacy-cmap \
		--notdef-glyph \
		--notdef-outline \
		--recommended-glyphs \
		--name-IDs='*' \
		--name-legacy \
		--name-languages='*'

$(FONT_BUNDLE): $(FONT_SUBSET)
	fyne bundle -o $(FONT_BUNDLE) $(FONT_SUBSET)

font: $(FONT_BUNDLE)

# ── Go application build ──────────────────────────────────────────────────
#
# CGO_LDFLAGS is shared between both targets so the two builds never link
# against different libraries by accident.
GO_CGO_LDFLAGS := -L. -l$(LIB_LINK_NAME) -lstdc++ -ldl -lpthread -lm

# PRODUCTION build. No pprof, stripped debug symbols (-s -w, ~15-20%
# smaller binary). Depends on `font`, so the subsetted font resource is
# always regenerated (or confirmed already up to date — the font target is
# a no-op unless the source .otf changed) before every build. This is the
# ONLY target that should ever be packaged or distributed to end users.
build: font
	CGO_LDFLAGS="$(GO_CGO_LDFLAGS)" go build -ldflags="-s -w" -o $(APP_NAME) .
	@$(MAKE) --no-print-directory verify-no-pprof
	@echo "✓  Production build → ./$(APP_NAME)  (no pprof, stripped)"

# DEVELOPMENT / PROFILING build only. Embeds net/http/pprof endpoints on
# localhost:6060 (see profiling.go's //go:build pprof guard). This is what
# every profiling round in this project's audit history has been built
# with — never ship a binary built with this target.
build-debug: font
	CGO_LDFLAGS="$(GO_CGO_LDFLAGS)" go build -tags pprof -o $(APP_NAME)-debug .
	@echo "⚠  Debug build (pprof ENABLED) → ./$(APP_NAME)-debug — development/profiling use only, do not distribute"

# Safety net: fails loudly if pprof symbols somehow ended up in the
# production binary — e.g. someone runs `go build -tags pprof` directly out
# of habit instead of using `make build`. Run automatically at the end of
# `make build`; safe to run standalone against any binary too, e.g.:
#   make verify-no-pprof APP_NAME=some-other-binary
verify-no-pprof:
	@if [ ! -f "$(APP_NAME)" ]; then \
	  echo "✗  $(APP_NAME) not found — run 'make build' first"; exit 1; \
	fi
	@if ! command -v strings >/dev/null 2>&1; then \
	  echo "⚠  'strings' not found — skipping pprof check. Install binutils to enable this safety net."; \
	  exit 0; \
	fi
	@if strings "$(APP_NAME)" 2>/dev/null | grep -qi "net/http/pprof"; then \
	  echo "✗  pprof symbols found in $(APP_NAME) — THIS MUST NOT BE SHIPPED."; \
	  echo "   Rebuild with 'make build' (not build-debug, and not a manual"; \
	  echo "   'go build -tags pprof') to produce a clean production binary."; \
	  exit 1; \
	fi
	@echo "✓  Verified: no pprof symbols in $(APP_NAME)"

# Wire `build` (not `all`) as the app build target on purpose: `all` in this
# Makefile has always meant "build the Rust static library" (all: rust,
# below) and existing scripts/CI may depend on `make`/`make all` doing only
# that. If you'd rather `make`/`make all` build the whole app end-to-end
# (Rust lib + font + Go binary) in one shot, change `all: rust` to
# `all: rust build` — left as a deliberate choice rather than done silently.

# ── Rust (host linux/amd64) ───────────────────────────────────────────────────

rust:
	cd $(WALRUS_BRIDGE_DIR) && CXXFLAGS="-include cstdint" JEMALLOC_NODEPS=1 cargo build --release
	@echo "✓  Static library (host) → $(RUST_RELEASE)"

rust-debug:
	cd $(WALRUS_BRIDGE_DIR) && CXXFLAGS="-include cstdint" JEMALLOC_NODEPS=1 cargo build
	@echo "✓  Static library (debug) → $(RUST_DEBUG)"

# ── Rust (Android arm64) ──────────────────────────────────────────────────────
#
# Builds libwalrus_go_ffi.a for aarch64-linux-android.
#
# After a successful build, run `make stage-android` to copy libc++_static.a
# and libc++abi.a from the NDK sysroot into the project root — walrus.go's
# #cgo android LDFLAGS line references them via plain "-L. -lc++_static
# -lc++abi" (not ${SRCDIR}), which resolves relative to the build's current
# working directory at link time. That only works if libc++_static.a/
# libc++abi.a actually exist at the project root when the link happens —
# which is exactly what stage-android is for. Both fyne-cross's Docker
# container and a plain host build run from the project root, so this
# resolves correctly in both cases as long as stage-android has been run
# first. `make package-android` below runs both steps for you, in order.

rust-android: check-android-ndk
	@echo "→  Building aarch64-linux-android (API $(ANDROID_API))"
	cd $(WALRUS_BRIDGE_DIR) && \
	  CXXFLAGS="-include cstdint" JEMALLOC_NODEPS=1 \
	  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$(ARM64_LINKER)" \
	  CC_aarch64_linux_android="$(ARM64_LINKER)" \
	  CXX_aarch64_linux_android="$(NDK_TOOLCHAIN)/aarch64-linux-android$(ANDROID_API)-clang++" \
	  AR_aarch64_linux_android="$(NDK_TOOLCHAIN)/llvm-ar" \
	  CFLAGS_aarch64_linux_android="--sysroot=$(NDK_SYSROOT)" \
	  CXXFLAGS_aarch64_linux_android="--sysroot=$(NDK_SYSROOT)" \
	  BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=$(NDK_SYSROOT) -target aarch64-linux-android$(ANDROID_API)" \
	  cargo build --release --target $(ARM64_TARGET)
	@echo "✓  arm64-v8a → $(ARM64_OUT)"

# ── Stage NDK C++ libs ────────────────────────────────────────────────────────
#
# Copies libc++_static.a and libc++abi.a from the NDK sysroot into the project
# root so that the cgo LDFLAGS in walrus.go (${SRCDIR}/libc++_static.a) resolve
# at link time on both the host and inside the fyne-cross Docker container.
#
# Run once after rust-android and before packaging with fyne-cross.
# The files are removed by `make clean`.

stage-android: check-android-ndk
	@echo "→  Staging libc++ static libs from NDK into project root"
	cp $(NDK_ARM64_LIBDIR)/libc++_static.a ./libc++_static.a
	cp $(NDK_ARM64_LIBDIR)/libc++abi.a     ./libc++abi.a
	@echo "✓  Staged:"
	@echo "     ./libc++_static.a"
	@echo "     ./libc++abi.a"

# ── Android packaging ─────────────────────────────────────────────────────
#
# Runs the full Android build chain in the correct order:
#   1. rust-android  – builds walrus-bridge/target/aarch64-linux-android/
#                      release/libwalrus_go_ffi.a
#   2. stage-android – copies libc++_static.a/libc++abi.a to project root
#                      (see the note on rust-android above for why this is
#                      required, not optional — it was silently being
#                      skipped before, which is exactly the kind of gap
#                      that produces a link failure with no obvious cause)
#   3. fyne-cross android – packages the .apk
#
# IMPORTANT: walrus.go's own "#cgo android LDFLAGS:" line already fully
# specifies everything needed to link the Android build correctly:
#
#   -Lwalrus-bridge/target/aarch64-linux-android/release -lwalrus_go_ffi \
#   -L. -lc++_static -lc++abi -ldl -lm
#
# Do NOT also pass a manual CGO_LDFLAGS env var for this command — an
# earlier manual override (-L. -lwalrus_go_ffi -lstdc++ -ldl -lm) pointed
# at the library's OLD location (project root, before the crate moved into
# walrus-bridge/) and used the wrong C++ runtime for Android (-lstdc++
# instead of the NDK's -lc++_static/-lc++abi). Since CGO_LDFLAGS and the
# #cgo directive are both applied together, a stale override doesn't
# replace the correct directive — it just adds wrong/conflicting flags
# alongside it. Letting the #cgo line in walrus.go do all the work, with
# no override, is both correct and simpler.
package-android: check-android-ndk rust-android stage-android
	fyne package -os android/arm64 -app-id $(APP_ID) $(ICON)
	@echo "✓  Android package built via fyne (app-id: $(APP_ID))"

# ── NDK preflight check ───────────────────────────────────────────────────────

check-android-ndk:
	@if [ -z "$(NDK_HOME)" ]; then \
	  echo "✗  NDK_HOME is not set."; \
	  echo "   export NDK_HOME=\$$HOME/Android/Sdk/ndk/30.0.14904198"; \
	  exit 1; \
	fi
	@if [ ! -f "$(ARM64_LINKER)" ]; then \
	  echo "✗  NDK linker not found at: $(ARM64_LINKER)"; \
	  echo "   Check NDK_HOME and ANDROID_API (currently $(ANDROID_API))."; \
	  exit 1; \
	fi
	@echo "✓  NDK linker: $(ARM64_LINKER)"

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	cd $(WALRUS_BRIDGE_DIR) && cargo clean
	rm -f ./libc++_static.a ./libc++abi.a
	rm -f $(FONT_SUBSET) $(FONT_BUNDLE)
	rm -f ./$(APP_NAME) ./$(APP_NAME)-debug
	@echo "✓  Build artefacts removed"

# ── Diagnostics ───────────────────────────────────────────────────────────────

# List all exported symbols in the host static library.
symbols:
	@if [ ! -f "$(RUST_RELEASE)" ]; then \
	  echo "✗  $(RUST_RELEASE) not found — run 'make rust' first"; exit 1; \
	fi
	nm -gU $(RUST_RELEASE) 2>/dev/null || nm --defined-only --extern-only $(RUST_RELEASE)

# List all exported symbols in the Android arm64 static library.
symbols-android:
	@if [ ! -f "$(ARM64_OUT)" ]; then \
	  echo "✗  $(ARM64_OUT) not found — run 'make rust-android' first"; exit 1; \
	fi
	@if [ -n "$(NDK_HOME)" ] && [ -f "$(NDK_TOOLCHAIN)/llvm-nm" ]; then \
	  echo "→  Using NDK llvm-nm"; \
	  $(NDK_TOOLCHAIN)/llvm-nm --defined-only --extern-only $(ARM64_OUT); \
	else \
	  echo "→  Falling back to host nm"; \
	  nm -g $(ARM64_OUT); \
	fi
