#!/usr/bin/env bash
# bootstrap.sh — one-shot developer environment setup for DexOS.
#
# Installs everything needed to build the workspace on this machine: the base C
# build toolchain, the pinned Rust toolchain (+ components and the wasm target),
# the per-OS GUI libraries the Dioxus desktop/mobile frontends link (GTK/webkit
# on Linux, system WebKit on macOS), the Dioxus CLI (`dx`), and a full download
# of the crate dependency graph. Idempotent — safe to re-run; it skips anything
# already present.
#
# It sets up the machine to build *natively on the OS it runs on* (Linux, macOS,
# or Windows via Git Bash/MSYS). It does not cross-compile to other OSes; mobile
# targets additionally need the platform SDKs (Xcode / Android SDK), which are
# out of scope here and only flagged.
#
# Usage:
#   ./bootstrap.sh                 # full setup: engine + frontends
#   ./bootstrap.sh --no-frontend   # engine only (skip wasm target, GUI libs, dx)
#   ./bootstrap.sh --dev           # also install CI dev tools (cargo-deny, llvm-cov)
#   ./bootstrap.sh --skip-system   # skip OS package installs (no sudo)
#   ./bootstrap.sh -h | --help
set -euo pipefail
cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
WANT_FRONTEND=1
WANT_DEV=0
SKIP_SYSTEM=0
# Set by install_frontend_toolchain when a non-Dioxus `dx` shadows the CLI on
# PATH; the completion hint then shows the direct-path invocation.
DX_SHADOWED=0
CARGO_DX="${CARGO_HOME:-$HOME/.cargo}/bin/dx"
# Set by check_toolchain_shadow when a non-rustup cargo/rustc wins on PATH.
TOOLCHAIN_SHADOWED=0
for arg in "$@"; do
    case "$arg" in
        --no-frontend) WANT_FRONTEND=0 ;;
        --dev) WANT_DEV=1 ;;
        --skip-system) SKIP_SYSTEM=1 ;;
        -h|--help)
            # Print the leading comment block (everything after the shebang up to
            # the first non-comment line), stripping the leading "# ".
            awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
            exit 0
            ;;
        *)
            echo "unknown option: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
    GRN=$(printf '\033[32m'); YLW=$(printf '\033[33m'); RST=$(printf '\033[0m')
else
    BOLD=""; DIM=""; RED=""; GRN=""; YLW=""; RST=""
fi
step() { printf '\n%s==>%s %s%s%s\n' "$GRN" "$RST" "$BOLD" "$*" "$RST"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$YLW" "$RST" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# `sudo` only when not already root and it exists. On systems without sudo the
# package step tells the user to re-run as root instead of failing opaquely.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then SUDO="sudo"; fi
fi

OS="$(uname -s)"

# How cargo/rustc resolve in the *invoking* shell, captured before install_rust
# may prepend ~/.cargo/bin for this run only. The toolchain-shadow guard checks
# these so it reflects the user's real shells, not the script's transient PATH.
ORIG_CARGO="$(command -v cargo 2>/dev/null || true)"
ORIG_RUSTC="$(command -v rustc 2>/dev/null || true)"

# ---------------------------------------------------------------------------
# 1. System packages (per OS / distro)
# ---------------------------------------------------------------------------
# Split in two: the *base* build toolchain (a C compiler/linker + pkg-config +
# curl) is needed to build **anything** in the workspace — even the engine links
# `ring`, which shells out to `cc` — so it installs on every run. The *GUI* dev
# headers (GTK3 / webkit2gtk / libsoup3 / xdo) are only needed by the Dioxus
# desktop/mobile apps, so they install only when frontends are wanted. Pass
# --no-frontend to skip just the GUI set; --skip-system skips both.
PM=""
detect_pm() {
    for pm in apt-get dnf pacman zypper; do
        if have "$pm"; then PM="$pm"; return 0; fi
    done
    return 1
}

install_base_deps_linux() {
    case "$PM" in
        apt-get) $SUDO apt-get update
                 $SUDO apt-get install -y --no-install-recommends \
                     build-essential pkg-config curl ca-certificates ;;
        dnf)     $SUDO dnf install -y \
                     gcc gcc-c++ make pkgconf-pkg-config curl ca-certificates ;;
        pacman)  $SUDO pacman -Sy --needed --noconfirm \
                     base-devel pkgconf curl ca-certificates ;;
        zypper)  $SUDO zypper install -y \
                     gcc gcc-c++ make pkg-config curl ca-certificates ;;
    esac
}

install_gui_deps_linux() {
    # Kept in lockstep with the apt list in .github/workflows/ci.yml (`apps` job).
    case "$PM" in
        apt-get) $SUDO apt-get install -y --no-install-recommends \
                     libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
                     libgtk-3-dev libsoup-3.0-dev libxdo-dev ;;
        dnf)     $SUDO dnf install -y \
                     webkit2gtk4.1-devel gtk3-devel libsoup3-devel libxdo-devel ;;
        pacman)  $SUDO pacman -Sy --needed --noconfirm \
                     webkit2gtk-4.1 gtk3 libsoup3 xdotool ;;
        zypper)  $SUDO zypper install -y \
                     webkit2gtk3-devel gtk3-devel libsoup-devel xdotool ;;
    esac
}

ensure_xcode_clt() {
    if xcode-select -p >/dev/null 2>&1; then
        info "Xcode Command Line Tools already installed."
    else
        info "installing Xcode Command Line Tools (a GUI prompt may appear)…"
        xcode-select --install 2>/dev/null || \
            warn "could not trigger 'xcode-select --install'; install it manually if compilers are missing."
    fi
}

install_system_deps() {
    case "$OS" in
        Linux)
            if ! detect_pm; then
                warn "no supported package manager (apt/dnf/pacman/zypper) found."
                warn "install a C toolchain + pkg-config manually, plus (for frontends)"
                warn "the GTK3 + webkit2gtk-4.1 + libsoup3 dev packages."
                return 1
            fi
            info "Linux ($PM) — base build toolchain…"
            install_base_deps_linux
            if [ "$WANT_FRONTEND" -eq 1 ]; then
                info "frontend GUI libraries (GTK3 / webkit2gtk-4.1 / libsoup3)…"
                install_gui_deps_linux
            fi
            ;;
        Darwin)
            # The Xcode Command Line Tools provide the base cc/linker; the desktop
            # app uses the system WebKit (WKWebView), so there is no GUI-lib step.
            ensure_xcode_clt
            if [ "$WANT_FRONTEND" -eq 1 ]; then
                info "macOS desktop uses the system WebKit (WKWebView) — no extra libraries."
                info "iOS builds additionally require full Xcode from the App Store."
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            warn "Windows detected. Install these manually (no reliable CLI path):"
            warn "  • Visual Studio Build Tools (MSVC + Windows SDK) — the base toolchain"
            warn "  • WebView2 Runtime (preinstalled on Windows 11) — for the desktop app"
            warn "then re-run with --skip-system to continue with the Rust setup."
            return 1
            ;;
        *)
            warn "unrecognized OS '$OS'; skipping system packages."
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# 2. Rust toolchain (rustup + the pinned channel, components, wasm target)
# ---------------------------------------------------------------------------
install_rust() {
    if ! have rustup; then
        info "rustup not found — installing…"
        # Let rustup add ~/.cargo/bin to the shell profile so `cargo`/`dx` are on
        # PATH in *new* shells; source its env now so the rest of this run sees it.
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
    have rustup || die "rustup install failed; ensure ~/.cargo/bin is on PATH."

    # rust-toolchain.toml pins the channel; `rustup show` inside the repo triggers
    # its install with the declared components/profile.
    info "installing the pinned toolchain (rust-toolchain.toml)…"
    rustup show active-toolchain >/dev/null 2>&1 || true
    rustup show >/dev/null

    info "ensuring rustfmt + clippy…"
    rustup component add rustfmt clippy >/dev/null 2>&1 || true
}

# Warn if a non-rustup cargo/rustc (commonly Homebrew's) shadows the rustup shims
# in the user's shells. Such a toolchain ignores rust-toolchain.toml, so the
# pinned channel — and targets added to it like wasm32 — are NOT used, and web
# builds fail confusingly with "Missing rust target wasm32-unknown-unknown" even
# though `rustup target list` shows it installed. Checked against the pre-install
# resolution (ORIG_*), since install_rust may have prepended ~/.cargo/bin for
# this run only.
check_toolchain_shadow() {
    local rustup_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
    local shadow=""
    case "$ORIG_CARGO" in
        ""|"$rustup_bin"/*) ;;
        *) shadow="$ORIG_CARGO" ;;
    esac
    if [ -z "$shadow" ]; then
        case "$ORIG_RUSTC" in
            ""|"$rustup_bin"/*) ;;
            *) shadow="$ORIG_RUSTC" ;;
        esac
    fi
    [ -z "$shadow" ] && return 0

    TOOLCHAIN_SHADOWED=1
    warn "your shell's cargo/rustc ($shadow) is NOT the rustup shim in $rustup_bin."
    warn "a non-rustup toolchain ignores rust-toolchain.toml, so this repo's pinned"
    warn "channel and its wasm32 target are not used — web builds then fail with"
    warn "\"Missing rust target wasm32-unknown-unknown\". Put ~/.cargo/bin first:"
    warn '    export PATH="$HOME/.cargo/bin:$PATH"'
    warn "add that to your shell rc (after any 'brew shellenv' line), open a new shell,"
    warn "and confirm with: cargo --version   (should NOT say 'Homebrew')."
}

# ---------------------------------------------------------------------------
# 3. Frontend build prerequisites (wasm target + Dioxus CLI)
# ---------------------------------------------------------------------------
install_frontend_toolchain() {
    # Add wasm32 to the *pinned* toolchain (invoking rustup in-repo respects the
    # override). This is the target the `dexos-web` build uses; a common gotcha
    # is having it on a default toolchain but not the pinned one.
    info "adding wasm32-unknown-unknown target…"
    rustup target add wasm32-unknown-unknown >/dev/null

    # Install the Dioxus CLI if the real one isn't already on disk. Detect it by
    # the cargo-installed binary path, NOT `command -v dx`: the name collides with
    # Deno's `dx` (its `deno x` alias), so a `dx` on PATH may be a different tool.
    CARGO_DX="${CARGO_HOME:-$HOME/.cargo}/bin/dx"
    if [ -x "$CARGO_DX" ] && "$CARGO_DX" --version 2>&1 | grep -qi dioxus; then
        info "Dioxus CLI already installed ($CARGO_DX)."
    else
        info "installing dioxus-cli (this compiles from source and is slow)…"
        cargo install dioxus-cli --locked
    fi

    # If a *different* `dx` shadows the Dioxus one on PATH, say exactly how to fix
    # it — a bare `dx serve …` would otherwise run the wrong program.
    if have dx && ! dx --version 2>&1 | grep -qi dioxus; then
        DX_SHADOWED=1
        warn "another 'dx' ($(command -v dx)) shadows the Dioxus CLI at $CARGO_DX."
        warn "put ~/.cargo/bin ahead of it on PATH — add to your shell rc (after any"
        warn "'brew shellenv' line), then open a new shell:"
        warn '    export PATH="$HOME/.cargo/bin:$PATH"'
        warn "or invoke the Dioxus CLI directly: $CARGO_DX serve --package dexos-web --platform web"
    fi
}

# ---------------------------------------------------------------------------
# 4. Optional CI dev tools
# ---------------------------------------------------------------------------
install_dev_tools() {
    info "adding llvm-tools-preview (coverage)…"
    rustup component add llvm-tools-preview >/dev/null 2>&1 || true
    for tool in cargo-deny cargo-llvm-cov; do
        if have "$tool"; then
            info "$tool already installed."
        else
            info "installing $tool…"
            cargo install "$tool" --locked
        fi
    done
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
printf '%sDexOS bootstrap%s — OS=%s frontend=%s dev=%s\n' \
    "$BOLD" "$RST" "$OS" "$WANT_FRONTEND" "$WANT_DEV"

if [ "$SKIP_SYSTEM" -eq 1 ]; then
    step "Skipping system packages (--skip-system)"
else
    if [ "$WANT_FRONTEND" -eq 1 ]; then
        step "Installing system packages (base toolchain + frontend GUI libraries)"
    else
        step "Installing system packages (base toolchain — GUI libs skipped via --no-frontend)"
    fi
    if ! install_system_deps; then
        warn "system package step did not complete; continuing with Rust setup."
        warn "(handle the packages manually, then re-run with --skip-system.)"
    fi
fi

step "Setting up the Rust toolchain"
install_rust
check_toolchain_shadow

if [ "$WANT_FRONTEND" -eq 1 ]; then
    step "Setting up the frontend toolchain (wasm target + Dioxus CLI)"
    install_frontend_toolchain
fi

if [ "$WANT_DEV" -eq 1 ]; then
    step "Installing CI dev tools"
    install_dev_tools
fi

step "Downloading crate dependencies"
info "cargo fetch --locked (whole workspace graph)…"
cargo fetch --locked

step "Bootstrap complete"
info "Verify the engine:      cargo build --locked"
if [ "$WANT_FRONTEND" -eq 1 ]; then
    info "Verify the web app:     cargo build -p dexos-web --target wasm32-unknown-unknown --locked"
    if [ "$DX_SHADOWED" -eq 1 ]; then
        info "Run the web app:        $CARGO_DX serve --package dexos-web --platform web"
        info "                        (a different 'dx' shadows it — see the PATH note above)"
    else
        info "Run the web app:        dx serve --package dexos-web --platform web"
    fi
    info "Run the desktop app:    cargo run -p dexos-desktop"
fi
info "Run all PR gates:       ./scripts/preflight.sh"
if [ "$TOOLCHAIN_SHADOWED" -eq 1 ] || [ "$DX_SHADOWED" -eq 1 ]; then
    warn "ACTION NEEDED: a non-rustup toolchain and/or a foreign 'dx' shadow the"
    warn "rustup binaries on your PATH (details above). Until you put ~/.cargo/bin"
    warn "first and open a new shell, builds may fail with \"Missing rust target\"."
    warn "    export PATH=\"\$HOME/.cargo/bin:\$PATH\""
elif ! have cargo; then
    info "PATH: open a new shell (or 'source \"\$HOME/.cargo/env\"') so cargo/dx resolve."
fi
printf '%s✓ ready%s\n' "$GRN" "$RST"
