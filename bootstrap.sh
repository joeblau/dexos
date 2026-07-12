#!/usr/bin/env bash
# bootstrap.sh — one-shot developer environment setup for DexOS.
#
# Installs everything needed to build the workspace on this machine: the pinned
# Rust toolchain (+ components and the wasm target), the per-OS system libraries
# the Dioxus desktop/mobile frontends link (GTK/webkit on Linux, WebKit on
# macOS), the Dioxus CLI (`dx`), and a full download of the crate dependency
# graph. Idempotent — safe to re-run; it skips anything already present.
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

# ---------------------------------------------------------------------------
# 1. System packages (per OS / distro)
# ---------------------------------------------------------------------------
# The Dioxus *desktop*/*mobile* apps link wry, which needs the platform webview
# and its dev headers. The engine, the CLI, and the wasm *web* app need none of
# this — pass --no-frontend to skip the whole step.
install_system_deps_linux() {
    # Package names differ per distro; keep these lists in lockstep with the
    # apt list in .github/workflows/ci.yml (the `apps` job).
    if have apt-get; then
        info "Debian/Ubuntu (apt-get)"
        $SUDO apt-get update
        $SUDO apt-get install -y --no-install-recommends \
            build-essential pkg-config libssl-dev curl \
            libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
            libgtk-3-dev libsoup-3.0-dev libxdo-dev
    elif have dnf; then
        info "Fedora (dnf)"
        $SUDO dnf install -y \
            gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl \
            webkit2gtk4.1-devel gtk3-devel libsoup3-devel libxdo-devel
    elif have pacman; then
        info "Arch (pacman)"
        $SUDO pacman -Sy --needed --noconfirm \
            base-devel pkgconf openssl curl \
            webkit2gtk-4.1 gtk3 libsoup3 xdotool
    elif have zypper; then
        info "openSUSE (zypper) — best effort"
        $SUDO zypper install -y \
            gcc gcc-c++ make pkg-config libopenssl-devel curl \
            webkit2gtk3-devel gtk3-devel libsoup-devel xdotool
    else
        warn "no supported package manager found (apt/dnf/pacman/zypper)."
        warn "install the GTK3 + webkit2gtk-4.1 + libsoup3 dev packages manually,"
        warn "or re-run with --no-frontend to set up the engine only."
        return 1
    fi
}

install_system_deps() {
    case "$OS" in
        Linux)
            install_system_deps_linux
            ;;
        Darwin)
            info "macOS — desktop uses the system WebKit (WKWebView); no extra libraries needed."
            if ! xcode-select -p >/dev/null 2>&1; then
                info "installing Xcode Command Line Tools (a GUI prompt may appear)…"
                xcode-select --install 2>/dev/null || \
                    warn "could not trigger 'xcode-select --install'; install it manually if compilers are missing."
            else
                info "Xcode Command Line Tools already installed."
            fi
            info "iOS builds additionally require full Xcode from the App Store."
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            warn "Windows detected. Install these manually (no reliable CLI path):"
            warn "  • Visual Studio Build Tools (MSVC + Windows SDK)"
            warn "  • WebView2 Runtime (preinstalled on Windows 11)"
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
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --no-modify-path
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

# ---------------------------------------------------------------------------
# 3. Frontend build prerequisites (wasm target + Dioxus CLI)
# ---------------------------------------------------------------------------
install_frontend_toolchain() {
    # Add wasm32 to the *pinned* toolchain (invoking rustup in-repo respects the
    # override). This is the target the `dexos-web` build uses; a common gotcha
    # is having it on a default toolchain but not the pinned one.
    info "adding wasm32-unknown-unknown target…"
    rustup target add wasm32-unknown-unknown >/dev/null

    # Dioxus CLI (`dx`). Note: the binary name collides with Deno's `deno x`
    # alias, also named `dx`. Detect a real Dioxus dx before deciding to install.
    if have dx && dx --help 2>&1 | grep -qi dioxus; then
        info "Dioxus CLI already installed ($(command -v dx))."
    else
        if have dx; then
            warn "'dx' on PATH is not the Dioxus CLI (likely Deno's 'deno x')."
            warn "installing dioxus-cli into ~/.cargo/bin; ensure it precedes the other 'dx' on PATH."
        fi
        info "installing dioxus-cli (this compiles from source and is slow)…"
        cargo install dioxus-cli --locked
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

if [ "$WANT_FRONTEND" -eq 1 ] && [ "$SKIP_SYSTEM" -eq 0 ]; then
    step "Installing system libraries"
    if ! install_system_deps; then
        warn "system package step did not complete; continuing with Rust setup."
        warn "(re-run with --skip-system once packages are handled, or --no-frontend.)"
    fi
elif [ "$SKIP_SYSTEM" -eq 1 ]; then
    step "Skipping system libraries (--skip-system)"
else
    step "Skipping GUI system libraries (--no-frontend: engine build needs none)"
fi

step "Setting up the Rust toolchain"
install_rust

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
    info "Run the web app:        dx serve --package dexos-web --platform web"
    info "Run the desktop app:    cargo run -p dexos-desktop"
fi
info "Run all PR gates:       ./scripts/preflight.sh"
printf '%s✓ ready%s\n' "$GRN" "$RST"
