#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="${PREFIX}/bin"
INSTALL_SKILL=0

for arg in "$@"; do
  case "$arg" in
    --install-skill) INSTALL_SKILL=1 ;;
    --prefix=*) PREFIX="${arg#*=}"; BIN_DIR="${PREFIX}/bin" ;;
    -h|--help)
      echo "Usage: ./scripts/install.sh [--prefix=/path] [--install-skill]"
      echo "  Builds and installs the single 'assay' release binary to \$PREFIX/bin (default: ~/.local/bin)."
      echo "  --install-skill  Also installs skills/assay/SKILL.md for Claude Code and Codex."
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 64
      ;;
  esac
done

echo "Building Assay (release)..."
cargo build --release --manifest-path "${REPO_ROOT}/Cargo.toml"

mkdir -p "$BIN_DIR"
cp "${REPO_ROOT}/target/release/assay" "${BIN_DIR}/assay"
chmod +x "${BIN_DIR}/assay"
echo "Installed: ${BIN_DIR}/assay ($("${BIN_DIR}/assay" --version))"

if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
  echo "Note: ${BIN_DIR} is not on your PATH. Add: export PATH=\"${BIN_DIR}:\$PATH\""
fi

if [[ "$INSTALL_SKILL" -eq 1 ]]; then
  for skill_root in "$HOME/.claude/skills" "$HOME/.codex/skills"; do
    mkdir -p "${skill_root}/assay"
    cp "${REPO_ROOT}/skills/assay/SKILL.md" "${skill_root}/assay/SKILL.md"
    echo "Installed agent skill: ${skill_root}/assay/SKILL.md"
  done
fi

echo ""
echo "Next steps:"
echo "  Humans: assay explain chalk@6.0.0..6.0.1"
echo "  Repos:  assay init --github --mcp"
