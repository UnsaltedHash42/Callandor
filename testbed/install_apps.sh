#!/bin/bash
# Runs ON the target VM. Installs Homebrew (if absent) then every cask in
# apps.txt. Non-interactive, continue-on-error, disk-guarded. Logs one row per
# cask to install_results.tsv so the corpus is reproducible.
#
# Usage (from the VM, with apps.txt alongside):  ./install_apps.sh [apps.txt]
set -u
APPS="${1:-$(dirname "$0")/apps.txt}"
RESULTS="$(dirname "$0")/install_results.tsv"
MIN_FREE_MB=3000

log() { printf '%s\n' "$*" >&2; }
free_mb() { df -m / | awk 'NR==2{print $4}'; }

# 1. Homebrew
if ! command -v brew >/dev/null 2>&1; then
  log "== installing Homebrew (non-interactive) =="
  NONINTERACTIVE=1 /bin/bash -c \
    "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
    || { log "Homebrew install failed"; exit 1; }
fi
[ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
command -v brew >/dev/null 2>&1 || { log "brew not on PATH after install"; exit 1; }
log "brew: $(brew --version | head -1)"

# 2. Casks
: > "$RESULTS"
printf 'cask\tstatus\tfree_mb_after\n' >> "$RESULTS"
ok=0; fail=0; skip=0
while IFS= read -r raw; do
  cask="${raw%%#*}"; cask="$(echo "$cask" | xargs)"
  [ -z "$cask" ] && continue

  free="$(free_mb)"
  if [ "$free" -lt "$MIN_FREE_MB" ]; then
    log "DISK GUARD: ${free}MB free (< ${MIN_FREE_MB}) — skipping rest"
    printf '%s\tskip-lowdisk\t%s\n' "$cask" "$free" >> "$RESULTS"; skip=$((skip+1)); continue
  fi

  if brew list --cask "$cask" >/dev/null 2>&1; then
    log "[have] $cask"; printf '%s\talready\t%s\n' "$cask" "$(free_mb)" >> "$RESULTS"; ok=$((ok+1)); continue
  fi

  log "[install] $cask  (free ${free}MB)"
  if brew install --cask "$cask" >/dev/null 2>&1; then
    log "  ok"; printf '%s\tok\t%s\n' "$cask" "$(free_mb)" >> "$RESULTS"; ok=$((ok+1))
  else
    log "  FAILED (EULA/sudo/unavailable)"; printf '%s\tfail\t%s\n' "$cask" "$(free_mb)" >> "$RESULTS"; fail=$((fail+1))
  fi
  # Drop the cached download so peak disk stays near the installed footprint.
  brew cleanup "$cask" >/dev/null 2>&1 || true
done < "$APPS"
brew cleanup -s >/dev/null 2>&1 || true

log ""
log "== done: $ok ok, $fail failed, $skip skipped — free $(free_mb)MB =="
log "results: $RESULTS"
