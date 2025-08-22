#!/usr/bin/env bash
#===============================================================================
# File: /usr/local/sbin/remove-cisco-agent.sh
# Purpose: Stop/disable Cisco agent services and move /opt/cisco -> /tmp,
#          with safety flags, timestamped logging, interactive confirmation,
#          unit-style checks and rollback support.
#===============================================================================
# Exit codes:
#   0   Success
#   1   Generic/unknown error
#   2   Not running as root
#   3   User aborted
#   4   Missing dependency (systemctl)
#   5   Source directory missing (/opt/cisco not present)
#  10   Failed to stop/disable service
#  11   Failed to move directory
#  12   Failed to restore during rollback
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

#-----------------------------------------------
# Timestamped logging to file + stdout
#-----------------------------------------------
TS="$(date +"%Y-%m-%d_%H-%M-%S")"
LOG_FILE="${TMPDIR:-/tmp}/remove-cisco-agent_${TS}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

#-----------------------------------------------
# Colors and log helpers
#-----------------------------------------------
GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"; BLUE="\033[1;34m"; NC="\033[0m"
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }

#-----------------------------------------------
# Configuration (services & paths)
#-----------------------------------------------
SERVICES=(vpnagentd.service ds_agent.service dcservice.service)
SRC_DIR="/opt/cisco"
DEST_DIR="/tmp"
MOVED_NAME=""         # will hold final moved path, e.g. /tmp/cisco_2025-08-22_12-00-00
AUTO_YES=false
ROLLBACK_ON_ERROR=true

#-----------------------------------------------
# Usage/help
#-----------------------------------------------
usage() {
  cat <<EOF
Usage: $0 [options]

Stops/disables services and moves ${SRC_DIR} -> ${DEST_DIR} with rollback support.

Options:
  --yes            Non-interactive; assume 'yes' to confirmation prompt
  --no-rollback    Do not attempt rollback on failure (keeps partial state)
  --help           Show this help

Notes:
  - Must be run as root (sudo).
  - Logs written to: $LOG_FILE
EOF
}

#-----------------------------------------------
# Parse args
#-----------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) AUTO_YES=true; shift ;;
    --no-rollback) ROLLBACK_ON_ERROR=false; shift ;;
    --help) usage; exit 0 ;;
    *) log_error "Unknown option: $1"; usage; exit 1 ;;
  esac
done

#-----------------------------------------------
# Root & dependency checks
#-----------------------------------------------
require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    log_error "This script must be run as root (sudo)."
    exit 2
  fi
}
require_systemctl() {
  if ! command -v systemctl >/dev/null 2>&1; then
    log_error "systemctl not found; cannot manage services on this system."
    exit 4
  fi
}
require_root
require_systemctl

#-----------------------------------------------
# State tracking for rollback
#    - SERVICE_STATES is associative: service -> "active|inactive;enabled|disabled|unknown"
#    - MOVED flag indicates we moved SRC_DIR and dest path
#-----------------------------------------------
declare -A SERVICE_PREV_ACTIVE=()   # service -> "active" or "inactive" or "unknown"
declare -A SERVICE_PREV_ENABLED=()  # service -> "enabled" or "disabled" or "unknown"
MOVED=false

#-----------------------------------------------
# Cleanup temp files at exit
#-----------------------------------------------
_tmpfile="$(mktemp)"
cleanup_temp() { rm -f "$_tmpfile" || true; }
trap cleanup_temp EXIT

#-----------------------------------------------
# Rollback function
#-----------------------------------------------
rollback() {
  log_warn "Attempting rollback..."
  local any_err=false

  # Move directory back if we moved it
  if [[ "$MOVED" == true && -n "$MOVED_NAME" && -e "$MOVED_NAME" ]]; then
    log_info "Restoring directory ${MOVED_NAME} -> ${SRC_DIR}"
    if mv "$MOVED_NAME" "$SRC_DIR"; then
      log_ok "Restored ${SRC_DIR}"
    else
      log_error "Failed to restore ${SRC_DIR} from ${MOVED_NAME}"
      any_err=true
    fi
  else
    log_info "No moved directory to restore (MOVED=${MOVED}, MOVED_NAME='${MOVED_NAME}')."
  fi

  # Restore services (enable/start according to prior state)
  for svc in "${SERVICES[@]}"; do
    prev_act="${SERVICE_PREV_ACTIVE[$svc]:-unknown}"
    prev_en="${SERVICE_PREV_ENABLED[$svc]:-unknown}"
    log_info "Restoring service ${svc}: was_active='${prev_act}', was_enabled='${prev_en}'"

    # Start service if it was active before
    if [[ "${prev_act}" == "active" ]]; then
      log_info "Starting ${svc}"
      if systemctl start "$svc"; then
        log_ok "Started ${svc}"
      else
        log_error "Failed to start ${svc}"
        any_err=true
      fi
    fi

    # Enable/disable as it was before
    if [[ "${prev_en}" == "enabled" ]]; then
      log_info "Enabling ${svc}"
      if systemctl enable "$svc" >/dev/null 2>&1; then
        log_ok "Enabled ${svc}"
      else
        log_error "Failed to enable ${svc}"
        any_err=true
      fi
    elif [[ "${prev_en}" == "disabled" ]]; then
      log_info "Disabling ${svc}"
      if systemctl disable "$svc" >/dev/null 2>&1; then
        log_ok "Disabled ${svc}"
      else
        log_error "Failed to disable ${svc}"
        any_err=true
      fi
    fi
  done

  if [[ "$any_err" == true ]]; then
    log_error "Rollback completed with errors."
    return 1
  else
    log_ok "Rollback completed successfully."
    return 0
  fi
}

#-----------------------------------------------
# Error/signal handling
#-----------------------------------------------
on_error() {
  local exitcode=$?
  local lineno=${1:-?}
  local cmd=${2:-?}
  log_error "Error (exit ${exitcode}) at line ${lineno}: ${cmd}"
  if $ROLLBACK_ON_ERROR; then
    rollback || log_error "Rollback failed; manual cleanup may be required."
  else
    log_warn "Rollback disabled (--no-rollback); leaving partial state."
  fi
  exit "$exitcode"
}
trap 'on_error "${LINENO}" "${BASH_COMMAND}"' ERR
trap 'log_warn "Interrupted by user (SIGINT)"; $ROLLBACK_ON_ERROR && rollback; exit 130' INT
trap 'log_warn "Terminated (SIGTERM)"; $ROLLBACK_ON_ERROR && rollback; exit 143' TERM

#-----------------------------------------------
# Helpers: service checks, stop/disable, move dir
#-----------------------------------------------
service_exists() {
  local s=$1
  systemctl list-unit-files --type=service --no-pager --no-legend | awk '{print $1}' | grep -qx "$s"
}

capture_service_state() {
  local s=$1
  # capture active state
  if systemctl is-active --quiet "$s" 2>/dev/null; then
    SERVICE_PREV_ACTIVE["$s"]="active"
  else
    # if unit exists but inactive, mark inactive; if unknown, mark unknown
    if service_exists "$s"; then
      SERVICE_PREV_ACTIVE["$s"]="inactive"
    else
      SERVICE_PREV_ACTIVE["$s"]="unknown"
    fi
  fi
  # capture enabled state
  if systemctl is-enabled --quiet "$s" 2>/dev/null; then
    SERVICE_PREV_ENABLED["$s"]="enabled"
  else
    if service_exists "$s"; then
      SERVICE_PREV_ENABLED["$s"]="disabled"
    else
      SERVICE_PREV_ENABLED["$s"]="unknown"
    fi
  fi
  log_info "Service ${s} prior state: active='${SERVICE_PREV_ACTIVE[$s]}', enabled='${SERVICE_PREV_ENABLED[$s]}'"
}

stop_and_disable_service() {
  local s=$1
  # Only attempt if service exists
  if ! service_exists "$s"; then
    log_warn "Service ${s} not found on this host; skipping stop/disable."
    return 0
  fi

  capture_service_state "$s"

  # Stop (if active)
  if [[ "${SERVICE_PREV_ACTIVE[$s]}" == "active" ]]; then
    log_info "Stopping ${s}"
    if systemctl stop "$s"; then
      # verify
      if systemctl is-active --quiet "$s"; then
        log_error "Failed to stop ${s}"
        return 10
      else
        log_ok "Stopped ${s}"
      fi
    else
      log_error "systemctl stop ${s} returned non-zero"
      return 10
    fi
  else
    log_info "Service ${s} not active; no need to stop."
  fi

  # Disable (if enabled)
  if [[ "${SERVICE_PREV_ENABLED[$s]}" == "enabled" ]]; then
    log_info "Disabling ${s}"
    if systemctl disable "$s" >/dev/null 2>&1; then
      # verify
      if systemctl is-enabled --quiet "$s"; then
        log_error "Failed to disable ${s}"
        return 10
      else
        log_ok "Disabled ${s}"
      fi
    else
      log_error "systemctl disable ${s} returned non-zero"
      return 10
    fi
  else
    log_info "Service ${s} not enabled; no need to disable."
  fi

  return 0
}

move_directory() {
  local src=$1 dest_dir=$2
  if [[ ! -d "$src" ]]; then
    log_error "Source directory ${src} does not exist."
    return 5
  fi
  # Create destination directory if needed
  if [[ ! -d "$dest_dir" ]]; then
    log_info "Creating destination directory ${dest_dir}"
    mkdir -p "$dest_dir"
  fi
  # Choose final name with timestamp to avoid collision
  local base="$(basename "$src")"
  local dest="${dest_dir}/${base}_${TS}"
  log_info "Moving ${src} -> ${dest}"
  if mv "$src" "$dest"; then
    MOVED=true
    MOVED_NAME="$dest"
    # unit check: ensure src no longer exists and dest exists
    if [[ -d "$dest" && ! -e "$src" ]]; then
      log_ok "Moved ${src} -> ${dest}"
      return 0
    else
      log_error "Move appeared to fail (post-check)."
      return 11
    fi
  else
    log_error "mv failed for ${src} -> ${dest}"
    return 11
  fi
}

#-----------------------------------------------
# Confirm action (interactive unless --yes)
#-----------------------------------------------
if ! $AUTO_YES; then
  cat <<-MSG
	This will perform the following actions:
	  - Stop & disable: ${SERVICES[*]}
	  - Move: ${SRC_DIR} -> ${DEST_DIR} (timestamped)
	  - Log file: ${LOG_FILE}

	Proceed? (y/N):
	MSG
  read -r answer
  if [[ "${answer,,}" != "y" ]]; then
    log_warn "User aborted."
    exit 3
  fi
fi

#-----------------------------------------------
# Main execution
#-----------------------------------------------
log_info "Starting remove-cisco-agent.sh at ${TS}"

# Stop & disable services (capture prior state for rollback)
for s in "${SERVICES[@]}"; do
  log_info "Handling service: ${s}"
  if ! stop_and_disable_service "$s"; then
    log_error "Failed to stop/disable ${s}"
    exit 10
  fi
done

# Move directory
if ! move_directory "$SRC_DIR" "$DEST_DIR"; then
  log_error "Failed to move ${SRC_DIR}; aborting."
  exit 11
fi

log_ok "All requested operations completed successfully."
log_info "Log file: ${LOG_FILE}"
exit 0
