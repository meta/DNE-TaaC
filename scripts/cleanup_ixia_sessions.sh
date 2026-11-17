#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# Cleanup a named IXIA session on the API server.
#
# When to run: sessions never establish because a stale session or cached
# config still holds the ports.
#
# What it does: authenticates to the IXIA API, then stops + deletes ONLY
# the sessions you name. The chassis is shared, so there is deliberately
# no way to delete every session at once — run --list, find the session
# that is yours, and pass its id or name.
#
# Prereqs: IXIA API server reachable, IXIA_API_PASSWORD set (or the
# password is read from ``taac/oss_topology_info/vendor_ixia_pwd.csv``,
# which the runner already uses for chassis auth).
#
# Usage:
#   scripts/cleanup_ixia_sessions.sh --list             # print sessions, don't touch them
#   scripts/cleanup_ixia_sessions.sh --id 42            # stop + delete session 42
#   scripts/cleanup_ixia_sessions.sh --id 42 --id 43    # ... several of them
#   scripts/cleanup_ixia_sessions.sh --name my-session  # match on sessionName instead
#   IXIA_API_SERVER=ixia-api.example.com scripts/cleanup_ixia_sessions.sh --id 42
#
# Selecting sessions:
#   - At least one --id or --name is REQUIRED for cleanup. Running with
#     no selector is an error, never a "delete everything".
#   - Both match exactly (no globbing); --name matches the session's
#     ``sessionName`` field as shown by --list.
#   - Selectors that match nothing warn and exit 0, so re-running after a
#     successful cleanup is harmless.
#   - A --name matching several sessions deletes all of them; they are
#     listed before the delete so you can Ctrl-C.
#   - Sessions you did not select are printed as "leaving untouched" —
#     other people's runs on the shared chassis are never disturbed.
#
# Safety guards:
#   - In cleanup mode, refuses to run while the tmux session named by
#     ``IXIA_CLEANUP_GUARD_TMUX`` (unset = no guard) exists on the caller's
#     default socket — use it to protect a live run whose IXIA session
#     would be ripped out from under it. Set ``IXIA_CLEANUP_FORCE=1`` to
#     bypass.
#   - ``--list`` mode is read-only and never triggers the guard, so it's
#     always safe to run mid-test to see chassis state.

set -euo pipefail

ACTION=cleanup
WANT_IDS=()
WANT_NAMES=()

usage() {
    # Print the header comment block (everything above the first non-comment
    # line) so help cannot drift out of sync with a hardcoded line range.
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' \
        "${BASH_SOURCE[0]}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -l|--list|--dry-run) ACTION=list; shift ;;
        -i|--id)
            [[ $# -ge 2 ]] || { echo "[cleanup] --id needs a session id" >&2; exit 2; }
            WANT_IDS+=("$2"); shift 2 ;;
        -n|--name)
            [[ $# -ge 2 ]] || { echo "[cleanup] --name needs a session name" >&2; exit 2; }
            WANT_NAMES+=("$2"); shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[cleanup] unknown arg: $1 (try --help)" >&2; exit 2 ;;
    esac
done

if [[ "$ACTION" == "cleanup" && ${#WANT_IDS[@]} -eq 0 && ${#WANT_NAMES[@]} -eq 0 ]]; then
    echo "[cleanup] refusing: no session selected." >&2
    echo "[cleanup]           This chassis is shared — deleting every session" >&2
    echo "[cleanup]           would kill other people's runs, so a selector is" >&2
    echo "[cleanup]           required. Run with --list to see what is active," >&2
    echo "[cleanup]           then pass --id <id> (or --name <sessionName>)." >&2
    exit 2
fi

GUARD_TMUX="${IXIA_CLEANUP_GUARD_TMUX:-}"
if [[ "$ACTION" == "cleanup" && -n "$GUARD_TMUX" ]] \
   && tmux has-session -t "$GUARD_TMUX" 2>/dev/null \
   && [[ -z "${IXIA_CLEANUP_FORCE:-}" ]]; then
    echo "[cleanup] refusing: tmux '$GUARD_TMUX' session is active — its IXIA" >&2
    echo "[cleanup]           session would be destroyed. Use --list to" >&2
    echo "[cleanup]           inspect, or set IXIA_CLEANUP_FORCE=1 to override." >&2
    exit 3
fi

API_SERVER="${IXIA_API_SERVER:-ixia-api.example.com}"
API_USER="${IXIA_API_USER:-admin}"
PWD_FILE="${IXIA_PASSWORD_FILE:-taac/oss_topology_info/vendor_ixia_pwd.csv}"

if [[ -z "${IXIA_API_PASSWORD:-}" ]]; then
    if [[ ! -f "$PWD_FILE" ]]; then
        echo "[cleanup] No IXIA_API_PASSWORD env var and $PWD_FILE not found" >&2
        exit 1
    fi
    IXIA_API_PASSWORD="$(grep -v '^\s*#' "$PWD_FILE" | grep -v '^\s*$' | head -1)"
fi

if [[ -z "$IXIA_API_PASSWORD" ]]; then
    echo "[cleanup] No password in $PWD_FILE (only placeholder/comments)" >&2
    exit 1
fi

echo "[cleanup] authenticating to $API_SERVER as $API_USER ..."
token=$(curl -sk -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"$API_USER\",\"password\":\"$IXIA_API_PASSWORD\"}" \
    "https://$API_SERVER/api/v1/auth/session" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("apiKey",""))')

if [[ -z "$token" ]]; then
    echo "[cleanup] auth failed — check IXIA_API_USER / IXIA_API_PASSWORD / $PWD_FILE" >&2
    exit 2
fi

# Tab-delimited so a sessionName containing spaces stays one field.
sessions=$(curl -sk -H "X-Api-Key: $token" "https://$API_SERVER/api/v1/sessions" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); [print("\t".join((str(s.get("id","?")), str(s.get("state","?")), s.get("sessionName") or s.get("applicationType") or "<unnamed>"))) for s in d]')

if [[ -z "$sessions" ]]; then
    echo "[cleanup] chassis is already clean (0 active sessions)"
    exit 0
fi

echo "[cleanup] active sessions:"
while IFS=$'\t' read -r id state name; do
    [[ -z "$id" ]] && continue
    printf '  %s\t%s\t%s\n' "$id" "$state" "$name"
done <<< "$sessions"
echo

if [[ "$ACTION" == "list" ]]; then
    echo "[cleanup] --list mode; leaving sessions untouched"
    exit 0
fi

matches() {
    local id="$1" name="$2" want
    for want in ${WANT_IDS[@]+"${WANT_IDS[@]}"}; do
        [[ "$id" == "$want" ]] && return 0
    done
    for want in ${WANT_NAMES[@]+"${WANT_NAMES[@]}"}; do
        [[ "$name" == "$want" ]] && return 0
    done
    return 1
}

selected=""
skipped=""
while IFS=$'\t' read -r id state name; do
    [[ -z "$id" ]] && continue
    if matches "$id" "$name"; then
        selected+="${id}"$'\t'"${state}"$'\t'"${name}"$'\n'
    else
        skipped+="  ${id}"$'\t'"${state}"$'\t'"${name}"$'\n'
    fi
done <<< "$sessions"

if [[ -z "$selected" ]]; then
    echo "[cleanup] no active session matched the given selector(s):" >&2
    for want in ${WANT_IDS[@]+"${WANT_IDS[@]}"}; do echo "[cleanup]   --id $want" >&2; done
    for want in ${WANT_NAMES[@]+"${WANT_NAMES[@]}"}; do echo "[cleanup]   --name $want" >&2; done
    echo "[cleanup] nothing to do." >&2
    exit 0
fi

echo "[cleanup] selected for stop + delete:"
echo "$selected" | sed '/^$/d; s/^/  /'
if [[ -n "$skipped" ]]; then
    echo "[cleanup] leaving untouched (not selected):"
    printf '%s' "$skipped"
fi
echo

while IFS=$'\t' read -r id state name; do
    [[ -z "$id" ]] && continue
    echo "[cleanup] stopping session $id ($name) ..."
    curl -sk -H "X-Api-Key: $token" -H "Content-Type: application/json" \
        -X POST -d '{}' "https://$API_SERVER/api/v1/sessions/$id/operations/stop" >/dev/null
done <<< "$selected"

# The stop is asynchronous — give the chassis a few seconds to transition
# each session out of Active before attempting delete (delete is only
# allowed on Stopped / Initial sessions per the IXIA API).
sleep 5

while IFS=$'\t' read -r id state name; do
    [[ -z "$id" ]] && continue
    echo "[cleanup] deleting session $id ($name) ..."
    curl -sk -H "X-Api-Key: $token" -X DELETE "https://$API_SERVER/api/v1/sessions/$id" >/dev/null
done <<< "$selected"

echo "[cleanup] done"
