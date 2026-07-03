#!/usr/bin/env bash
set -euo pipefail

readonly max_attempts=3
readonly retry_delay_seconds=15

for attempt in $(seq 1 "${max_attempts}"); do
  log_file="$(mktemp)"
  trap 'rm -f "${log_file}"' EXIT

  set +e
  cargo run --manifest-path dagger/rust-sdk/Cargo.toml -- ci-all 2>&1 | tee "${log_file}"
  status=${PIPESTATUS[0]}
  set -e

  if [[ ${status} -eq 0 ]]; then
    exit 0
  fi

  if ! grep -Eq \
    'failed to pull image|docker pull registry\.dagger\.io/engine|unexpected HTTP status: 5[0-9]{2}' \
    "${log_file}"; then
    echo "Dagger CI failed with a non-retryable error." >&2
    exit "${status}"
  fi

  if [[ ${attempt} -eq ${max_attempts} ]]; then
    echo "Dagger engine pull failed after ${max_attempts} attempts." >&2
    exit "${status}"
  fi

  echo "Transient Dagger engine pull failure; retrying attempt $((attempt + 1))/${max_attempts} in ${retry_delay_seconds}s." >&2
  rm -f "${log_file}"
  trap - EXIT
  sleep "${retry_delay_seconds}"
done
