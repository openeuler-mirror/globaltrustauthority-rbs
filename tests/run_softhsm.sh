#!/usr/bin/env bash
# Run ignored HSM tests against a disposable SoftHSM2 token, never a real HSM.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SOFTHSM_UTIL="${SOFTHSM_UTIL:-softhsm2-util}"
command -v "$SOFTHSM_UTIL" >/dev/null || {
  echo "SoftHSM2 is required; install it or set SOFTHSM_UTIL to softhsm2-util." >&2
  exit 1
}
if [[ -z "${RBS_HSM_MODULE_TEST:-}" ]]; then
  for candidate in /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so; do
    if [[ -f "$candidate" ]]; then
      export RBS_HSM_MODULE_TEST="$candidate"
      break
    fi
  done
fi
[[ -f "${RBS_HSM_MODULE_TEST:-}" ]] || {
  echo "Set RBS_HSM_MODULE_TEST to the SoftHSM2 libsofthsm2.so path." >&2
  exit 1
}

scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT
mkdir "$scratch_dir/tokens"
export SOFTHSM2_CONF="$scratch_dir/softhsm2.conf"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $scratch_dir/tokens
objectstore.backend = file
log.level = ERROR
EOF
# These PINs belong only to the temporary software token.
export RBS_HSM_PIN_TEST=123456
"$SOFTHSM_UTIL" --module "$RBS_HSM_MODULE_TEST" --init-token --free --label rbs_test --so-pin 12345678 --pin "$RBS_HSM_PIN_TEST"
# Each test initializes/finalizes the module, so execute them serially.
cargo test -p rbs-core --lib resource::adapter::hsm::tests -- --ignored --test-threads=1
