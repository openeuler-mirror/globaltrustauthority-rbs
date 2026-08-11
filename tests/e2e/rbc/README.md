# RBC e2e

Markers: `e2e` + `rbc`. These tests invoke the built `rbc-cli`, the public Rust SDK, and a C program linked against `librbc.so`.

The suite starts one real RBS process, OpenBao dev backend, local Fake GTA, and a provisioned `swtpm` TPM 2.0 socket. The Rust SDK probe and a thin dynamic-library wrapper around GTA's real unified `tpm` attester are standalone crates under `tests/fixtures`; neither is a root workspace member, and each keeps build artifacts in its own `target/` directory. The fixture replays the supplied TCG event log into swtpm, so PCRs 0-7 match the boot log before the real plugin reads the AK certificate and PCRs and produces a TPM-signed quote. Boot and IMA logs are read from temporary files prepared by the E2E fixture. No hardware TPM or fake RBS HTTP implementation is used.

Coverage is split by operation and semantic mode:

- `challenge/`: success, text output, directory/path validation, and GTA failure mapping.
- `collect_evidence/`: complete TPM envelope with boot and IMA logs, file output, required arguments, runtime-data, and JSON validation.
- `get_token/`: evidence input, native flow, JWT contract, mutually exclusive arguments, malformed evidence, and GTA failure mapping.
- `get_resource/`: separate attest-token, inline-evidence, passport, and background files, plus URI/auth validation and 401/404/503 mappings.
- `test_lifecycle.py`: one serial CLI challenge → evidence → token → resource flow.
- `test_sdk.py`: direct `rbc::Client`/`Session` lifecycle.
- `test_ffi.py`: direct C ABI lifecycle linked to the generated shared library.
- `test_https.py`: real HTTPS challenge, correct/wrong/missing CA handling, TLS handshake failures, and a complete HTTPS resource flow.
- `test_global_options.py`: `--quiet`, `--noout`, `--verbose`, and invalid URL/certificate/output-path handling.

The RBC-specific JWE key is 4096-bit RSA because the client enforces its TEE public-key minimum. It is intentionally separate from the RBS signing key.

Run with:

```bash
./tests/run_e2e.sh --suite rbc
```
