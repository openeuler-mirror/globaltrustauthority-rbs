# tools e2e

Markers: `e2e` + `tools`. Tests invoke the real `rbs-cli` binary against a shared RBS/OpenBao/Fake GTA deployment whose SQLite API data resets after each test.

Coverage is split by command family and operation:

- `client/`: challenge, collect-evidence, get-token, and separate token/evidence/passport/background resource modes, including parser and auth-mode validation.
- `users/`: list/create/get/update/delete, complete response contracts, JWK input, pagination, path validation, and not-found behavior.
- `policies/`: list/create/get/update/delete, response/version contracts, pagination, path validation, and delete target validation.
- `resources/`: create/info/update/get/delete, metadata/content/JWE contracts, URI/export-mode validation, and not-found behavior.
- `token/`: PS256 generation, custom claims, and malformed claims validation.
- `version/`: JSON and text output contracts.
- `test_lifecycle.py`: one serial client challenge → evidence → token → resource/decrypt flow.
- `test_https.py`: real HTTPS `--cert` verification, wrong/missing CA failures, and complete HTTPS resource retrieval.
- `test_global_options.py`: `--quiet`, `--noout`, `--verbose`, and invalid global input handling.

Attestation policy, certificate/CRL, and reference-value commands are intentionally out of scope until their CLI adapters are available.

Run with:

```bash
./tests/run_e2e.sh --suite tools
```
