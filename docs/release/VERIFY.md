Pipe CLI release archives are published by **PipeNetwork/pipe**. Always choose an explicit version and verify both the checksum and the GitHub Actions provenance before running a downloaded binary.

```sh
# Replace VERSION and TARGET with a published release and your platform.
gh release download vVERSION --repo PipeNetwork/pipe --pattern 'pipe-vVERSION-TARGET.tar.gz' --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify pipe-vVERSION-TARGET.tar.gz --repo PipeNetwork/pipe --source-ref refs/tags/vVERSION
```

On macOS, use `shasum -a 256` and compare the matching filename in `SHA256SUMS`. On Windows, use `Get-FileHash -Algorithm SHA256` for the ZIP, then the same `gh attestation verify` command. Provenance binds an artifact to its repository, workflow, source ref and commit; checksums alone do not establish who built it.

The native build workflow tests Linux x86-64/ARM64, macOS x86-64/ARM64, and Windows x86-64. Linux GNU releases require glibc 2.39 or newer (Ubuntu 24.04 baseline). These archives are not static musl builds. Native macOS qualification runs on macOS 15 and Windows qualification on Windows Server 2025; older systems need separate verification. Consult `release.json` and the qualification record for the exact tested OS and Rust toolchain.

Installers require an explicit version and verify provenance automatically through GitHub CLI. Download the installer from that release, verify its checksum and attestation, then run:

```sh
bash install.sh --version VERSION --prefix "$HOME/.local"
# Restore the exact previous binary; configuration and journals are retained.
bash install.sh --rollback --prefix "$HOME/.local"
```

```powershell
.\install.ps1 -Version VERSION -Prefix "$env:LOCALAPPDATA\Pipe"
.\install.ps1 -Rollback -Prefix "$env:LOCALAPPDATA\Pipe"
```

For offline installation, provide a previously verified archive and its exact SHA-256 (`--archive FILE --sha256 HASH` or `-Archive FILE -Sha256 HASH`). Installation does not edit PATH, fund accounts, change configuration, transfer ownership, or remove recovery journals. A binary rollback cannot make an older client understand new state formats; use a preserved compatible profile or the explicit configuration rollback workflow. Resolve pending payments and transfers before changing client generations.

Every release includes `release.json` inside each archive with the source commit, target, binary checksum, Cargo lockfile checksum and pinned contract checksums. The final qualification record must additionally name compatible deployed backend revisions, passing staging and production checks, intentional feature gates, canary spending/reservations and cleanup. The publication workflow creates an explicit RC draft after staging qualification, matching immutable contracts and compatible backend deployment, with `production_pending: true` until acceptance passes. Stable promotion remains a separate action and must pass `python scripts/verify-release-qualification.py --stage stable` against the full production record. Passing coverage alone cannot satisfy either gate.

GitHub documents [artifact provenance verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) and the [`gh attestation verify` checks](https://cli.github.com/manual/gh_attestation_verify).
