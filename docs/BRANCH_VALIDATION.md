# Two-branch validation

After exact patch review, validation creates a downloadable Git bundle containing `vulnerable` and `guardian-fixed`. Download it from the Remediation validation result along with its diff and commit evidence. The bundle contains sanitized snapshot history, not the original Git history, and never pushes to a remote automatically. Each proposal has its own independent branch pair; multiple proposals are not presented as a combined fix.

```sh
git clone --branch guardian-fixed branches.bundle guardian-comparison
cd guardian-comparison
git diff origin/vulnerable guardian-fixed
```

When build/tests are requested, Guardian installs the baseline and patched versions in separate temporary directories with lifecycle scripts disabled, then invokes the same declared `build` and `test` scripts through its restricted Docker runner. Compatibility is passed only when both scripts pass on both versions. A missing runner, missing script, or failed baseline prevents a compatibility pass. Results retain command output, image identity, exit codes and security-rescan differences. No-match advisories and passing tests do not prove all possible application behavior.

The ordinary runner still requires a preloaded digest-pinned `GUARDIAN_TEST_IMAGE` and correctly configured Docker access. The default Compose service has neither a Docker CLI/socket nor host-path mapping for sibling-container mounts. Do not mount the host Docker socket casually. Without an appropriate runner, checks remain `not_run`; branch exports and security rescans still work.

## Private controlled demonstration

Repository: https://github.com/p-art-dheev/guardian-validation-demo-20261124 (private).

- `vulnerable`: intentionally outdated lodash 4.17.20.
- `guardian-fixed`: Guardian-selected lodash 4.18.1 and captured validation evidence.
- Four advisory findings resolved in the live rescan, none remaining or introduced in that scan.
- Both versions passed their build and two tests: dependency-backed order calculations and real HTTP dashboard/health/API/404 requests.
- Application code and tests are identical across branches; only package files and evidence files changed.

The demo's actual compatibility checks ran through operator-side restricted Docker containers, separately from the default Compose runner. `validation-evidence.json` and both application logs on the fixed branch identify that provenance. Overall Guardian security verification remains partial; this is not a universal safety claim.

Private repositories require GitHub access. Guardian's normal URL intake still supports public GitHub repositories only; this controlled fixture was supplied locally through the trusted operator, without adding credentials or private-clone support to the intake API.

For the strongest demo on a real application, include existing unit/integration tests plus end-to-end browser tests covering its critical user journeys. Compare the same assertions and API responses on both branches. A successful build alone is insufficient evidence of compatibility.
