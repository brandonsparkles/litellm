# Managed filelock compatibility patch

**Keywords:** LiteLLM filelock 4 NIM proxy native wheel abi3 security compatibility

## LiteLLM source and dependency contract

The base is v1.106.6, `61c6ab78393ef45683dd7d963d2a315bd845e20b`. The dependency change follows upstream fix `dacaaad72ed25663ad7f40941c48f653a45289be`. Both package manifests accept filelock 4.2.4 through 4.x and Python 3.11 through 3.14. The repository's existing three-day dependency aging rule remains active, so its lock selects 4.2.4 while the workstation runtime may select a newer qualified 4.x patch. Public version remains 1.106.6, with the full fork Git SHA identifying the patch

## LiteLLM wheel build and verification

Build from clean committed source with `bash scripts/build-security-wheel.sh <new-artifacts>/wheels`. The wrapper sets a persistent Cargo cache, four build jobs and reduced scheduling priority; explicit caller overrides remain supported. The existing pinned Maturin backend emits an arm64 ABI3 wheel for all supported Python minors. Preserve the build log, source commit, wheel hash and installed package graph. The persistent target directory avoids repeating the first seventeen-minute native build

Import the installed native bridge on each supported Python minor, including filelock 4.2.4 at the minimum supported interpreter. Run the existing CLI settings and configure tests against the installed wheel. Scoped CLI qualification can stop conftest discovery at `tests/unit/proxy/client`; its one secret-vault fixture must come unchanged from the upstream proxy conftest and `FakeSecretVault` implementation. This avoids starting unrelated database integration fixtures. Record this qualification scope explicitly

## LiteLLM runtime cutover and rollback

Prepare a permanent candidate with the proxy extra and Pillow 13, then audit every installed package with zero omissions. Exercise the actual proxy on loopback with a local NIM-compatible provider: Chat Completions, Messages translation, and 429/5xx key failover. No real provider request or customer credential is needed

The owned consumer is control-plane `scripts/ensure-nim-proxy.sh`, which serves localhost port 8084. Preserve the old uv tool receipt and environment, verify active requests have drained, select the qualified candidate and restart only that daemon. Verify actual process executable, listener and both request surfaces. Failed startup or behavior requires restoring the old selection and restarting it. When upstream publishes a compatible release, qualify that wheel and replace the immutable fork pin through normal tool maintenance
