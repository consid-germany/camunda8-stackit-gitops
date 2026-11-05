#!/usr/bin/env bash
# Render dev + prod across all layers, then assert the rendered output with conftest.
# Exits non-zero on any mismatch. Run from anywhere.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/policy"

command -v conftest >/dev/null 2>&1 || { echo "conftest not installed" >&2; exit 127; }

bash "${ROOT}/tests/render.sh" || exit 1

rc=0
for env in dev prod; do
	echo
	echo "== conftest: ${env} =="
	conftest test --combine --policy "${POLICY}" \
		--namespace common --namespace "${env}" \
		"${ROOT}/tests/temp/${env}"/*.yaml --no-color || rc=1
done

echo
if [ "${rc}" -eq 0 ]; then
	echo "render-and-assert: ALL GREEN"
else
	echo "render-and-assert: FAILURES (see above)" >&2
fi
exit "${rc}"
