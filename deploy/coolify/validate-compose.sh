#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

env_file="${tmp_dir}/compose.env"

cat >"${env_file}" <<'ENV'
MCP_EDGE_PUBLIC_BASE_URL=https://edge.example.invalid
MCP_EDGE_AUTHENTIK_ISSUER_URL=https://auth.example.invalid/application/o/mcp-edge/
MCP_EDGE_AUTHENTIK_CLIENT_ID=dummy-edge-client-id
MCP_EDGE_IMAGE=example.invalid/mcp-edge:validation
MCP_INFISICAL_BRIDGE_IMAGE=example.invalid/infisical-bridge:validation
MCP_CONTROL_PLANE_IMAGE=example.invalid/mcp-control-plane:validation
MCP_INFISICAL_BRIDGE_UPSTREAM_HOST=infisical.example.invalid
MCP_CONTROL_PLANE_AUTHENTIK_ISSUER_URL=https://auth.example.invalid/application/o/mcp-control-plane/
MCP_CONTROL_PLANE_AUTHENTIK_CLIENT_ID=dummy-control-plane-client-id
MCP_CONTROL_PLANE_COOLIFY_API_BASE_URL=https://coolify.example.invalid/api/v1
MCP_CONTROL_PLANE_COOLIFY_PROJECT_UUID=00000000-0000-0000-0000-000000000001
MCP_CONTROL_PLANE_COOLIFY_SERVER_UUID=00000000-0000-0000-0000-000000000002
MCP_CONTROL_PLANE_COOLIFY_DESTINATION_UUID=00000000-0000-0000-0000-000000000003
MCP_CONTROL_PLANE_INFISICAL_PROJECT_SLUG=dummy-project
MCP_CONTROL_PLANE_INFISICAL_ENV_SLUG=prod
MCP_CONTROL_PLANE_INFISICAL_MACHINE_CLIENT_ID=dummy-machine-client-id
MCP_CONTROL_PLANE_MEALIE_BASE_URL=https://mealie.example.invalid
MCP_CONTROL_PLANE_ACTUAL_SERVER_URL=https://actual.example.invalid
ENV

if ! command -v docker >/dev/null 2>&1; then
  printf 'docker CLI is required for compose template validation\n' >&2
  exit 1
fi

docker compose version >/dev/null

validate_compose() {
  name="$1"
  compose_file="$2"

  printf 'Validating %s...\n' "${name}"
  docker compose \
    --project-directory "${repo_root}" \
    --env-file "${env_file}" \
    -f "${compose_file}" \
    config --quiet
}

render_compose_json() {
  compose_file="$1"
  output_file="$2"

  docker compose \
    --project-directory "${repo_root}" \
    --env-file "${env_file}" \
    -f "${compose_file}" \
    config --format json >"${output_file}"
}

validate_source_builds() {
  name="$1"
  rendered_file="$2"
  shift 2

  python3 - "${name}" "${rendered_file}" "${repo_root}" "$@" <<'PY'
import json
import sys

name, rendered_file, repo_root, *expectations = sys.argv[1:]

with open(rendered_file, encoding="utf-8") as rendered:
    config = json.load(rendered)

services = config.get("services", {})
for expectation in expectations:
    service_name, expected_dockerfile = expectation.split("=", 1)
    service = services.get(service_name)
    if service is None:
        sys.exit(f"{name} did not render service {service_name}")

    build = service.get("build")
    if not isinstance(build, dict):
        sys.exit(f"{name} service {service_name} did not render a build section")

    context = build.get("context")
    if context != repo_root:
        sys.exit(
            f"{name} service {service_name} rendered build context {context!r}; "
            f"expected repository root {repo_root!r}"
        )

    dockerfile = build.get("dockerfile")
    if dockerfile != expected_dockerfile:
        sys.exit(
            f"{name} service {service_name} rendered Dockerfile {dockerfile!r}; "
            f"expected {expected_dockerfile!r}"
        )
PY
}

validate_compose "source edge compose" "${script_dir}/mcp-edge.compose.yaml"
validate_compose "image edge compose" "${script_dir}/mcp-edge.image.compose.yaml"
validate_compose "source control-plane-only compose" "${script_dir}/mcp-control-plane.compose.yaml"
validate_compose "image control-plane-only compose" "${script_dir}/mcp-control-plane.image.compose.yaml"
validate_compose "combined source core stack compose" "${script_dir}/mcp-platform-core.compose.yaml"
validate_compose "combined image core stack compose" "${script_dir}/mcp-platform-core.image.compose.yaml"

render_compose_json "${script_dir}/mcp-edge.compose.yaml" "${tmp_dir}/mcp-edge.config.json"
render_compose_json "${script_dir}/mcp-control-plane.compose.yaml" "${tmp_dir}/mcp-control-plane.config.json"
render_compose_json "${script_dir}/mcp-platform-core.compose.yaml" "${tmp_dir}/mcp-platform-core.config.json"

validate_source_builds \
  "source edge compose" \
  "${tmp_dir}/mcp-edge.config.json" \
  "mcp-edge=Dockerfile.edge"

validate_source_builds \
  "source control-plane-only compose" \
  "${tmp_dir}/mcp-control-plane.config.json" \
  "infisical-bridge=Dockerfile.infisical-bridge" \
  "mcp-control-plane=Dockerfile.control-plane"

validate_source_builds \
  "combined source core stack compose" \
  "${tmp_dir}/mcp-platform-core.config.json" \
  "infisical-bridge=Dockerfile.infisical-bridge" \
  "mcp-control-plane=Dockerfile.control-plane" \
  "mcp-edge=Dockerfile.edge"

printf 'Coolify compose templates validated.\n'
