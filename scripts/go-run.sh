#!/usr/bin/env bash
set -euo pipefail

TAG="${GO_TAG:-1.25}"

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"

if [[ $# -eq 0 ]]; then
	echo "usage: scripts/go-run.sh <tool> [args...]" >&2
	exit 2
fi

TOOL="$1"
shift

WORKDIR="$PWD"
REL_PATH="${WORKDIR#"$REPO_ROOT"/}"
CONTAINER_WORKDIR="/src"
if [[ "$WORKDIR" != "$REPO_ROOT" ]]; then
	CONTAINER_WORKDIR="/src/$REL_PATH"
fi

GOPATH_HOST="${HOME}/go"
GOCACHE_HOST="${HOME}/.cache/go-build"
mkdir -p "$GOPATH_HOST" "$GOCACHE_HOST"

UID_VAL="$(id -u)"
PODMAN_SOCK="/run/user/${UID_VAL}/podman/podman.sock"

podman_args=(
	run --rm
	--userns=keep-id
	--net=host
	--security-opt label=disable
	-v "${REPO_ROOT}:/src"
	-v "${GOPATH_HOST}:/go"
	-v "${GOCACHE_HOST}:/go/build-cache"
	-w "${CONTAINER_WORKDIR}"
	-e "GOCACHE=/go/build-cache"
	-e "GOPATH=/go"
	-e "CGO_ENABLED=1"
)

WORKSPACE_PATH="${REPO_ROOT}/workspace"
if [[ -d "$WORKSPACE_PATH" ]]; then
	podman_args+=(
		-v "${WORKSPACE_PATH}:${WORKSPACE_PATH}"
	)
fi

if [[ -S "$PODMAN_SOCK" ]]; then
	podman_args+=(
		-v "${PODMAN_SOCK}:/run/user/${UID_VAL}/podman/podman.sock"
		-v "${PODMAN_SOCK}:/var/run/docker.sock"
		-e "DOCKER_HOST=unix:///var/run/docker.sock"
	)
fi

exec podman "${podman_args[@]}" "golang:${TAG}" "$TOOL" "$@"
