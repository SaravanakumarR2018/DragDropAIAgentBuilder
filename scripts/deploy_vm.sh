#!/bin/bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <vm-user>@<vm-host> [tag]" >&2
  exit 1
fi

VM_TARGET="$1"
IMAGE_TAG="${2:-latest}"

if [ -z "${DOCKERHUB_USERNAME:-}" ] || [ -z "${DOCKERHUB_TOKEN:-}" ]; then
  echo "DOCKERHUB_USERNAME and DOCKERHUB_TOKEN must be set" >&2
  exit 1
fi

IMAGE="$DOCKERHUB_USERNAME/dragdropagentbuilder:$IMAGE_TAG"

ssh "$VM_TARGET" <<EOT
  echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USERNAME" --password-stdin
  docker pull "$IMAGE"
  docker stop dragdropagentbuilder || true
  docker rm dragdropagentbuilder || true
  docker run -d --name dragdropagentbuilder -p 80:80 "$IMAGE"
  curl -f http://localhost:80/ > /dev/null
EOT

echo "Deployment complete and health check passed."