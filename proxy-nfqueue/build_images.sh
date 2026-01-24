#!/bin/bash
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pushd "${SCRIPT_DIR}/../" > /dev/null

DOCKERFILE_PATH="${SCRIPT_DIR}/Dockerfile"
IMAGE_NAME="symphony-proxy-nfqueue"
FULL_IMAGE="appnetorg/${IMAGE_NAME}:latest"

sudo docker build -f "${DOCKERFILE_PATH}" -t "${IMAGE_NAME}:latest" .

sudo docker tag "${IMAGE_NAME}:latest" "${FULL_IMAGE}"
sudo docker push "${FULL_IMAGE}"

popd > /dev/null

set +ex
