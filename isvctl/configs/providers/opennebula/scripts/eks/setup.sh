#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# K8s Inventory Stub - Queries real cluster and outputs inventory JSON
#
# Requirements:
#   - kubectl OR microk8s configured and accessible
#   - jq for JSON processing
#   - nvidia GPU operator installed (for GPU detection)

set -eo pipefail

# -----------------------------------------------------------------------------
# Configuration & Constants
# -----------------------------------------------------------------------------
CLUSTER_NAME="${ONE_CLUSTER_NAME:-isv-k8s-cluster}"
K8S_VERSION="v1.34.2"
PUBLIC_NETWORK_ID=0
PRIVATE_NETWORK_ID=1
CONTROL_PLANE_FAMILY="general"
CONTROL_PLANE_FLAVOUR="standalone"
NODEGROUP_FAMILY="general"
NODEGROUP_FLAVOUR="small"
GPU_NODE_COUNT=1
CLUSTER_TIMEOUT=900
CLUSTER_INTERVAL=60

LONGHORN_VERSION="1.11.2"
NVIDIA_CHART_REPO="https://helm.ngc.nvidia.com/nvidia"
NVIDIA_GPU_OPERATOR_VERSION="v26.3.1"
NVIDIA_GPU_OPERATOR_NAMESPACE="nvidia-gpu-operator"

KUBEFLOW_MPI_VERSION="v0.8.0"
KF_BASE="https://raw.githubusercontent.com/kubeflow"
KF_PATH="mpi-operator/${KUBEFLOW_MPI_VERSION}"
KF_SUFFIX="deploy/v2beta1/mpi-operator.yaml"
KUBEFLOW_MPI_URL="${KF_BASE}/${KF_PATH}/${KF_SUFFIX}"


# -----------------------------------------------------------------------------
# Global Variables
# -----------------------------------------------------------------------------
KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube}"
mkdir -p "$KUBECONFIG_PATH"
KUBECONFIG_PATH=$(cd "$KUBECONFIG_PATH" && pwd)

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------

wait_for_cluster() {
  local target_id="${1}"
  local start
  local state
  start=$(date +%s)

  while true; do
    state=$(oneks show cluster "$target_id" -j | \
      jq -r '.TEMPLATE.CLUSTER_BODY.state')
    echo "Current state: $state" >&2

    case "$state" in
      RUNNING)
        echo "Cluster is running" >&2
        return 0
        ;;
      PROVISIONING_FAILURE)
        echo "Error: Cluster deployment failed" >&2
        return 1
        ;;
    esac

    if (( $(date +%s) - start >= CLUSTER_TIMEOUT )); then
      echo "Error: Timeout waiting for cluster" >&2
      return 1
    fi

    sleep "$CLUSTER_INTERVAL"
  done
}

# -----------------------------------------------------------------------------
# Dependency Checks
# -----------------------------------------------------------------------------
echo "Checking dependencies..." >&2

for cmd in kubectl jq helm oneks; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd not found" >&2
        exit 1
    fi
done

if [[ ! -f "/var/lib/one/.one/oneks_auth" ]]; then
    echo "Error: OpenNebula KS auth file not found" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Provisioning Logic
# -----------------------------------------------------------------------------
echo "Provisioning OpenNebula GPU Cluster..." >&2

# Create cluster (1 Control Plane and 1 VirtualRouter)
cluster_spec=$(mktemp)
# Initialize nodegroup_spec to avoid unbound variable error if trap triggers
# early
nodegroup_spec=""
trap 'rm -f "$cluster_spec" ${nodegroup_spec:+"$nodegroup_spec"}' EXIT

cat > "$cluster_spec" <<EOF
{
  "name": "$CLUSTER_NAME",
  "kubernetes_version": "$K8S_VERSION",
  "public_network": "$PUBLIC_NETWORK_ID",
  "private_network": "$PRIVATE_NETWORK_ID",
  "spec": {
    "family": "$CONTROL_PLANE_FAMILY",
    "flavour": "$CONTROL_PLANE_FLAVOUR",
    "user_inputs_values": {}
  }
}
EOF

CLUSTER_ID=$(oneks create cluster --file "$cluster_spec" | \
  sed -n 's/^ID: *//p')
wait_for_cluster "$CLUSTER_ID"

# -----------------------------------------------------------------------------
# Configure kubectl
# -----------------------------------------------------------------------------
echo "Configuring kubectl..." >&2

oneks show cluster "$CLUSTER_ID" --kubeconfig > "$KUBECONFIG_PATH/config"
export KUBECONFIG="$KUBECONFIG_PATH/config"

if ! kubectl cluster-info &> /dev/null; then
    echo "Error: Cannot connect to Kubernetes cluster" >&2
    exit 1
fi

# Add GPU nodes
nodegroup_spec=$(mktemp)
cat > "$nodegroup_spec" <<EOF
{
   "name": "gpu-nodegroup",
   "family": "$NODEGROUP_FAMILY",
   "flavour": "$NODEGROUP_FLAVOUR",
   "user_inputs_values": {
     "count": $GPU_NODE_COUNT
   }
}
EOF

oneks create group --cluster-id "$CLUSTER_ID" --file "$nodegroup_spec" >&2
wait_for_cluster "$CLUSTER_ID"

EXPECTED_NODES=$(( GPU_NODE_COUNT + 1 ))

echo "Waiting for $EXPECTED_NODES nodes to be Ready..." >&2
while true; do
    READY=$(kubectl get nodes --no-headers | grep -c " Ready " || echo 0)
    READY=${READY:-0}
    if [[ "$READY" -ge "$EXPECTED_NODES" ]]; then
        echo "All nodes ready: $READY/$EXPECTED_NODES" >&2
        break
    fi
    echo "Waiting for nodes... ($READY/$EXPECTED_NODES ready)" >&2
    sleep 15
done

# -----------------------------------------------------------------------------
# Software Installation
# -----------------------------------------------------------------------------
echo "Installing software components..." >&2

# Install Longhorn CSI Driver
helm repo add longhorn https://charts.longhorn.io >&2 && helm repo update >&2
helm install --wait longhorn longhorn/longhorn \
    --namespace longhorn-system \
    --create-namespace \
    --version "$LONGHORN_VERSION" >&2

# Install NVIDIA GPU Operator
kubectl apply -f - <<EOF >&2
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: gpu-operator
  namespace: kube-system
spec:
  repo: "$NVIDIA_CHART_REPO"
  chart: gpu-operator
  version: "$NVIDIA_GPU_OPERATOR_VERSION"
  targetNamespace: "$NVIDIA_GPU_OPERATOR_NAMESPACE"
  createNamespace: true
  valuesContent: |-
    cdi:
      nriPluginEnabled: true
EOF

# Install Kubeflow MPI Operator
kubectl apply --server-side -f "$KUBEFLOW_MPI_URL" >&2

# -----------------------------------------------------------------------------
# Preflight Checks (Wait for GPUs and Runtime)
# -----------------------------------------------------------------------------
echo "Running preflight checks..." >&2
# Increased timeout to ~15 minutes (60 * 15s) as GPU operator components (driver/toolkit) can be slow
for i in {1..60}; do
    # 1. Check for nodes with GPU presence labels
    GPU_LABELS=$(kubectl get nodes -l nvidia.com/gpu.present=true -o name 2>/dev/null | wc -l || echo "0")

    if [[ "$GPU_LABELS" -ge "$GPU_NODE_COUNT" ]]; then
        echo "  All $GPU_NODE_COUNT GPU nodes are ready and capacity is registered." >&2
        break
    fi

    if [[ "$i" -eq 60 ]]; then
        echo "Warning: Timeout waiting for full GPU readiness on all nodes. Following tests might fail if components are still initializing." >&2
    fi
    sleep 15
done

# Detect kubectl command
if [[ "${KUBECTL:-}" =~ [^[:space:]] ]]; then
    :  # already set from environment; skip detection
elif command -v kubectl &> /dev/null; then
    KUBECTL="kubectl"
elif command -v microk8s &> /dev/null; then
    KUBECTL="microk8s kubectl"
else
    echo "Error: Neither kubectl nor microk8s found. Set KUBECTL to override." >&2
    exit 1
fi

kubectl apply -f - <<EOF >&2
apiVersion: longhorn.io/v1beta2
kind: Volume
metadata:
  name: static-test-vol
  namespace: longhorn-system
spec:
  size: "1073741824"
  numberOfReplicas: 1
  accessMode: rwo
  frontend: blockdev
EOF


CLUSTER_NAME=$($KUBECTL config current-context 2>/dev/null || echo "unknown")
DEFAULT_GPU_NS="unknown"
REQUIRE_JQ="true"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"
