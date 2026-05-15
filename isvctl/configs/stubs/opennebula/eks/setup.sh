#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

# OpenNebula Kubernetes Setup Stub - Provisions cluster and outputs inventory

set -eo pipefail

CLUSTER_NAME="${ONE_CLUSTER_NAME:-isv-k8s-cluster}"
KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube}"
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
NVIDIA_GPU_OPERATOR_VERSION="v25.10.1"
NVIDIA_GPU_OPERATOR_NAMESPACE="nvidia-gpu-operator"

KUBEFLOW_MPI_VERSION="v0.8.0"
KUBEFLOW_MPI_URL="https://raw.githubusercontent.com/kubeflow/mpi-operator/${KUBEFLOW_MPI_VERSION}/deploy/v2beta1/mpi-operator.yaml"

export NGC_API_KEY=nvapi-XXXXX

wait_for_cluster() {
  local start
  start=$(date +%s)

  while true; do
    state=$(oneks show cluster "$CLUSTER_ID" -j | jq -r '.TEMPLATE.CLUSTER_BODY.state')
    echo "Current state: $state"

    case "$state" in
      RUNNING) echo "Cluster is running"; return 0 ;;
      PROVISIONING_FAILURE)  echo "Cluster deployment failed"; return 1 ;;
    esac

    (( $(date +%s) - start >= CLUSTER_TIMEOUT )) && { echo "Timeout waiting for cluster"; return 1; }

    sleep "$CLUSTER_INTERVAL"
  done
}

# -----------------------------------------------------------------------------
# Dependency Checks
# -----------------------------------------------------------------------------
echo "Checking dependencies..." >&2

for cmd in kubectl jq helm; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd not found" >&2
        exit 1
    fi
done

# Create $KUBECONFIG_PATH if it doesn't exist
if [ ! -d "$KUBECONFIG_PATH" ]; then
    mkdir -p "$KUBECONFIG_PATH"
fi

if [ ! -f "$HOME/.one/oneks_auth" ]; then
    echo "Error: OpenNebula KS auth file not found" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Provisioning Logic (Placeholder)
# -----------------------------------------------------------------------------
echo "Provisioning OpenNebula GPU Cluster..." >&2

# Create cluster (1 Control Plane and 1 VirtualRouter)
cluster_spec=$(mktemp)
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

CLUSTER_ID=$(oneks create cluster --file "$cluster_spec" | sed -n 's/^ID: *//p')
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

oneks create group --cluster-id "$CLUSTER_ID" --file "$nodegroup_spec"
wait_for_cluster "$CLUSTER_ID"

EXPECTED_NODES=$(( GPU_NODE_COUNT + 1 ))

echo "Waiting for $EXPECTED_NODES nodes to be Ready..."
while true; do
    READY=$(kubectl get nodes --no-headers | grep -c " Ready " || echo 0)
    READY=${READY:-0}
    if [ "$READY" -ge "$EXPECTED_NODES" ]; then
        echo "All nodes ready: $READY/$EXPECTED_NODES"
        break
    fi
    echo "Waiting for nodes... ($READY/$EXPECTED_NODES ready)"
    sleep 15
done


# Install Longhorn CSI Driver (if not already installed)
# sudo apt-get update && sudo apt-get install -y nfs-common required for nodes
helm repo add longhorn https://charts.longhorn.io && helm repo update

helm install --wait longhorn longhorn/longhorn \
    --namespace longhorn-system \
    --create-namespace \
    --version "$LONGHORN_VERSION"

# Install NVIDIA GPU Operator
kubectl apply -f - <<EOF
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
    toolkit:
      env:
      - name: CONTAINERD_SOCKET
        value: /run/k3s/containerd/containerd.sock
EOF

# Install Kubeflow MPI Operator
kubectl apply --server-side -f "$KUBEFLOW_MPI_URL"

# -----------------------------------------------------------------------------
# Preflight Checks (Wait for GPUs)
# -----------------------------------------------------------------------------
echo "Running preflight checks..." >&2
for i in {1..20}; do
    GPU_NODES=$(kubectl get nodes -l nvidia.com/gpu.present=true -o name 2>/dev/null | wc -l || echo "0")
    if [ "$GPU_NODES" -gt 0 ]; then
        echo "  Found $GPU_NODES GPU node(s)" >&2
        break
    fi
    echo "  Waiting for GPU operator... ($i/20)" >&2
    sleep 15
done

while [ "$(kubectl get ds nvidia-mig-manager -n "$NVIDIA_GPU_OPERATOR_NAMESPACE" -o jsonpath='{.status.numberReady}')" -lt "$GPU_NODE_COUNT" ]; do
    echo "Waiting for GPU operator..."
    sleep 30
done


# -----------------------------------------------------------------------------
# Gather Information
# -----------------------------------------------------------------------------
NODE_COUNT=$(kubectl get nodes --no-headers | wc -l)
GPU_NODE_COUNT=$(kubectl get nodes -l nvidia.com/gpu.present=true --no-headers | wc -l || echo "0")
GPU_PER_NODE=$(kubectl get nodes -l nvidia.com/gpu.present=true -o jsonpath='{.items[0].status.capacity.nvidia\.com/gpu}' 2>/dev/null || echo "0")
TOTAL_GPUS=$((GPU_NODE_COUNT * GPU_PER_NODE))

DRIVER_VERSION=$(kubectl get nodes -l nvidia.com/gpu.present=true -o jsonpath='{.items[0].metadata.labels.nvidia\.com/cuda\.driver\.version}' 2>/dev/null || echo "unknown")

NODES=$(kubectl get nodes -o json | jq '[.items[] | {
    name: .metadata.name,
    ip: (if .status.addresses then (.status.addresses | map(select(.type == "InternalIP")) | .[0].address) else null end),
    gpus: (if .status.capacity["nvidia.com/gpu"] then (.status.capacity["nvidia.com/gpu"] | tonumber) else 0 end)
}]')

# -----------------------------------------------------------------------------
# Output JSON Inventory
# -----------------------------------------------------------------------------

cat << EOF
{
  "success": true,
  "platform": "kubernetes",
  "cluster_name": "${CLUSTER_NAME}",
  "node_count": ${NODE_COUNT},
  "endpoint": "${CLUSTER_ENDPOINT}",
  "gpu_count": ${TOTAL_GPUS},
  "gpu_per_node": ${GPU_PER_NODE},
  "driver_version": "${DRIVER_VERSION}",
  "kubeconfig_path": "${KUBECONFIG_PATH}",
  "kubernetes": {
    "driver_version": "${DRIVER_VERSION}",
    "node_count": ${NODE_COUNT},
    "nodes": ${NODES},
    "gpu_node_count": ${GPU_NODE_COUNT},
    "gpu_per_node": ${GPU_PER_NODE},
    "total_gpus": ${TOTAL_GPUS},
    "control_plane_address": "${CLUSTER_ENDPOINT}",
    "kubeconfig_path": "${KUBECONFIG_PATH}",
    "gpu_operator_namespace": "${NVIDIA_GPU_OPERATOR_NAMESPACE}",
    "runtime_class": "${RUNTIME_CLASS}",
    "gpu_resource_name": "nvidia.com/gpu"
  }
}
EOF