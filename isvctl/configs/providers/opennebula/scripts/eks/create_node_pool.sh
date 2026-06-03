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

# Create a test node pool in OpenNebula EKS and output the node_pool schema JSON.
#
# Environment variables:
#   ONE_CLUSTER_NAME        - Cluster name (default: isv-k8s-cluster)
#   POOL_NAME               - Node pool name (default: isv-test-pool)
#   DESIRED_SIZE            - Node count (default: 1)
#   NODE_TYPE               - "cpu" | "gpu" (default: gpu)
#   LABELS_JSON             - JSON object of extra labels (default: "{}")
#   TAINTS_JSON             - JSON array of taints (default: "[]")
#   ACTION                  - Banner verb: "Creating" | "Updating" (default: "Creating")

set -eo pipefail

# -----------------------------------------------------------------------------
# Configuration & Constants
# -----------------------------------------------------------------------------
CLUSTER_NAME="${ONE_CLUSTER_NAME:-isv-k8s-cluster}"
POOL_NAME="${POOL_NAME:-isv-test-pool}"
DESIRED_SIZE="${DESIRED_SIZE:-1}"
NODEGROUP_FAMILY="general"
NODEGROUP_FLAVOUR="small"
NODE_TYPE="${NODE_TYPE:-cpu}"
LABELS_JSON="${LABELS_JSON:-"{}"}"
TAINTS_JSON="${TAINTS_JSON:-[]}"
ACTION="${ACTION:-Creating}"
CLUSTER_TIMEOUT=900
CLUSTER_INTERVAL=60

if ! command -v jq &> /dev/null; then
    echo "Error: jq not found" >&2
    exit 1
fi
if ! command -v oneks &> /dev/null; then
    echo "Error: oneks not found" >&2
    exit 1
fi

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

echo "" >&2
echo "========================================" >&2
echo "  ${ACTION} test node pool" >&2
echo "========================================" >&2
echo "  pool name: ${POOL_NAME}" >&2
echo "  desired size: ${DESIRED_SIZE}" >&2
echo "  node type tag: ${NODE_TYPE}" >&2
echo "" >&2

CLUSTER_ID=$(oneks list cluster | awk -v cn="$CLUSTER_NAME" '$4==cn {print $1}')
if [ -z "$CLUSTER_ID" ]; then
    echo "Error: Cluster ${CLUSTER_NAME} not found" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Provisioning
# -----------------------------------------------------------------------------
nodegroup_spec=$(mktemp)
cat > "$nodegroup_spec" <<EOF
{
   "name": "$POOL_NAME",
   "family": "$NODEGROUP_FAMILY",
   "flavour": "$NODEGROUP_FLAVOUR",
   "user_inputs_values": {
     "count": $DESIRED_SIZE
   }
}
EOF

echo "Creating group $POOL_NAME in cluster $CLUSTER_NAME..." >&2
oneks create group --cluster-id "$CLUSTER_ID" --file "$nodegroup_spec" >&2
wait_for_cluster "$CLUSTER_ID"

# -----------------------------------------------------------------------------
# Node Configuration (Labels & Taints)
# -----------------------------------------------------------------------------
# We identify nodes from this pool by a common label.
LABEL_SELECTOR="oneks.io/nodegroup=${POOL_NAME}"

echo "Waiting for $DESIRED_SIZE nodes to appear in Kubernetes..." >&2
MAX_WAIT=300
WAIT_COUNT=0
NODES=""
while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    # We use '|| true' to prevent grep from failing the script due to 'set -e' / 'pipefail'
    NODES=$($KUBECTL get nodes -l "$LABEL_SELECTOR" --no-headers -o custom-columns=NAME:.metadata.name || true)
    NODE_COUNT=$(echo "$NODES" | grep -c . || echo 0)
    if [ "$NODE_COUNT" -ge "$DESIRED_SIZE" ]; then
        echo "Found $NODE_COUNT nodes." >&2
        break
    fi
    echo "Waiting for nodes... ($NODE_COUNT/$DESIRED_SIZE)" >&2
    sleep 5
    WAIT_COUNT=$((WAIT_COUNT + 5))
done

if [ -z "$NODES" ]; then
    echo "Warning: No nodes for pool $POOL_NAME appeared after $MAX_WAIT seconds." >&2
fi

# We apply labels and taints to any node that matches the pool name in its name.
echo "$NODES" | while read -r node; do
    [ -z "$node" ] && continue
    echo "Configuring node: $node" >&2
    $KUBECTL label node "$node" "$LABEL_SELECTOR" --overwrite >&2
    $KUBECTL label node "$node" "node.kubernetes.io/instance-type=${NODEGROUP_FLAVOUR}" --overwrite >&2

    # Apply extra labels
    echo "$LABELS_JSON" | jq -r 'to_entries[] | "\(.key)=\(.value)"' | while read -r label; do
        $KUBECTL label node "$node" "$label" --overwrite >&2
    done

    # Apply taints
    echo "$TAINTS_JSON" | jq -c '.[]' | while read -r taint; do
        KEY=$(echo "$taint" | jq -r .key)
        VALUE=$(echo "$taint" | jq -r .value)
        EFFECT=$(echo "$taint" | jq -r .effect)
        $KUBECTL taint nodes "$node" "${KEY}=${VALUE}:${EFFECT}" --overwrite >&2
    done
done

# -----------------------------------------------------------------------------
# Output Payload
# -----------------------------------------------------------------------------
EXPECTED_LABELS_COMPACT=$(echo "${LABELS_JSON}" | jq -c .)
EXPECTED_TAINTS_COMPACT=$(echo "${TAINTS_JSON}" | jq -c .)
EXPECTED_INSTANCE_TYPES_COMPACT=$(echo "[\"${NODEGROUP_FLAVOUR}\"]" | jq -c .)

jq -n \
    --arg node_pool_name "${POOL_NAME}" \
    --arg label_selector "${LABEL_SELECTOR}" \
    --argjson expected_replicas "${DESIRED_SIZE}" \
    --arg expected_labels_json "${EXPECTED_LABELS_COMPACT}" \
    --arg expected_taints_json "${EXPECTED_TAINTS_COMPACT}" \
    --arg expected_instance_types_json "${EXPECTED_INSTANCE_TYPES_COMPACT}" \
    --arg node_type "${NODE_TYPE}" \
    '{
      success: true,
      platform: "kubernetes",
      node_pool_name: $node_pool_name,
      label_selector: $label_selector,
      expected_replicas: $expected_replicas,
      expected_labels_json: $expected_labels_json,
      expected_taints_json: $expected_taints_json,
      expected_instance_types_json: $expected_instance_types_json,
      node_type: $node_type
    }' > /create-config


jq -n \
    --arg node_pool_name "${POOL_NAME}" \
    --arg label_selector "${LABEL_SELECTOR}" \
    --argjson expected_replicas "${DESIRED_SIZE}" \
    --arg expected_labels_json "${EXPECTED_LABELS_COMPACT}" \
    --arg expected_taints_json "${EXPECTED_TAINTS_COMPACT}" \
    --arg expected_instance_types_json "${EXPECTED_INSTANCE_TYPES_COMPACT}" \
    --arg node_type "${NODE_TYPE}" \
    '{
      success: true,
      platform: "kubernetes",
      node_pool_name: $node_pool_name,
      label_selector: $label_selector,
      expected_replicas: $expected_replicas,
      expected_labels_json: $expected_labels_json,
      expected_taints_json: $expected_taints_json,
      expected_instance_types_json: $expected_instance_types_json,
      node_type: $node_type
    }'
