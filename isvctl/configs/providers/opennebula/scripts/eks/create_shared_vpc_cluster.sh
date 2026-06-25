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

# Create a secondary OpenNebula Kubernetes cluster using the same private
# network as the primary cluster and emit the multi_cluster JSON contract.

set -eo pipefail

PRIMARY_CLUSTER_NAME="${ONE_PRIMARY_CLUSTER_NAME:-isv-k8s-cluster}"
SECONDARY_CLUSTER_NAME="${ONE_SECONDARY_CLUSTER_NAME:-isv-k8s-cluster-shared-vnet}"
K8S_VERSION="${ONE_K8S_VERSION:-v1.34.2}"
PUBLIC_NETWORK_ID="${ONE_PUBLIC_NETWORK_ID:-0}"
PRIVATE_NETWORK_ID="${ONE_PRIVATE_NETWORK_ID:-2}"
CONTROL_PLANE_FAMILY="${ONE_CONTROL_PLANE_FAMILY:-general}"
CONTROL_PLANE_FLAVOUR="${ONE_CONTROL_PLANE_FLAVOUR:-standalone}"
NODEGROUP_FAMILY="${ONE_NODEGROUP_FAMILY:-general}"
NODEGROUP_FLAVOUR="${ONE_NODEGROUP_FLAVOUR:-small}"
SECONDARY_NODE_COUNT="${ONE_SECONDARY_NODE_COUNT:-1}"
CLUSTER_TIMEOUT="${ONE_CLUSTER_TIMEOUT:-900}"
CLUSTER_INTERVAL="${ONE_CLUSTER_INTERVAL:-60}"
READY_TIMEOUT="${ONE_SECONDARY_CLUSTER_READY_TIMEOUT:-900}"
READY_INTERVAL="${ONE_SECONDARY_CLUSTER_POLL_INTERVAL:-10}"
SECONDARY_NODEGROUP_NAME="${ONE_SECONDARY_NODEGROUP_NAME:-shared-vnet-cpu}"
cluster_spec=""
nodegroup_spec=""

trap 'rm -f ${cluster_spec:+"$cluster_spec"} ${nodegroup_spec:+"$nodegroup_spec"}' EXIT

for cmd in oneks kubectl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd not found" >&2
        exit 1
    fi
done

wait_for_cluster() {
    local target_id="$1"
    local start
    local state
    start=$(date +%s)

    while true; do
        state=$(oneks show cluster "$target_id" -j | jq -r '.TEMPLATE.CLUSTER_BODY.state // empty')
        case "$state" in
            RUNNING)
                return 0
                ;;
            PROVISIONING_FAILURE)
                echo "Error: cluster $target_id provisioning failed" >&2
                return 1
                ;;
        esac

        if (( $(date +%s) - start >= CLUSTER_TIMEOUT )); then
            echo "Error: timeout waiting for cluster $target_id" >&2
            return 1
        fi

        sleep "$CLUSTER_INTERVAL"
    done
}

cluster_id_by_name() {
    local name="$1"
    oneks list cluster | awk -v cn="$name" '$4==cn {print $1; exit}'
}

cluster_state() {
    local cluster_id="$1"
    oneks show cluster "$cluster_id" -j | jq -r '.TEMPLATE.CLUSTER_BODY.state // empty'
}

group_id_by_name() {
    local name="$1"
    oneks list group | awk -v gn="$name" '$4==gn {print $1; exit}'
}

ready_nodes_for_cluster() {
    local cluster_id="$1"
    local kubeconfig_path="$2"

    oneks show cluster "$cluster_id" --kubeconfig > "$kubeconfig_path"

    KUBECONFIG="$kubeconfig_path" kubectl get nodes -o json \
        | jq '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length'
}

wait_for_ready_nodes() {
    local cluster_id="$1"
    local kubeconfig_path
    local ready_nodes
    local elapsed=0

    kubeconfig_path="$(mktemp)"
    trap 'rm -f "$kubeconfig_path"' RETURN

    while [ "$elapsed" -le "$READY_TIMEOUT" ]; do
        ready_nodes="$(ready_nodes_for_cluster "$cluster_id" "$kubeconfig_path" 2>/dev/null || echo "0")"
        if [ "$ready_nodes" -ge 1 ]; then
            echo "$ready_nodes"
            return 0
        fi

        echo "Waiting for secondary cluster node readiness (${ready_nodes} Ready node(s))..." >&2
        sleep "$READY_INTERVAL"
        elapsed=$((elapsed + READY_INTERVAL))
    done

    echo "Error: secondary cluster did not report a Ready node within ${READY_TIMEOUT}s" >&2
    return 1
}

PRIMARY_CLUSTER_ID="$(cluster_id_by_name "$PRIMARY_CLUSTER_NAME")"
if [ -z "$PRIMARY_CLUSTER_ID" ]; then
    echo "Error: primary cluster ${PRIMARY_CLUSTER_NAME} not found" >&2
    exit 1
fi

PRIMARY_STATE="$(cluster_state "$PRIMARY_CLUSTER_ID")"
if [ "$PRIMARY_STATE" != "RUNNING" ]; then
    echo "Error: primary cluster ${PRIMARY_CLUSTER_NAME} is not RUNNING: ${PRIMARY_STATE}" >&2
    exit 1
fi

SECONDARY_CLUSTER_ID="$(cluster_id_by_name "$SECONDARY_CLUSTER_NAME")"

if [ -z "$SECONDARY_CLUSTER_ID" ]; then
    cluster_spec="$(mktemp)"

    cat > "$cluster_spec" <<EOF
{
  "name": "$SECONDARY_CLUSTER_NAME",
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

    SECONDARY_CLUSTER_ID=$(oneks create cluster --file "$cluster_spec" | sed -n 's/^ID: *//p')
fi

wait_for_cluster "$SECONDARY_CLUSTER_ID"

SECONDARY_READY_NODES="$(wait_for_ready_nodes "$SECONDARY_CLUSTER_ID")"

TENANCY_ID="opennebula:${ONE_XMLRPC:-default}"
NETWORK_ID="$PRIVATE_NETWORK_ID"

jq -n \
    --arg tenancy_id "$TENANCY_ID" \
    --arg network_id "$NETWORK_ID" \
    --arg primary_name "$PRIMARY_CLUSTER_NAME" \
    --arg secondary_name "$SECONDARY_CLUSTER_NAME" \
    --argjson secondary_ready_nodes "$SECONDARY_READY_NODES" \
    '{
      success: true,
      platform: "kubernetes",
      test_id: "K8S26-01",
      tenancy_id: $tenancy_id,
      network_id: $network_id,
      clusters: [
        {
          name: $primary_name,
          role: "primary",
          tenancy_id: $tenancy_id,
          network_id: $network_id,
          status: "ACTIVE"
        },
        {
          name: $secondary_name,
          role: "secondary",
          tenancy_id: $tenancy_id,
          network_id: $network_id,
          status: "ACTIVE",
          ready_node_count: $secondary_ready_nodes
        }
      ]
    }'
