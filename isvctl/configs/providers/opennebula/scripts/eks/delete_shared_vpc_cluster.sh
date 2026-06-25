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

# Delete the secondary OpenNebula Kubernetes cluster created for K8S26-01.

set -eo pipefail

SECONDARY_CLUSTER_NAME="${ONE_SECONDARY_CLUSTER_NAME:-isv-k8s-cluster-shared-vnet}"

if ! command -v oneks &> /dev/null; then
    echo "Error: oneks not found" >&2
    exit 1
fi

CLUSTER_ID=$(oneks list cluster | awk -v cn="$SECONDARY_CLUSTER_NAME" '$4==cn {print $1; exit}')

if [ -n "$CLUSTER_ID" ]; then
    oneks delete cluster "$CLUSTER_ID" >&2
    RESOURCES_DELETED="[\"cluster/${SECONDARY_CLUSTER_NAME}\"]"
else
    RESOURCES_DELETED="[]"
fi

cat <<EOF
{
  "success": true,
  "platform": "kubernetes",
  "message": "Shared-VNet test cluster teardown completed",
  "cluster_name": "$SECONDARY_CLUSTER_NAME",
  "resources_deleted": $RESOURCES_DELETED
}
EOF
