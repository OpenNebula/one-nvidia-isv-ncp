#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

# OpenNebula Kubernetes Teardown Stub

set -eo pipefail

echo "Tearing down OpenNebula GPU Cluster..." >&2

CLUSTER_NAME="${ONE_CLUSTER_NAME:-isv-k8s-cluster}"

CLUSTER_ID=$(oneks list cluster | awk -v cn="$CLUSTER_NAME" '$4==cn {print $1}')

if [ -n "$CLUSTER_ID" ]; then
  oneks delete cluster "$CLUSTER_ID"
fi

cat << EOF
{
  "platform": "opennebula",
  "success": true,
  "message": "Cluster teardown initiated successfully",
  "resources_deleted": true
}
EOF