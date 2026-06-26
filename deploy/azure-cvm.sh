#!/bin/bash
set -euo pipefail

# ===========================================================================
# Deploy an Azure Confidential VM for unified-quote hardware validation.
#
# Prerequisites:
#   - Azure CLI authenticated: az login
#   - Subscription quota for the selected Confidential VM family/region
#
# Usage:
#   ./deploy/azure-cvm.sh
#
# Optional environment overrides:
#   AZURE_LOCATION=northeurope
#   AZURE_RESOURCE_GROUP=uq-tee-validation
#   VM_NAME=uq-azure-snp
#   VM_SIZE=Standard_DC4as_v5
#   ADMIN_USERNAME=azureuser
#   AZURE_IMAGE='Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest'
# ===========================================================================

LOCATION="${AZURE_LOCATION:-northeurope}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-uq-tee-validation}"
VM_NAME="${VM_NAME:-uq-azure-snp}"
VM_SIZE="${VM_SIZE:-Standard_DC4as_v5}"
ADMIN_USERNAME="${ADMIN_USERNAME:-azureuser}"
IMAGE="${AZURE_IMAGE:-Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest}"
OS_ENCRYPTION_TYPE="${OS_ENCRYPTION_TYPE:-VMGuestStateOnly}"

echo "=== Deploying Azure Confidential VM ==="
echo "  Resource group: ${RESOURCE_GROUP}"
echo "  Location:       ${LOCATION}"
echo "  VM:             ${VM_NAME}"
echo "  Size:           ${VM_SIZE}"
echo "  Image:          ${IMAGE}"
echo ""

if ! az account show --output none 2>/dev/null; then
    echo "ERROR: Azure CLI is not authenticated. Run: az login" >&2
    exit 1
fi

echo "Creating resource group..."
az group create \
    --name "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --output table

if az vm show --resource-group "${RESOURCE_GROUP}" --name "${VM_NAME}" --output none 2>/dev/null; then
    echo "VM ${VM_NAME} already exists in ${RESOURCE_GROUP}; refusing to replace it." >&2
    echo "Delete it first with: az vm delete -g ${RESOURCE_GROUP} -n ${VM_NAME}" >&2
    exit 1
fi

echo "Creating Confidential VM..."
az vm create \
    --resource-group "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --name "${VM_NAME}" \
    --size "${VM_SIZE}" \
    --admin-username "${ADMIN_USERNAME}" \
    --image "${IMAGE}" \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type "${OS_ENCRYPTION_TYPE}" \
    --enable-vtpm true \
    --enable-secure-boot true \
    --public-ip-sku Standard \
    --generate-ssh-keys \
    --output json

echo "Opening TCP/443 for the stage 1 attested-TLS server..."
az vm open-port \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --port 443 \
    --priority 1043 \
    --output table

PUBLIC_IP="$(az vm show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --show-details \
    --query publicIps \
    --output tsv)"

echo ""
echo "=== Deployment Complete ==="
echo "  VM:        ${VM_NAME}"
echo "  Public IP: ${PUBLIC_IP}"
echo ""
echo "Next validation steps:"
echo "  scp v2/target/release/uq ${ADMIN_USERNAME}@${PUBLIC_IP}:~/uq"
echo "  ssh ${ADMIN_USERNAME}@${PUBLIC_IP}"
echo "  ls /dev/sev-guest /sys/kernel/config/tsm/report 2>&1"
echo ""
echo "Note: Azure DCasv5 CVMs may use the vTOM/paravisor path and not expose"
echo "      raw SNP report collection to the guest. If /dev/sev-guest is absent"
echo "      and configfs-tsm report creation fails, unified-quote needs an Azure"
echo "      MAA/vTOM collector before stage0/stage1 can be marked verified."
echo ""
echo "  sudo ~/uq build ~/source --cmd 'echo stage0 build' --output ~/out"
echo "  sudo ~/uq run ~/source --attestation ~/out/attestation.cbor"
