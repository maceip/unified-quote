#!/bin/bash
set -euo pipefail

# ===========================================================================
# Deploy an AWS AMD SEV-SNP instance for a live Runcard node.
#
# SEV-SNP on AWS exposes /dev/sev-guest to the guest, and SNP_GET_EXT_REPORT
# returns the VCEK cert table inline — so the node produces a fully
# self-verifiable quote (no live AMD KDS dependency from the verifier).
#
# Prerequisites:
#   - AWS CLI authenticated (aws sts get-caller-identity works)
#   - An EC2 key pair, or set CREATE_KEY=1 to generate one
#
# Usage:
#   ./deploy/aws-snp.sh
#
# Optional environment overrides:
#   AWS_REGION=us-east-2
#   INSTANCE_TYPE=c6a.xlarge        # AMD, SEV-SNP capable
#   KEY_NAME=runcard-snp
#   CREATE_KEY=1                    # generate KEY_NAME.pem locally if missing
# ===========================================================================

AWS_REGION="${AWS_REGION:-us-east-2}"
INSTANCE_TYPE="${INSTANCE_TYPE:-c6a.xlarge}"
KEY_NAME="${KEY_NAME:-runcard-snp}"
SG_NAME="${SG_NAME:-runcard-snp-sg}"
CREATE_KEY="${CREATE_KEY:-1}"

echo "=== Deploying AWS SEV-SNP node ==="
echo "  Region:   ${AWS_REGION}"
echo "  Type:     ${INSTANCE_TYPE} (AMD SEV-SNP)"
echo ""

if ! aws sts get-caller-identity --output none 2>/dev/null; then
    echo "ERROR: AWS CLI is not authenticated." >&2
    exit 1
fi

# Latest Ubuntu 24.04 x86_64 AMI (Canonical owner 099720109477).
AMI_ID="$(aws ec2 describe-images \
    --region "${AWS_REGION}" \
    --owners 099720109477 \
    --filters \
        'Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*' \
        'Name=state,Values=available' \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
    --output text)"
echo "  AMI:      ${AMI_ID}"

# Key pair
if [ "${CREATE_KEY}" = "1" ] && ! aws ec2 describe-key-pairs --region "${AWS_REGION}" --key-names "${KEY_NAME}" >/dev/null 2>&1; then
    echo "Creating key pair ${KEY_NAME} -> ${KEY_NAME}.pem"
    aws ec2 create-key-pair --region "${AWS_REGION}" --key-name "${KEY_NAME}" \
        --query 'KeyMaterial' --output text > "${KEY_NAME}.pem"
    chmod 600 "${KEY_NAME}.pem"
fi

# Security group: allow SSH (22) and attested-TLS (443)
SG_ID="$(aws ec2 describe-security-groups --region "${AWS_REGION}" \
    --filters "Name=group-name,Values=${SG_NAME}" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")"
if [ "${SG_ID}" = "None" ] || [ -z "${SG_ID}" ]; then
    SG_ID="$(aws ec2 create-security-group --region "${AWS_REGION}" \
        --group-name "${SG_NAME}" --description "Runcard SNP node" \
        --query 'GroupId' --output text)"
    aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" \
        --group-id "${SG_ID}" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
    aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" \
        --group-id "${SG_ID}" --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
fi
echo "  SG:       ${SG_ID}"

echo "Launching instance with SEV-SNP enabled..."
INSTANCE_ID="$(aws ec2 run-instances --region "${AWS_REGION}" \
    --image-id "${AMI_ID}" \
    --instance-type "${INSTANCE_TYPE}" \
    --key-name "${KEY_NAME}" \
    --security-group-ids "${SG_ID}" \
    --cpu-options AmdSevSnp=enabled \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":30}}]' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=runcard-snp}]' \
    --query 'Instances[0].InstanceId' --output text)"
echo "  Instance: ${INSTANCE_ID}"

aws ec2 wait instance-running --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}"
PUBLIC_IP="$(aws ec2 describe-instances --region "${AWS_REGION}" \
    --instance-ids "${INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"

echo ""
echo "=== Deployment Complete ==="
echo "  Instance:  ${INSTANCE_ID}"
echo "  Public IP: ${PUBLIC_IP}"
echo ""
echo "Next: copy the verifier + a source tree, then build/run/check:"
echo "  scp -i ${KEY_NAME}.pem dist/bountynet-linux-x86_64 ubuntu@${PUBLIC_IP}:~/runcard"
echo "  ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP}"
echo "    ls /dev/sev-guest /sys/kernel/config/tsm/report   # at least one must exist"
echo "    sudo ./runcard build ~/source --cmd 'echo build' --output ~/out"
echo "    sudo ./runcard run ~/source --attestation ~/out/attestation.cbor   # serves :443"
echo ""
echo "Then register the node for the live dashboard by setting its endpoint in"
echo "deploy/nodes.config.json:  \"endpoint\": \"https://${PUBLIC_IP}/\""
echo ""
echo "Tear down:"
echo "  aws ec2 terminate-instances --region ${AWS_REGION} --instance-ids ${INSTANCE_ID}"
