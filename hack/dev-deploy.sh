#!/usr/bin/env bash

set -o errexit

IMG=$1
TMP_DIR="$(git rev-parse --show-toplevel)/tmp"

mkdir -p ${TMP_DIR}

cat << EOF | tee ${TMP_DIR}/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: sourcer-system
namePrefix: sourcer-
bases:
- ../config/crd
- ../config/rbac
- ../config/manager
EOF

cd ${TMP_DIR} && kustomize edit set image fluxcd/sourcer=${IMG}
kustomize build ${TMP_DIR} | kubectl apply -f -
rm -rf ${TMP_DIR}
kubectl -n sourcer-system rollout status deploy/sourcer-controller --timeout=1m
