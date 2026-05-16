#!/usr/bin/env bash
# ── CVEs Enterprise Platform — Operator Installation Script ──────────────────
# Run ONCE against a fresh cluster BEFORE applying any other manifests.
# Requires: kubectl configured + cluster admin permissions
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

STRIMZI_VERSION="0.44.0"
CNPG_VERSION="1.24.0"
KEDA_VERSION="2.16.0"
NGINX_INGRESS_VERSION="1.12.1"

echo "==> [1/4] Installing Strimzi Kafka Operator ${STRIMZI_VERSION} in cves-infra..."
kubectl create namespace cves-infra --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "https://strimzi.io/install/latest?namespace=cves-infra" \
  --server-side --field-manager=strimzi
kubectl -n cves-infra rollout status deployment/strimzi-cluster-operator --timeout=180s

echo "==> [2/4] Installing CloudNativePG Operator ${CNPG_VERSION}..."
kubectl apply -f \
  "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-${CNPG_VERSION%.*}/releases/cnpg-${CNPG_VERSION}.yaml" \
  --server-side
kubectl -n cnpg-system rollout status deployment/cnpg-controller-manager --timeout=180s

echo "==> [3/4] Installing KEDA ${KEDA_VERSION}..."
kubectl apply -f \
  "https://github.com/kedacore/keda/releases/download/v${KEDA_VERSION}/keda-${KEDA_VERSION}.yaml" \
  --server-side
kubectl -n keda rollout status deployment/keda-operator --timeout=180s
kubectl -n keda rollout status deployment/keda-operator-metrics-apiserver --timeout=180s

echo "==> [4/4] Installing NGINX Ingress Controller ${NGINX_INGRESS_VERSION}..."
kubectl apply -f \
  "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v${NGINX_INGRESS_VERSION}/deploy/static/provider/aws/deploy.yaml" \
  --server-side
kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=180s

echo ""
echo "All operators installed and ready."
echo ""
echo "Next steps:"
echo "  1. Create Secrets: kubectl apply -f k8s/secrets/"
echo "  2. Apply namespaces: kubectl apply -f k8s/namespaces.yaml"
echo "  3. Apply RBAC: kubectl apply -f k8s/rbac/"
echo "  4. Deploy infra: kubectl apply -f k8s/infra/ --recursive"
echo "  5. Wait for Kafka cluster READY, then deploy topics:"
echo "     kubectl wait kafka/cves-kafka -n cves-infra --for=condition=Ready --timeout=300s"
echo "     kubectl apply -f k8s/infra/kafka/kafka-topics.yaml"
echo "  6. Deploy services: kubectl apply -f k8s/services/ --recursive"
echo "  7. Deploy observability: kubectl apply -f k8s/observability/ --recursive"
echo "  8. Apply network policies: kubectl apply -f k8s/networkpolicies/"
