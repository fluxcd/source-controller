kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        service-account-jwks-uri: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REG_LOCALHOST_PORT}"]
    endpoint = ["http://${CLUSTER_NAME}-registry:5000"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."${CLUSTER_NAME}-registry:5000"]
    endpoint = ["http://${CLUSTER_NAME}-registry:5000"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REG2_LOCALHOST_PORT}"]
    endpoint = ["http://${CLUSTER_NAME}-registry2:5000"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."${CLUSTER_NAME}-registry2:5000"]
    endpoint = ["http://${CLUSTER_NAME}-registry2:5000"]
