# Deploying RBS on Kubernetes

> Execute the chapters in order. Every command is followed by its expected output — **if they don't match, stop and troubleshoot per chapter 8**; do not continue in a broken state.
> After chapters 1–5 you have: RBS running in the cluster, probes `/livez` and `/readyz` returning 200, and the business API reachable from outside via `https://<NODE_IP>:30666`.
> Chapter 6 connects a real GTA (chapters 1–5 run completely without one: deployment, probes and business verification do not depend on GTA). Chapter 7 is entirely optional.

**Table of contents**

- [0. Environment self-check](#0-environment-self-check)
- [1. Start a cluster](#1-start-a-cluster)
- [2. Build and load the image](#2-build-and-load-the-image)
- [3. Generate certificates and keys](#3-generate-certificates-and-keys)
- [4. Deploy](#4-deploy)
- [5. Verify](#5-verify)
- [6. Connect a GTA](#6-connect-a-gta)
- [7. Optional paths](#7-optional-paths-not-required-for-the-main-line)
- [8. Troubleshooting](#8-troubleshooting)
- [9. Integrate the Vault resource backend (OpenBao)](#9-integrate-the-vault-resource-backend-openbao)
- [10. Integrate the HSM resource backend (SoftHSM2)](#10-integrate-the-hsm-resource-backend-softhsm2)
- [11. Integrate the CA resource backend (XiPKI)](#11-integrate-the-ca-resource-backend-xipki)

**Requirements**

| Item | Requirement |
|---|---|
| Machine | ≥ 4 CPUs / 8 GB RAM / 20 GB free disk |
| OS | Linux |
| Tools | git, Docker, kubectl v1.30+, openssl, curl |
| Cluster tool | minikube (main line) or kind (equivalent commands in each chapter) |
| GTA service | only needed in chapter 6 (base URL, credentials user_id, token-signing public key) |

## 0. Environment self-check

```bash
for c in git kubectl docker openssl curl; do
  command -v "$c" >/dev/null 2>&1 && echo "[OK]      $c" || echo "[MISSING] $c"
done
if command -v minikube >/dev/null 2>&1; then echo "[OK]      minikube"
elif command -v kind >/dev/null 2>&1; then echo "[OK]      kind"
else echo "[MISSING] minikube or kind"; fi
free -h | awk '/^Mem:/{print "Memory: "$2}'
```

All `[OK]` passes. Install kubectl/minikube per 1.1; install git/openssl/curl with your package manager.

## 1. Start a cluster

> Chapter output: a running cluster + `NODE_IP` (used in chapters 3, 5, 6 — write it down).
> Pick 1.1 (minikube) **or** 1.2 (kind); after 1.1 succeeds go straight to 1.3.

### 1.1 minikube (main line)

```bash
# Install (skip if present)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -LO "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-$ARCH"
sudo install minikube-linux-$ARCH /usr/local/bin/minikube && rm -f minikube-linux-$ARCH
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/$ARCH/kubectl"
sudo install -m 0755 kubectl /usr/local/bin/kubectl && rm -f kubectl

# Start (root users must add --force)
minikube start --cpus=4 --memory=8g
```

Success ends with `Done! kubectl is now configured to use "minikube" cluster`.

### 1.2 kind

```bash
# Install (skip if present)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-$ARCH"
sudo install ./kind /usr/local/bin/kind && rm -f ./kind

# Create the cluster
kind create cluster --name rbs
```

### 1.3 Record the node IP

```bash
# minikube
NODE_IP=$(minikube ip)
echo "NODE_IP=$NODE_IP"
```

```bash
# kind
NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
echo "NODE_IP=$NODE_IP"
```

```text
NODE_IP=192.168.49.2
```

> Both forms read the node IP locally without contacting the API server, so they keep working even when exported proxy variables make kubectl fail with `Unable to connect to the server: Gateway Time-out` (see the proxy note in chapter 2). On minikube, add `-p <profile>` when multiple profiles exist.

## 2. Build and load the image

> Chapter output: the image `globaltrustauthority-rbs/rbs:latest` available inside the cluster.
> Run from the repository root (clone first if you haven't).
> How the build works in one sentence: `docker build` first downloads two **base images** — `rust:1.88` (compile environment) and `openeuler/openeuler:24.03-lts` (runtime OS) — compiles the RBS sources in the former and packs the result into the latter. **Most build errors happen while downloading the base images** (the RBS code is not even involved yet); see the note below.

**Build** (first build compiles all dependencies — tens of minutes is normal; the required clang is installed inside the Dockerfile):

```bash
docker build -f deployment/docker/dockerfile -t globaltrustauthority-rbs/rbs:latest .
```

Success ends with `naming to docker.io/globaltrustauthority-rbs/rbs:latest done`.
> If the build reports `failed size validation: xxx != xxx` or `failed to resolve source metadata` (registry-mirror cache corruption; after 1–2 retries run the block below to bypass it — no daemon changes, no restart): once the base images are local, the build no longer contacts the mirror.
> ```bash
> # 1) Pull both base images via an alternate mirror (explicit prefix goes direct,
> #    bypassing the mirror configured in the daemon)
> docker pull docker.m.daocloud.io/openeuler/openeuler:24.03-lts
> docker tag docker.m.daocloud.io/openeuler/openeuler:24.03-lts openeuler/openeuler:24.03-lts
> docker pull docker.m.daocloud.io/library/rust:1.88
> docker tag docker.m.daocloud.io/library/rust:1.88 rust:1.88
>
> # 2) Build again (base images are local now; the mirror is not consulted)
> docker build -f deployment/docker/dockerfile -t globaltrustauthority-rbs/rbs:latest .
> ```
> If the alternate mirror fails too, try other prefixes (`dockerproxy.net`, `docker.1ms.run`), or change `registry-mirrors` in `/etc/docker/daemon.json` and run `sudo systemctl restart docker`.


> Build containers **do not inherit the shell's proxy variables**: on hosts that need `export http_proxy` (etc.) to reach the internet, the build fails with `Couldn't resolve host name` (dnf/apt/cargo downloads). Inject the proxy (set `https_proxy` too if missing — usually the same value). **Always pair the proxy with the cluster-address exclusion** — a proxy without `no_proxy` also breaks every later kubectl/curl/rbs-cli call to the cluster:
> ```bash
> export https_proxy=$http_proxy    # set if missing (usually the same value)
> # Mandatory companion of the proxy: without it, kubectl/curl/rbs-cli requests to
> # cluster addresses are hijacked and fail with 504 Gateway Time-out
> export no_proxy="localhost,127.0.0.1,$(minikube ip)"    # kind: use the rbs-control-plane container IP
> export NO_PROXY="$no_proxy"
> docker build -f deployment/docker/dockerfile -t globaltrustauthority-rbs/rbs:latest \
>   --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy .
> ```
> If dnf/apt/cargo then report `SSL peer certificate ... self-signed certificate in certificate chain`: the proxy performs TLS interception — extract its CA chain and inject trust (`host-ca-bundle.pem` is created in the repository root; the block is re-runnable):
> ```bash
> openssl s_client -proxy ${http_proxy#http://} -connect mirrors.openeuler.org:443 -showcerts </dev/null 2>/dev/null \
>   | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{print}' > host-ca-bundle.pem
> grep -c "BEGIN CERTIFICATE" host-ca-bundle.pem    # expect >= 1; 0 means the proxy handshake failed
> docker build -f deployment/docker/dockerfile -t globaltrustauthority-rbs/rbs:latest \
>   --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy \
>   --build-arg CA_BUNDLE="$(cat host-ca-bundle.pem)" .
> ```

> **Symptom — kubectl reports `Unable to connect to the server: Gateway Time-out`**: kubectl honors the exported proxy variables like any HTTP client, and the proxy cannot reach cluster-internal addresses; the error text is the proxy's 504 answer (a dead API server reports `connection refused`/`i/o timeout` instead). The fix is the mandatory `no_proxy`/`NO_PROXY` pair from the block above — when in doubt, check `echo $no_proxy`.

**Verify the image exists**:

```bash
docker images | grep globaltrustauthority-rbs
```

```text
globaltrustauthority-rbs/rbs   latest   xxxxxxxxxx   x minutes ago   xxxMB
```

**Load into the cluster** (clusters do not read host images by default):

```bash
# minikube
minikube image load globaltrustauthority-rbs/rbs:latest
minikube image ls --format table | grep rbs
```

```bash
# kind
kind load docker-image globaltrustauthority-rbs/rbs:latest --name rbs
docker exec rbs-control-plane ctr --namespace k8s.io images ls | grep rbs
```

One `globaltrustauthority-rbs/rbs` line means success.

> If minikube reports `The image ... was not found` or kind reports `failed to detect containerd snapshotter`, fall back to ctr import (minikube's node container is `minikube`, kind's is `<cluster-name>-control-plane`):
> ```bash
> docker save globaltrustauthority-rbs/rbs:latest | docker exec -i minikube ctr --namespace k8s.io images import -
> ```

## 3. Generate certificates and keys

> Chapter output: the `rbs-k8s-deploy/` directory with 5 files (TLS pair, admin pair, placeholder GTA signing key).
> Chapter 4 references these files directly. Run from the repository root.

```bash
mkdir -p rbs-k8s-deploy && cd rbs-k8s-deploy
NODE_IP=$(minikube ip)   # kind: NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
echo "NODE_IP=$NODE_IP"

# 1) TLS server certificate (SAN must contain the node IP — business verification uses it)
openssl req -x509 -newkey rsa:2048 -keyout tls.key -out tls.crt -days 365 -nodes \
  -subj "/CN=rbs.local" \
  -addext "subjectAltName=DNS:rbs.local,DNS:localhost,IP:${NODE_IP},IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

# 2) Administrator key pair (bootstraps the Administrator, signs admin JWTs)
openssl genrsa -out admin_key.pem 2048
openssl rsa -in admin_key.pem -pubout -out admin_pub.pem

# 3) GTA token-signing public key (placeholder; replaced in chapter 6)
openssl genrsa -out attest_key.pem 2048
openssl rsa -in attest_key.pem -pubout -out attest_pub.pem

cd ..
```

**Verify** (all 5 files present + SAN contains the node IP):

```bash
ls rbs-k8s-deploy/{tls.key,tls.crt,admin_key.pem,admin_pub.pem,attest_key.pem,attest_pub.pem}
openssl x509 -in rbs-k8s-deploy/tls.crt -noout -text | grep -A1 "Subject Alternative Name"
```

```text
X509v3 Subject Alternative Name:
    DNS:rbs.local, DNS:localhost, IP Address:192.168.49.2, IP Address:127.0.0.1
```

## 4. Deploy

> Chapter output: RBS running in namespace `rbs`. **Order matters**: namespace → Secrets/ConfigMap → remaining manifests (the Deployment references them).
> Prerequisite when the shell exports proxy variables: export the `no_proxy`/`NO_PROXY` pair from chapter 2 first — otherwise every command below fails with `Unable to connect to the server: Gateway Time-out`.
> When re-running this chapter — after a failure, or to redeploy over a running instance — clean up first: otherwise `create` reports `already exists`, and `apply` on an unchanged manifest leaves the old pod running (same AGE, old image/config):
> ```bash
> kubectl delete deployment rbs -n rbs --ignore-not-found
> kubectl delete secret rbs-tls rbs-config -n rbs --ignore-not-found
> kubectl delete configmap rbs-keys -n rbs --ignore-not-found
> ```
> Do **not** delete the `rbs-data` PVC — it holds the SQLite database, and chapter 5 verifies data surviving redeploys. With the Deployment deleted, step 5's `apply` re-creates it and the new pod mounts the fresh Secrets/ConfigMap and the newly loaded image. Alternatively, keep the Deployment and finish with the rollout restart shown in step 6.

**1) Create the namespace** (first):

```bash
kubectl apply -f deployment/k8s/namespace.yaml
# expected: namespace/rbs created
```

**2) Create the TLS Secret**:

```bash
kubectl create secret tls rbs-tls -n rbs \
  --cert=rbs-k8s-deploy/tls.crt --key=rbs-k8s-deploy/tls.key
kubectl get secret rbs-tls -n rbs
# expected: rbs-tls   kubernetes.io/tls   2   xs
```

**3) Generate the runtime config and create its Secret** (copy the whole block; the two variables only change in chapter 6):

```bash
GTA_BASE_URL=https://127.0.0.1:8083   # ← change to the real GTA address in chapter 6
GTA_USER_ID=rbs-service               # ← change to the real GTA credentials user_id in chapter 6

cat > rbs-k8s-deploy/rbs.yaml <<EOF
rest:
  listen_addr: "0.0.0.0:6666"
  https:
    enabled: true
    cert_file: "/etc/rbs/tls/tls.crt"
    key_file: "/etc/rbs/tls/tls.key"

health:
  listen_addr: "0.0.0.0:6667"

logging:
  level: info
  format: text

auth:
  attest_token:
    public_key_path: "/etc/rbs/keys/attest_pub.pem"
    issuer: "Global Trust Authority"
  bearer_token:
    issuer: "rbs-cli"
    audience: "globaltrustauthority-rbs"

admin:
  admin_key:
    public_key_path: "/etc/rbs/keys/admin_pub.pem"

policy:
  max_per_user: 10

attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: rest
      rest:
        base_url: "${GTA_BASE_URL}"
        timeout_secs: 30
        retries: 3
        tls_verify: true
        ca_file: ""
        credentials:
          user_id: "${GTA_USER_ID}"
          api_key_auth: false
          main_api_key: ""
          sub_api_key: ""

storage:
  db_type: sqlite
  max_connections: 10
  timeout: 30
  url: "sqlite:///var/lib/rbs/rbs.db?mode=rwc"
  sql_file_path: "/usr/share/rbs/sqlite_rbs.sql"
EOF

kubectl create secret generic rbs-config -n rbs --from-file=rbs.yaml=rbs-k8s-deploy/rbs.yaml
kubectl get secret rbs-config -n rbs
# expected: rbs-config   Opaque   1   xs
```

**4) Create the public-key ConfigMap** (public keys are non-secret; created straight from files):

```bash
kubectl create configmap rbs-keys -n rbs \
  --from-file=admin_pub.pem=rbs-k8s-deploy/admin_pub.pem \
  --from-file=attest_pub.pem=rbs-k8s-deploy/attest_pub.pem
kubectl get configmap rbs-keys -n rbs
# expected: rbs-keys   1   xs
```

**5) Apply the remaining manifests** (order matters: PVC → Deployment → Service):

```bash
kubectl apply -f deployment/k8s/pvc.yaml
# expected: persistentvolumeclaim/rbs-data created

kubectl apply -f deployment/k8s/deployment.yaml
# expected: deployment.apps/rbs created

kubectl apply -f deployment/k8s/service.yaml
# expected: service/rbs created
```

> All at once: `kubectl apply -f deployment/k8s/` also works (the namespace from step 1 is re-applied and reported unchanged; `optional/` is skipped — kubectl does not recurse into subdirectories by default). Files are processed in alphabetical order, so the Deployment is created before the PVC binds and the pod stays `Pending` a few seconds longer; the explicit sequence above avoids that transient state.

**6) Wait for the pod** (first start runs the SQL migration and admin bootstrap, within ~30s):

> Re-running over an existing deployment: if `apply` reported `deployment.apps/rbs unchanged`, the old pod keeps running (same AGE) — deleting/recreating the Secrets does not restart it either, because the running process read that content at startup. Restart it so the new pod picks up the fresh Secrets/config and the newly loaded image:
> ```bash
> kubectl rollout restart deployment/rbs -n rbs
> kubectl rollout status deployment/rbs -n rbs --timeout=120s
> ```

```bash
kubectl get pods -n rbs -w
```

`READY 1/1` succeeds (Ctrl+C to leave the watch):

```text
NAME                   READY   STATUS    RESTARTS   AGE
rbs-xxxxxxxxx-xxxxx    1/1     Running   0          40s
```

> Stuck? Go to [8. Troubleshooting](#8-troubleshooting).

## 5. Verify

> Chapter output: probes and business API fully verified.

**1) Probe endpoints** (health port 6667 is not exposed; verify via port-forward):

```bash
kubectl port-forward -n rbs deploy/rbs 16667:6667 &
PF=$!
sleep 1
curl -s http://localhost:16667/livez;  echo   # expected {"status":"ok"}
curl -s http://localhost:16667/readyz; echo   # expected {"status":"ok"} (includes SQLite)
kill $PF
```

**2) Business API** (from outside the cluster via NodePort 30666, TLS verified with the chapter-3 certificate):

```bash
NODE_IP=$(minikube ip)   # kind: NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
curl -s --cacert rbs-k8s-deploy/tls.crt "https://${NODE_IP}:30666/rbs/version"
```

```text
{"service_name":"globaltrustauthority-rbs","api_version":"0",...}
```

> Local port busy? Change the first number of the port-forward (e.g. `26667:6667`) and the curl URL accordingly.
> NodePort curl times out: typical on Docker Desktop / cross-machine access — see 8.4.

**3) Data persistence** (optional check; the admin is not re-created and data survives a pod restart):

```bash
kubectl delete pod -n rbs -l app=rbs
sleep 20
kubectl get pods -n rbs                                   # expected: new pod READY 1/1
kubectl logs -n rbs deploy/rbs | grep -i bootstrap | tail -1
# expected: Admin bootstrap check completed (no "creating" line = existing users detected)
```

## 6. Connect a GTA

> Chapter output: RBS calls the real GTA for challenge. Prerequisites: a reachable GTA (outside the cluster) with its base URL, credentials user_id, token-signing public key, and CA/client certificates (generated by the GTA deployment guide).

**1) Replace the placeholder signing key** (save the GTA's public key as `rbs-k8s-deploy/attest_pub.pem`, then):

```bash
kubectl delete configmap rbs-keys -n rbs
kubectl create configmap rbs-keys -n rbs \
  --from-file=admin_pub.pem=rbs-k8s-deploy/admin_pub.pem \
  --from-file=attest_pub.pem=rbs-k8s-deploy/attest_pub.pem
```

**2) Mount GTA certificates and update the config** (copy the whole block; only change the first two variables and the certificate paths):

> **Why certificates must be mounted**: RBS calls the GTA over HTTPS (self-signed certificate + mTLS mutual authentication). It needs to trust the GTA's CA (`ca_file`) and present a client certificate (`client_cert_path`/`client_key_path`). Certificate files must be **mounted inside the RBS container** — host paths (e.g. `/home/xxx/...`) are invisible inside the container; writing host paths causes a startup panic.

```bash
# ===== 2.1 Create the GTA certificate Secret (change paths to your actual certificate locations) =====
kubectl create secret generic gta-certs -n rbs \
  --from-file=ca.crt=/home/xxx/global-trust-authority/gta-certs/ca.crt \
  --from-file=client.crt=/home/xxx/global-trust-authority/gta-certs/client.crt \
  --from-file=client.key=/home/xxx/global-trust-authority/gta-certs/client.key

# ===== 2.2 Mount the certificates into the RBS pod =====
kubectl patch deployment rbs -n rbs --type='json' -p='[
  {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"gta-certs","secret":{"secretName":"gta-certs"}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"gta-certs","mountPath":"/etc/rbs/gta-certs","readOnly":true}}
]'

# ===== 2.3 Generate the config (certificate paths point to the container-internal mount) =====
GTA_BASE_URL=https://192.168.1.100:8083   # ← your GTA's real address: IP:port (reachable from the cluster; a domain name works too)
GTA_USER_ID=rbs-service                     # ← the real GTA credentials user_id

cat > rbs-k8s-deploy/rbs.yaml <<EOF
rest:
  listen_addr: "0.0.0.0:6666"
  https:
    enabled: true
    cert_file: "/etc/rbs/tls/tls.crt"
    key_file: "/etc/rbs/tls/tls.key"

health:
  listen_addr: "0.0.0.0:6667"

logging:
  level: info
  format: text

auth:
  attest_token:
    public_key_path: "/etc/rbs/keys/attest_pub.pem"
    issuer: "Global Trust Authority"
  bearer_token:
    issuer: "rbs-cli"
    audience: "globaltrustauthority-rbs"

admin:
  admin_key:
    public_key_path: "/etc/rbs/keys/admin_pub.pem"

policy:
  max_per_user: 10

attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: rest
      rest:
        base_url: "${GTA_BASE_URL}"
        timeout_secs: 30
        retries: 3
        tls_verify: true
        ca_file: "/etc/rbs/gta-certs/ca.crt"
        client_cert_path: "/etc/rbs/gta-certs/client.crt"
        client_key_path: "/etc/rbs/gta-certs/client.key"
        credentials:
          user_id: "${GTA_USER_ID}"
          api_key_auth: false
          main_api_key: ""
          sub_api_key: ""

storage:
  db_type: sqlite
  max_connections: 10
  timeout: 30
  url: "sqlite:///var/lib/rbs/rbs.db?mode=rwc"
  sql_file_path: "/usr/share/rbs/sqlite_rbs.sql"
EOF

# ===== 2.4 Update the Secret and restart =====
kubectl delete secret rbs-config -n rbs
kubectl create secret generic rbs-config -n rbs --from-file=rbs.yaml=rbs-k8s-deploy/rbs.yaml
kubectl rollout restart deployment/rbs -n rbs
```

> **Common mistake**: writing host paths (e.g. `/home/xxx/...`) for `ca_file` etc. — the container **cannot see the host filesystem**, and startup panics with `Failed to read CA certificate file: NotFound`. Certificate paths must point to the **container-internal mount point** `/etc/rbs/gta-certs/`.

**3) Wait for the rollout and verify challenge** (public endpoint, no auth):

```bash
kubectl rollout status deployment/rbs -n rbs --timeout=120s
NODE_IP=$(minikube ip)   # kind: NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
curl -s --cacert rbs-k8s-deploy/tls.crt "https://${NODE_IP}:30666/rbs/v0/challenge?attester_type=tpm"
```

A JSON containing `nonce` means success (HTTP 200). Errors: see 8.5.

## 7. Optional paths (not required for the main line)

### 7.1 Cross-machine NodePort access (agents / external clients)

> By default NodePorts are only reachable from the k8s host. External machines (e.g. the attestation_agent host) need routing + iptables rules — same approach as the GTA deployment guide section 6.3 (if you already set it up for GTA port 30443, you only need to add the 30666 iptables rules).

**Step 1: add a route on the external machine** (skip if already done for GTA):

```bash
# Route the cluster subnet via the k8s host (subnet = first three octets of the node IP + .0/24)
sudo ip route add 192.168.58.0/24 via <K8S_HOST_IP>
```

**Step 2: allow forwarding on the k8s host** (Docker's default FORWARD policy is DROP):

```bash
# Skip the 30443 rules if already added for GTA; only add the RBS 30666 ones
sudo iptables -A FORWARD -d 192.168.58.2 -p tcp --dport 30666 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.58.2 -p tcp --sport 30666 -j ACCEPT
```

**Step 3: verify from the external machine**:

```bash
curl -s --max-time 5 --cacert tls.crt "https://192.168.58.2:30666/rbs/version"
```

A `{"service_name":"globaltrustauthority-rbs",...}` response means success.

> Both `ip route` and `iptables` are lost on machine reboot — re-run them (or persist via systemd units / boot scripts).

### 7.2 Network hardening (NetworkPolicy)

> NOT enabled by default (chapter 4 only applies namespace/pvc/deployment/service — this file is not included). You MUST update the CIDR before applying, otherwise all external machines are blocked.

```bash
# 1) Find your cluster's node network
kubectl get nodes -o wide | awk '{print $6}' | tail -1
# example output: 192.168.58.2 -> network 192.168.58.0/24

# 2) Edit the CIDR (change to your node network + external client networks)
#    file: deployment/k8s/optional/networkpolicy.yaml
#    change cidr: 192.168.49.0/24 -> cidr: 192.168.58.0/24
#    add an extra ipBlock rule for external access if needed
vim deployment/k8s/optional/networkpolicy.yaml

# 3) Apply separately
kubectl apply -f deployment/k8s/optional/networkpolicy.yaml

# 4) Verify
kubectl get networkpolicy -n rbs
```

> Delete: `kubectl delete networkpolicy rbs-ingress -n rbs`. Silently ignored when the CNI does not support NetworkPolicy (kindnet; calico does).

### 7.3 Other

```bash
# LoadBalancer exposure (replace NodePort)
sed -i 's/type: NodePort/type: LoadBalancer/; /nodePort:/d' deployment/k8s/service.yaml
kubectl apply -f deployment/k8s/service.yaml

# Private registry
docker tag globaltrustauthority-rbs/rbs:latest <your-registry>/rbs:latest
docker push <your-registry>/rbs:latest
sed -i 's|image: globaltrustauthority-rbs/rbs:latest|image: <your-registry>/rbs:latest|' deployment/k8s/deployment.yaml
kubectl apply -f deployment/k8s/deployment.yaml
```

## 8. Troubleshooting

**Four-step method** (in order; each step narrows the problem):

```bash
kubectl describe pod -n rbs -l app=rbs            # 1. events: probe failures / unbound volumes / image pulls
kubectl logs -n rbs deploy/rbs --previous         # 2. last crash log: which config field / file failed
kubectl port-forward -n rbs deploy/rbs 16667:6667 &
curl -s http://localhost:16667/livez; kill %1     # 3. verify the health contract directly (bypasses probes)
kubectl get events -n rbs --sort-by=.lastTimestamp # 4. scheduling and volume events
```

**Symptom table**:

| Symptom | Cause | Fix |
|---|---|---|
| `kubectl` fails with `Unable to connect to the server: Gateway Time-out` | shell proxy variables hijack API-server requests | export the `no_proxy`/`NO_PROXY` pair with the node IP (chapter 2 proxy block) |
| Pod `Pending` | PVC unbound (no default StorageClass) | `kubectl get storageclass`; add `storageClassName:` in `pvc.yaml` and re-apply |
| Pod `ImagePullBackOff` | image not loaded into the cluster | re-run the chapter-2 load command (incl. the ctr fallback) |
| Pod `CrashLoopBackOff`, log mentions a config field | missing/invalid config value | fix `rbs-k8s-deploy/rbs.yaml` → update rbs-config via delete+create as in 4.3 → `kubectl rollout restart deployment/rbs -n rbs` |
| Pod `CrashLoopBackOff`, log mentions `health.listen_addr must differ` | health and rest share an address | make them differ, update rbs-config |
| Pod `CrashLoopBackOff`, log mentions `execute sql: No such file` | `storage.sql_file_path` points nowhere | keep the template value `/usr/share/rbs/sqlite_rbs.sql` (in-image path) |
| Pod `Running` but `READY 0/1` | readiness probe failing (SQLite unavailable or slow) | `kubectl logs -n rbs deploy/rbs` for "readiness probe"; check the PVC |
| NodePort `curl` times out | cross-machine routing / Docker Desktop bridge limits | see 8.4 |

### 8.4 NodePort unreachable (cross-machine / Docker Desktop)

The `<NODE_IP>` of minikube/kind is a container-bridge address reachable only from the host by default. With two machines:

```bash
# client machine: route the cluster subnet via the host (subnet = first three octets of NODE_IP + .0/24)
sudo ip route add 192.168.49.0/24 via <HOST_IP>

# host: allow 30666 when the docker FORWARD policy is DROP
sudo iptables -A FORWARD -p tcp --dport 30666 -j ACCEPT
sudo iptables -A FORWARD -p tcp --sport 30666 -j ACCEPT
```

When the Docker Desktop host itself cannot reach the node IP, fall back to port-forward:

```bash
kubectl port-forward -n rbs deploy/rbs 16666:6666 &
curl -s --cacert rbs-k8s-deploy/tls.crt https://localhost:16666/rbs/version
kill %1
```

### 8.5 challenge errors

Connection timeout/refused in `kubectl logs -n rbs deploy/rbs`: `GTA_BASE_URL` unreachable from inside the cluster (verify in the pod: `kubectl exec -n rbs deploy/rbs -- curl -sk --max-time 5 ${GTA_BASE_URL}`). 404: the attester_type value is not supported by the GTA. Certificate errors (`certificate verify failed` / `self-signed certificate`): follow **chapter 6 step 2** to mount GTA certificates and retry; if certificates are truly unavailable, set `tls_verify` to `false` (less secure, only works without mTLS).


## 9. Integrate the Vault resource backend (OpenBao)

> Chapter output: RBS reads secrets/certs from OpenBao and returns JWE-encrypted content. Prerequisites: chapter 6 (GTA) done; a reachable OpenBao service (outside the cluster).


### 9.0 Prerequisites (common to chapters 9/10/11)

The following tools and files are used across all three resource-backend chapters — prepare them once:

**1) rbs-cli** (resource policy/resource CRUD and JWE decryption):

```bash
# Option A: build from source (from the repo root)
cargo build -p rbs-cli --release
export PATH="$PATH:$(pwd)/target/release"

# Option B: install via RPM (see build_and_install.md)
```

**2) Admin Bearer Token** (required for all admin operations):

```bash
export BEARER_TOKEN="$(rbs-cli token gen --private-key-file rbs-k8s-deploy/admin_key.pem)"
```

**3) Attester key pair** (the attest token's `tee-pubkey`; RBS encrypts the JWE response with it, you decrypt with the paired private key):

```bash
openssl genrsa -out attester_private.pem 4096
openssl rsa -in attester_private.pem -pubout -out attester_public.pem
```

> **Note: this is NOT `attest_pub.pem`!** The two are easily confused but completely different:
>
> | | `attest_pub.pem` (configured in chapter 6) | `attester_public.pem` (generated in this step) |
> |---|---|---|
> | Belongs to | GTA (server side) | You (client side) |
> | Purpose | RBS verifies GTA-issued tokens are genuine | RBS encrypts resource content returned to you (JWE) |
> | Paired private key | On GTA's side (you don't have it) | In your hands (`attester_private.pem`) |
> | If mixed up | — | RBS encrypts with GTA's public key → you lack the private key → **decryption fails** |

> **Keep `attester_private.pem` safe** — all later `client get-resource --private-key-file attester_private.pem` decryptions depend on it, and it must be the same pair as `attester_public.pem`.

**4) attestation_agent** (a GTA-side component; `client get-token` needs it to collect evidence locally):

See the GTA client guide: [attestation_agent user guide](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/client/user_guide.md). Skip if already installed.

**5) Base variables** (shared across the three chapters):

```bash
NODE_IP=$(minikube ip)   # kind: NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
export RBS_URL="https://${NODE_IP}:30666"
```

**6) Proxy exclusion** (mandatory when `http_proxy`/`https_proxy` is set, otherwise kubectl/rbs-cli requests are hijacked by the proxy and fail with 504; same exclusion as the chapter 2 proxy note):

```bash
export no_proxy="${NODE_IP},localhost,127.0.0.1"
export NO_PROXY="${NODE_IP},localhost,127.0.0.1"
```

> **Why**: clients connecting to RBS (an internal node IP) do not need the proxy, but HTTP clients (kubectl, curl, rbs-cli) inherit shell proxy variables by default — the proxy doesn't know the internal address and returns 504 Gateway Timeout. `no_proxy` tells the client to connect directly to these addresses.

### 9.1 Start OpenBao and pre-create a secret

```bash
# On the OpenBao host (dev mode for functional verification; use a persistent deployment in production)
docker run -d --name rbs-openbao -p 8200:8200 \
  openbao/openbao server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200

# Health check
sleep 3
curl -s -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/sys/health

# Pre-create a secret (corresponds to RBS resource URI vault/default/secret/mykey)
curl -s -X POST -H "X-Vault-Token: root" -H "Content-Type: application/json" \
  -d '{"data":{"myvalue":"hello-vault","num":42}}' \
  http://127.0.0.1:8200/v1/secret/data/default/secret/mykey
```

### 9.2 Update the RBS config

Insert a `resource:` section before `storage:` in `rbs-k8s-deploy/rbs.yaml` (other sections unchanged), then update the Secret and restart:

```bash
sed -i '/^storage:/i\
resource:\
  backends:\
    vault:\
      type: vault\
      url: "http://<OPENBAO_IP>:8200"\
      token: "root"\
      mount_path: "secret"\
      kv_version: "v2"\
      verify_ssl: false\
      allowed_resource_types: ["secret", "cert"]' rbs-k8s-deploy/rbs.yaml

kubectl delete secret rbs-config -n rbs
kubectl create secret generic rbs-config -n rbs --from-file=rbs.yaml=rbs-k8s-deploy/rbs.yaml
kubectl rollout restart deployment/rbs -n rbs
kubectl rollout status deployment/rbs -n rbs --timeout=120s
```

> `<OPENBAO_IP>` = the IP of the machine running OpenBao (run `hostname -I | awk '{print $1}'` **on that machine**). It must be reachable from the RBS pod — same principle as the GTA address in chapter 6. Verify before applying:
> ```bash
> kubectl exec -n rbs deploy/rbs -- curl -s --max-time 5 http://<OPENBAO_IP>:8200/v1/sys/health
> ```
> In production, replace `token: "root"` with a dedicated token and set `verify_ssl: true` with a CA.

Verify registration:

```bash
kubectl logs -n rbs deploy/rbs | grep -i vault | tail -2
# expected: Registered resource backend 'vault' (type=vault, url=http://<OPENBAO_IP>:8200)
```

### 9.3 Create a resource policy and register the resource

Run on the **host**:

```bash
NODE_IP=$(minikube ip)   # kind: NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
export RBS_URL="https://${NODE_IP}:30666"
export BEARER_TOKEN="$(rbs-cli token gen --private-key-file rbs-k8s-deploy/admin_key.pem)"

# 1) Create a resource policy
cat > vault_policy.rego <<'EOF'
package verification
default allow = false
allow { true }
result = {"policy_matched": allow}
EOF

rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt -t "$BEARER_TOKEN" \
  res-policy create --name vault-policy --content @vault_policy.rego
export POLICY_ID="<the returned policy_id>"

# 2) Register the resource (reference only; writes nothing to OpenBao)
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt -t "$BEARER_TOKEN" \
  res create --uri vault/default/secret/mykey --policy-id "$POLICY_ID" --content-type json

# 3) Query metadata
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt -t "$BEARER_TOKEN" \
  res get-res-info --uri vault/default/secret/mykey
```

### 9.4 Get the resource content (attest token + JWE decryption)

```bash
# 1) Generate an attest token (requires GTA integration + local attestation_agent)
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt \
  client get-token --attester-pubkey @attester_public.pem -o /tmp/attest_token.jwt

# 2) Retrieve and decrypt (the CLI does GET + JWE decryption in one step)
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt \
  client get-resource \
  --uri vault/default/secret/mykey \
  --attest-token @/tmp/attest_token.jwt \
  --private-key-file attester_private.pem
```

Expected output: `{"myvalue":"hello-vault","num":42}` (the secret pre-created in 9.1).

> **Vault backend behavior**: read-only — `res create` only registers a reference; the secret itself must be pre-created in OpenBao. Update/delete only touch the RBS DB record, never the OpenBao content.

## 10. Integrate the HSM resource backend (SoftHSM2)

> Chapter output: RBS reads/writes key material in an HSM via PKCS#11. Prerequisites: chapter 6 (GTA) done; SoftHSM2 installed on the host.
> Opposite to Vault, HSM is **write-mostly**: create/update/delete all operate the HSM. GET accepts attest tokens only (Bearer GETs always return 404).

### 10.1 Install SoftHSM2 and initialize a token

```bash
# On the host
sudo dnf install -y softhsm
sudo softhsm2-util --init-token --free --label "rbs_slot" --pin 1234 --so-pin 5678
softhsm2-util --show-slots | grep -i label    # expected: Token label: rbs_slot
ls /usr/lib64/pkcs11/libsofthsm2.so           # confirm the module file exists
```

### 10.2 Mount the HSM module and token into the pod

HSM is a local device — mount the host's module file and token data into the RBS pod:

```bash
# 1) Create the HSM PIN Secret
kubectl create secret generic rbs-hsm-pin -n rbs --from-literal=pin=1234

# 2) Mount module + tokens + inject the PIN env var
kubectl patch deployment rbs -n rbs --type='json' -p='[
  {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"hsm-module","hostPath":{"path":"/usr/lib64/pkcs11/libsofthsm2.so","type":"File"}}},
  {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"hsm-tokens","hostPath":{"path":"/var/lib/softhsm/tokens","type":"Directory"}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"hsm-module","mountPath":"/usr/lib/pkcs11/libsofthsm2.so","subPath":"libsofthsm2.so","readOnly":true}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"hsm-tokens","mountPath":"/var/lib/softhsm/tokens"}},
  {"op":"add","path":"/spec/template/spec/containers/0/env","value":[{"name":"RBS_HSM_PIN","valueFrom":{"secretKeyRef":{"name":"rbs-hsm-pin","key":"pin"}}}]}
]'
```

> For production, use a network HSM (no hostPath mounts needed; just set `module_path` to the network HSM's PKCS#11 library).

### 10.3 Update the RBS config

```bash
sed -i '/^storage:/i\
resource:\
  backends:\
    hsm:\
      type: hsm\
      module_path: "/usr/lib/pkcs11/libsofthsm2.so"\
      slot:\
        label: "rbs_slot"\
      credentials:\
        pin_env: "RBS_HSM_PIN"\
      allowed_resource_types: ["key", "secret"]' rbs-k8s-deploy/rbs.yaml

kubectl delete secret rbs-config -n rbs
kubectl create secret generic rbs-config -n rbs --from-file=rbs.yaml=rbs-k8s-deploy/rbs.yaml
kubectl rollout restart deployment/rbs -n rbs
kubectl rollout status deployment/rbs -n rbs --timeout=120s
```

Verify registration:

```bash
kubectl logs -n rbs deploy/rbs | grep -iE "hsm|slot" | tail -3
# expected: HsmBackend: loaded module '/usr/lib/pkcs11/libsofthsm2.so', found slot 'rbs_slot'
#           Registered resource backend 'hsm' (type=hsm)
```

### 10.4 Create a resource policy and write key material

```bash
NODE_IP=$(minikube ip)   # kind: NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
export RBS_URL="https://${NODE_IP}:30666"
export BEARER_TOKEN="$(rbs-cli token gen --private-key-file rbs-k8s-deploy/admin_key.pem)"

cat > hsm_policy.rego <<'EOF'
package verification
default allow = false
allow { true }
result = {"policy_matched": allow}
EOF

rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt -t "$BEARER_TOKEN" \
  res-policy create --name hsm-policy --content @hsm_policy.rego
export POLICY_ID="<the returned policy_id>"

# Generate 32 bytes of random key material
head -c 32 /dev/urandom | base64 > keymat.b64

# Write into the HSM (creates a CKO_DATA object)
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt -t "$BEARER_TOKEN" \
  res create --uri hsm/default/key/mykey --policy-id "$POLICY_ID" \
  --content-type binary --content @keymat.b64
```

### 10.5 Get HSM resource content (attest token only)

```bash
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt \
  client get-token --attester-pubkey @attester_public.pem -o /tmp/attest_token.jwt

rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt \
  client get-resource \
  --uri hsm/default/key/mykey \
  --attest-token @/tmp/attest_token.jwt \
  --private-key-file attester_private.pem
```

The output is the Base64 encoding of the key material; `base64 -d` matches what was written in 10.4.

> **HSM backend behavior**: write-mostly — create actually writes to the HSM (must carry `--content`, otherwise later GETs fail with 404); update with `--content` overwrites the HSM object; delete actually removes the PKCS#11 object (irreversible).

## 11. Integrate the CA resource backend (XiPKI)

> Chapter output: RBS issues certificates live from a CA via CMPv2. Prerequisites: chapter 6 (GTA) done; a reachable XiPKI service (outside the cluster).
> The CA backend is a **certificate-issuance proxy**: create/update/delete are metadata-only; GET takes the CSR from the attest token and issues a certificate live from the CA.

### 11.1 Deploy XiPKI

On the XiPKI host (abbreviated steps; full deployment see [XiPKI docs](https://github.com/xipki/xipki)):

```bash
# Prerequisites: Java 11; download xipki-setup-*.tar.gz to /opt
cd /opt && tar xzf xipki-setup-6.7.0-bclts.tar.gz
rm -f xipki-setup-6.7.0/setup/jars/xipki/bcbridge-fips-6.7.0.jar

# Change the OCSP port (avoid conflicts)
sed -i 's/"ocsp.http.port": "8080"/"ocsp.http.port": "8083"/' xipki-setup-6.7.0/setup/conf.json

# Initialize + start (see the XiPKI official docs for full steps)
cd xipki-setup-6.7.0 && ./prepare.sh && ./demo.sh

# Start H2 database and the three Tomcats (CA/gateway/OCSP)
# ... full steps in usage_guide/rbs_usage_manual.md chapter 11

# Verify ports
ss -ltn | grep -E ':8444|:8082|:8083'
```

### 11.2 Prepare the CMP client certificate and trust anchors

```bash
# CMP client certificate/key (RBS signs CMP requests with it)
cp /opt/xipki-setup-6.7.0/xipki-cli/xipki/keycerts/cmp-client-cert.pem rbs-k8s-deploy/cmp-client.crt
cp /opt/xipki-setup-6.7.0/xipki-cli/xipki/keycerts/cmp-client.p12 /tmp/cmp-client.p12
openssl pkcs12 -in /tmp/cmp-client.p12 -nocerts -nodes \
  -passin pass:changeit-cmpclient -out /tmp/cmp-client.key.tmp
openssl pkey -in /tmp/cmp-client.key.tmp -out rbs-k8s-deploy/cmp-client.key
rm -f /tmp/cmp-client.key.tmp /tmp/cmp-client.p12

# Trust anchor (the certificate the gateway uses to sign CMP responses)
cp /root/demo_xipki/gateway-tomcat/xipki/keycerts/gateway-server-cert.pem rbs-k8s-deploy/ca-anchors.pem
```

### 11.3 Mount certificates and update the RBS config

```bash
# 1) Create the CA certificate Secret
kubectl create secret generic ca-certs -n rbs \
  --from-file=cmp-client.crt=rbs-k8s-deploy/cmp-client.crt \
  --from-file=cmp-client.key=rbs-k8s-deploy/cmp-client.key \
  --from-file=ca-anchors.pem=rbs-k8s-deploy/ca-anchors.pem

# 2) Mount into the pod
kubectl patch deployment rbs -n rbs --type='json' -p='[
  {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"ca-certs","secret":{"secretName":"ca-certs"}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"ca-certs","mountPath":"/etc/rbs/ca-certs","readOnly":true}}
]'

# 3) Add the resource section
sed -i '/^storage:/i\
resource:\
  backends:\
    ca:\
      type: ca\
      url: "http://<XIPKI_IP>:8082/gw/cmp/myca1"\
      https:\
        verify: false\
      message_protection_cert_file: "/etc/rbs/ca-certs/cmp-client.crt"\
      message_protection_key_file: "/etc/rbs/ca-certs/cmp-client.key"\
      response_protection_trust_anchors_file: "/etc/rbs/ca-certs/ca-anchors.pem"\
      cert_profile: "smime"\
      allowed_resource_types: ["cert"]' rbs-k8s-deploy/rbs.yaml

# 4) Update the Secret and restart
kubectl delete secret rbs-config -n rbs
kubectl create secret generic rbs-config -n rbs --from-file=rbs.yaml=rbs-k8s-deploy/rbs.yaml
kubectl rollout restart deployment/rbs -n rbs
kubectl rollout status deployment/rbs -n rbs --timeout=120s
```

> Replace `<XIPKI_IP>` with the XiPKI host's IP.

Verify registration:

```bash
kubectl logs -n rbs deploy/rbs | grep -i "CA backend" | tail -2
# expected: CA backend initialized: url='http://<XIPKI_IP>:8082/gw/cmp/myca1', anchors=1
#           Registered resource backend 'ca' (type=ca)
```

### 11.4 Create a resource policy and register the CA resource

```bash
NODE_IP=$(minikube ip)   # kind: NODE_IP=$(docker inspect rbs-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
export RBS_URL="https://${NODE_IP}:30666"
export BEARER_TOKEN="$(rbs-cli token gen --private-key-file rbs-k8s-deploy/admin_key.pem)"

cat > ca_policy.rego <<'EOF'
package verification
default allow = false
allow { true }
result = {"policy_matched": allow}
EOF

rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt -t "$BEARER_TOKEN" \
  res-policy create --name ca-policy --content @ca_policy.rego
export POLICY_ID="<the returned policy_id>"

# Register the CA resource (metadata only; no request to the CA)
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt -t "$BEARER_TOKEN" \
  res create --uri ca/default/cert/mycert --policy-id "$POLICY_ID" --content-type binary
```

### 11.5 Get a certificate (attest token + CSR)

```bash
# 1) Generate a CSR (subject must match cert_profile)
openssl req -new -newkey rsa:2048 -nodes \
  -keyout csr-client.key -out client.csr \
  -subj "/C=DE/O=myorg/emailAddress=info@myorg.com/CN=workload"
export CSR_DER_B64=$(openssl req -in client.csr -outform DER | base64 -w0)

# 2) Issue an attest token carrying the CSR
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt \
  client get-token \
  --attester-pubkey @attester_public.pem \
  --runtime-data "csr=$CSR_DER_B64" \
  -o /tmp/attest_token.jwt

# 3) Get the certificate (RBS issues it live from XiPKI; the CLI decrypts the JWE)
rbs-cli -b "$RBS_URL" --cert rbs-k8s-deploy/tls.crt \
  client get-resource \
  --uri ca/default/cert/mycert \
  --attest-token @/tmp/attest_token.jwt \
  --private-key-file attester_private.pem \
  -o issued-cert.b64

# 4) Restore and inspect the certificate
base64 -d issued-cert.b64 > issued-cert.der
openssl x509 -in issued-cert.der -inform der -noout -subject -issuer
# expected: subject=C = DE, O = myorg, CN = workload
#           issuer=O = myorg, CN = myca1
```

> **CA backend behavior**: GET issues live — the token must carry both `csr` (DER Base64) and `tee-pubkey`; a missing `csr` yields `400 csr required for this resource provider`. The same CSR within the TTL (default 300 s) returns a cached certificate.

## Further reading

- Build, run, test on a single host: [build_and_install.md](build_and_install.md)
- RPM installation: [rpm.md](rpm.md)
- Sample config with all sections: [rbs/conf/rbs.yaml](../../rbs/conf/rbs.yaml)
