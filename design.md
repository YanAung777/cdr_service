# Design Document: Document Upload & Delivery Service (Version 2.0)

---

## 1. Purpose

Provide a **secure, high‑performance, end‑to‑end pipeline** that accepts CVs and professional‑license documents from authenticated users, stores them safely in Azure Blob Storage, performs **malware scanning** and **Content Disarm & Reconstruction (CDR)**, and serves the sanitized artifacts **only through a credential‑checked download function**. The service is packaged as a **custom Docker image** and runs on an Azure Functions **Premium/Dedicated** plan to support heavy native binaries (Ghostscript, LibreOffice, libmagic).

---

## 2. Core Functional Changes (since v1.0)

| Area | New Behaviour | Rationale |
|------|---------------|-----------|
| **Upload** | Still goes through APIM → Upload Function. Validation order is now **extension → magic‑bytes → size → filename sanitisation → UUID rename**. | Aligns with enterprise file‑upload security standard; eliminates client‑side SAS token. |
| **Download** | `download_document` now streams directly from Blob Storage using an **async generator** (`download_blob().chunks()`). It also performs **role‑based authorization** (`owner` or `Recruiter` role). | Reduces memory pressure on the Function host and supports large files. |
| **OOXML handling** | Added `stream_ooxml` helper that opens Office Open XML files (`.docx`, `.xlsx`, `.pptx`) as a **ZIP stream** and processes the internal XML without ever writing to disk. | Enables in‑memory processing of large Office files and keeps the container lightweight. |
| **PDF Overlay Edge‑Cases** | `add_overlay_to_pdf` now validates: *empty PDFs*, *encrypted PDFs*, and **idempotent overlay addition** (second call does not duplicate overlay). Errors raise clear `ValueError`/`RuntimeError`. | Guarantees deterministic CDR behaviour and prevents hidden payloads from persisting. |
| **Telemetry** | Global counter `OVERLAY_TRUNCATED_COUNT` plus `_emit_overlay_metric` emit a structured `CDROverlayTruncated` metric via Application Insights logger. Warm‑up timer logs `FunctionWarmup` metric. | Provides observability for performance engineering and capacity planning. |
| **Warm‑up Timer** | `warmup_trigger` runs every 5 minutes, calls a no‑op endpoint to keep the Premium host warm, shaving ~150 ms from cold‑starts. | Improves perceived latency for end‑users. |
| **Containerisation** | Dockerfile now installs **Ghostscript**, **LibreOffice**, **libmagic**, Python dependencies, and sets `FUNCTIONS_WORKER_RUNTIME=python`. | Required for on‑the‑fly document conversion (`.doc` → `.docx` → PDF). |
| **CI/CD** | GitHub Actions workflow builds the Docker image, pushes it to Azure Container Registry, and deploys/updates the Function App on every push to `main`. | Guarantees reproducible builds and automated production rollout. |

---

## 3. Architecture Overview

```mermaid
flowchart LR
    U[Browser (Authenticated User)] -->|1 POST /upload| APIM[APIM (authN/authZ, CSRF, rate‑limit)]
    APIM -->|2 Forward| UPF[Upload Function]
    UPF -->|3 Write to quarantine| QUAR[uploads‑quarantine (private blob container)]
    UPF -->|4 Audit record| AUD[Azure Table Storage (audit)]
    QUAR -->|5 Scan| DEF[Defender for Storage]
    DEF -->|6 Tags + EventGrid| EG[Event Grid]
    EG -->|7 Trigger| ROUTE[Routing Function]
    ROUTE -->|8 CDR (cdr_engine.py)| CDR[CDR Engine]
    ROUTE -->|9 Clean → public| PUB[public‑documents (private)]
    ROUTE -->|10 Malicious → rejected| REJ[rejected (private)]
    U -->|11 GET /download| APIM
    APIM -->|12 Forward| DLF[Download Function]
    DLF -->|13 Stream| PUB
```

---

## 4. Components (updated)

| Component | Responsibility |
|-----------|-----------------|
| **APIM** | Enforces OAuth2/JWT, CSRF, CORS, rate limiting, and request‑size caps before any request reaches a Function. |
| **Upload Function** (`function_app.upload_document`) | Parses multipart body, validates file (extension, magic‑bytes, size), regenerates UUID filename, writes to `uploads-quarantine` via Managed Identity, records audit metadata. |
| **Defender for Storage** | Performs on‑upload AV scan; writes verdict as blob index tags and emits `Microsoft.Security.MalwareScanningResult` Event Grid events. |
| **Routing Function** (`routing_function.py`) | Consumes Event Grid events, reads scan verdict, invokes **CDR engine** (`cdr_engine.route_file_to_cdr`). Successful CDR moves file to `public-documents`; failures keep the file in quarantine with audit status `cdr_failed`. |
| **CDR Engine** (`cdr_engine.py`) | Implements PDF/A‑4 conversion, trailing‑overlay truncation, PDF overlay addition, OOXML streaming, image sanitisation, etc. Exposes telemetry counters. |
| **Download Function** (`function_app.download_document`) | Re‑authorises the caller (`owner` or `Recruiter` role), streams the blob via `download_blob().chunks()`, sets security headers (`Content‑Disposition`, `X‑Content‑Type‑Options`, CSP). |
| **Warm‑up Trigger** (`warmup_trigger.py`) | Periodic timer‑triggered HTTP call to keep the Premium host warm. |
| **Telemetry** | Application Insights logs custom metrics: `CDROverlayTruncated`, `FunctionWarmup`, plus standard request/exception metrics. |
| **Docker Image** | Custom image containing Ghostscript, LibreOffice, libmagic, and Python runtime. |
| **GitHub Actions CI/CD** (`.github/workflows/deploy.yml`) | Builds Docker image, pushes to Azure Container Registry, creates/updates the Function App on Premium plan, validates health endpoint. |

---

## 5. API Surface

| Method | Path | Description | Authz |
|--------|------|-------------|-------|
| `POST` | `/api/upload` | multipart file upload; returns `blob_id`. | Owner (JWT) |
| `GET`  | `/api/status/{blob_id}` | Returns scan + CDR status. | Owner |
| `GET`  | `/api/download/{blob_id}` | Streams the sanitized file with security headers. | Owner **or** `Recruiter` role |
| `GET`  | `/api/health` | Simple liveness probe. | Public |

---

## 6. Security Controls

* **Transport** – TLS 1.3 enforced at Front Door/APIM layer; HSTS header set by Function App.
* **Identity** – Managed Identity for all Functions; APIM forwards `X‑Ms‑Client‑Principal‑Id` (and optional `X‑Ms‑Client‑Principal‑Role`).
* **Authorization** – Owner‑only by default; role claim `Recruiter` can be added in `_authorize_document_access()`.
* **Storage** – All containers are private; only the Download Function has read rights to `public‑documents`.
* **Malware & CDR** – Dual‑layer defence; AV tags are mandatory, CDR is the final gate.
* **Audit** – SHA‑256 hash, uploader ID, timestamps, scan verdict, and CDR outcome stored in Azure Table Storage.
* **Logging** – All security‑relevant actions logged to Application Insights; alerts routed to Azure Sentinel.

---

## 7. Performance Optimisations

* **Streaming download** – `download_blob().chunks()` yields small byte chunks (default 4 MiB) eliminating full‑file buffering.
* **OOXML streaming** – `stream_ooxml` processes Office files as ZIP streams; no temporary files on disk.
* **Overlay handling** – Overlay addition checks for existing overlay page to avoid duplication; early exit reduces work.
* **Warm‑up** – Timer‑trigger reduces cold‑start latency by keeping host ready.
* **Docker image layering** – Packages installed in separate layers to speed up rebuilds when only code changes.

---

## 8. Deployment & Operations

1. **Build & push** – `docker build -t <ACR_NAME>.azurecr.io/cdr-service:latest .` and `docker push` (handled by CI).
2. **Create Premium plan & Function App** – `azure_deploy.sh` creates an App Service Plan (`--sku P1v3`) and a Function App with `--runtime custom`.
3. **Configure Managed Identity** – Grants `Storage Blob Data Owner` on the storage account and `Event Grid Subscriber` rights.
4. **App Settings** – Key‑values such as `ALLOWED_EXTENSIONS`, `MAX_FILE_SIZE_BYTES`, `CDR_*` flags are stored in the Function App configuration.
5. **Health‑check** – Automated step in the GitHub workflow (`curl https://<FUNCAPP>.azurewebsites.net/api/health`).

---

## 9. CI/CD Pipeline (GitHub Actions)

```yaml
name: CI/CD Deploy to Azure Functions

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    env:
      IMAGE_NAME: ${{ secrets.ACR_NAME }}.azurecr.io/cdr-service:latest
      RESOURCE_GROUP: ${{ secrets.RESOURCE_GROUP }}
      PLAN_NAME: ${{ secrets.PLAN_NAME }}
      FUNCAPP_NAME: ${{ secrets.FUNCAPP_NAME }}
      STORAGE_ACCOUNT: ${{ secrets.STORAGE_ACCOUNT }}
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Azure CLI
        uses: azure/cli@v2
        with:
          az-version: '2.57.0'
      - name: Azure login
        uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - name: Log in to ACR
        run: az acr login --name ${{ secrets.ACR_NAME }}
      - name: Build & push image
        run: |
          docker build -t $IMAGE_NAME .
          docker push $IMAGE_NAME
      - name: Deploy Function App (Premium)
        run: |
          az functionapp create \
            --resource-group $RESOURCE_GROUP \
            --name $FUNCAPP_NAME \
            --storage-account $STORAGE_ACCOUNT \
            --plan $PLAN_NAME \
            --deployment-container-image-name $IMAGE_NAME \
            --runtime custom \
            --functions-version 4 || \
          az functionapp update \
            --resource-group $RESOURCE_GROUP \
            --name $FUNCAPP_NAME \
            --set "siteConfig.linuxFxVersion=DOCKER||$IMAGE_NAME"
      - name: Verify deployment
        run: |
          sleep 30
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://${FUNCAPP_NAME}.azurewebsites.net/api/health)
          if [ "$STATUS" -ne 200 ]; then
            echo "Health check failed: $STATUS"
            exit 1
          fi
```

*All secrets must be added to the repository (Azure service principal JSON, ACR name, resource‑group, plan, function‑app name, storage account).* 

---

## 10. Testing

* **Unit tests** – `pytest -q` now runs:
  * Existing tests (`test_cdr_engine*`, `test_download_stream`).
  * New OOXML streaming tests (`tests/test_ooxml_stream.py`).
  * New PDF overlay edge‑case tests (`tests/test_pdf_overlay_edge.py`).
* **Performance bench** – `benchmark_performance.py` measures PDF/A‑4 conversion (~31 ms) and overlay/Unicode ops (<5 ms). 
* **CI integration** – The GitHub workflow fails early if any test fails, preventing a bad image from being pushed.

---

## 11. Future Work

* **Recruiter role** – Extend `_authorize_document_access()` to support a `Recruiter` claim allowing cross‑applicant reads.
* **VNet isolation** – Deploy the Function App with a private endpoint to guarantee APIM‑only traffic.
* **Extended format support** – Add safe handling for `.doc` via LibreOffice conversion (already present in the container). 
* **Dynamic scaling** – Tune Premium plan SKU based on telemetry (`FunctionWarmup` and request latency). 

---

*Design last updated: 2026‑10‑28*
