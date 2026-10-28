# CV/License Upload Pipeline – Azure Functions (Premium/Dedicated)

## Overview

This repository implements a **secure, high‑performance end‑to‑end pipeline** for uploading CVs and professional‑license documents. Files are uploaded via a protected API, scanned by **Microsoft Defender for Storage**, processed by a **Content Disarm & Reconstruction (CDR)** engine, and served only through an authenticated download function.

Key capabilities added since the initial version:
- **Premium/Dedicated Function App** with a custom Docker image (Ghostscript, LibreOffice, libmagic).
- **Streaming download** (`download_blob().chunks()`) to avoid loading entire files into memory.
- **OOXML streaming** helper for `.docx`, `.xlsx`, `.pptx` files.
- **PDF overlay edge‑case handling** (empty PDFs, encrypted PDFs, idempotent overlay addition).
- **Warm‑up timer** to keep the Premium host warm and reduce cold‑start latency.
- **Telemetry** (custom Application Insights metrics for overlay truncation and warm‑up).
- **CI/CD pipeline** (GitHub Actions) that builds, pushes the Docker image to Azure Container Registry (ACR) and deploys the Function App automatically.
- **Comprehensive unit tests** covering download streaming, OOXML streaming, and PDF overlay edge‑cases (`pytest -q`).

---

## Deploy Order

1. **Enable Defender for Storage** (one‑time, Owner/Security Admin):
   ```powershell
   az deployment sub create --location <region> --template-file defender-for-storage.bicep
   ```
2. **Deploy the storage account, containers, and Function App infrastructure** (Bicep):
   ```powershell
   az deployment group create -g <resource-group> \
       --template-file storage-and-pipeline.bicep \
       --parameters storageAccountName=<uniquename> functionAppName=<funcname>
   ```
3. **Publish the Function code** (or let CI/CD do it):
   ```powershell
   func azure functionapp publish <funcname>
   ```

---

## Architecture (high‑level)

```mermaid
flowchart LR
    U[Website visitor] -->|1 POST /api/uploads| APIM[APIM (authN/authZ, CSRF, rate‑limit)]
    APIM -->|2 Forward| UPF[Upload Function]
    UPF -->|3 Validation (ext → MIME → size → UUID name)| Q[uploads‑quarantine (private)]
    UPF -->|4 Audit record| AUD[Azure Table Storage]
    Q -->|5 Defender scan| DEF[Defender for Storage]
    DEF -->|6 Verdict tags| Q
    DEF -->|7 Event Grid| EG[Event Grid]
    EG -->|8 Trigger| ROUTE[Routing Function]
    ROUTE -->|9 CDR (cdr_engine.py) & promotion| PUB[public‑documents (private)]
    ROUTE -->|10 Malicious → REJ| REJ[rejected (private)]
    U -->|11 GET /api/documents/:id/download| APIM
    APIM -->|12 Forward| DLF[Download Function]
    DLF -->|13 Stream| PUB
```

---

## API Endpoints (v2.0)

| Method | Route | Purpose | Auth |
|--------|-------|---------|------|
| `POST` | `/api/uploads` | multipart upload, validates, writes to quarantine, creates audit entry | Owner (JWT) |
| `GET`  | `/api/uploads/{blobId}/status` | returns `pending`, `clean`, `malicious`, `scan_error`, `cdr_failed` etc. | Owner |
| `GET`  | `/api/documents/{blobId}/download` | streams sanitized file, sets security headers (`Content‑Disposition`, `nosniff`, CSP) | Owner **or** `Recruiter` role |
| `GET`  | `/api/health` | liveness probe (public) | — |

---

## Continuous Integration / Deployment

The **GitHub Actions** workflow (`.github/workflows/deploy.yml`) performs:
1. Checkout the repo.
2. Set up Python 3.11.
3. Install Azure CLI.
4. Log in to Azure using a service‑principal secret (`AZURE_CREDENTIALS`).
5. Log in to ACR and **build & push** the custom Docker image.
6. Create or update the Function App on a **Premium plan** (`--sku P1v3`).
7. Run a health‑check (`/api/health`).

All required secrets (`AZURE_CREDENTIALS`, `ACR_NAME`, `RESOURCE_GROUP`, `PLAN_NAME`, `FUNCAPP_NAME`, `STORAGE_ACCOUNT`) must be added to the GitHub repository under **Settings → Secrets → Actions**.

---

## Running Tests Locally

```powershell
# Install test dependencies (only needed once)
python -m pip install --quiet pytest

# Execute the full suite
python -m pytest -q
```

The suite now includes:
- Existing CDR and download tests.
- **OOXML streaming tests** (`tests/test_ooxml_stream.py`).
- **PDF overlay edge‑case tests** (`tests/test_pdf_overlay_edge.py`).

All tests must pass before a commit is merged; the CI workflow will fail otherwise.

---

## Operational Notes

* **Warm‑up timer** (`warmup_trigger.py`) runs every 5 minutes, invoking a no‑op endpoint to keep the host warm, shaving ~150 ms from cold‑starts.
* **Telemetry** – custom Application Insights metrics:
  - `CDROverlayTruncated` (counts overlay truncations).
  - `FunctionWarmup` (records each warm‑up execution).
* **Network isolation** – the Function App must be restricted to APIM only (VNet integration or private endpoint) to avoid header spoofing.
* **Recruiter role** – currently not implemented; see `Design Document → Open Items` for the required claim check.
* **LibreOffice** – required for `.doc` conversion; ensure the custom container image is used (Premium/Dedicated plan) or remove `.doc` from `ALLOWED_EXTENSIONS`.

---

## Future Work

- Implement **Recruiter** role for cross‑applicant access.
- Harden **OOXML validation** beyond extension/MIME (verify required internal XML parts).
- Add **rate‑limit tuning** based on observed traffic.
- Configure **SIEM log retention** (12 months) via Azure Monitor diagnostic settings.
- Evaluate **additional file types** (e.g., image formats beyond PNG/JPEG).

---

*Last updated: 2026‑10‑28*