# CV/license upload pipeline — Azure Blob + Defender for Storage

## Deploy order

1. **Enable Defender for Storage on the subscription** (one-time, needs Owner/Security Admin):
   ```
   az deployment sub create --location <region> --template-file defender-for-storage.bicep
   ```
2. **Deploy the storage account + containers + Function App**:
   ```
   az deployment group create -g <resource-group> \
     --template-file storage-and-pipeline.bicep \
     --parameters storageAccountName=<uniquename> functionAppName=<funcname>
   ```
3. **Deploy the Function code** (from this folder):
   ```
   func azure functionapp publish <funcname>
   ```

## Flow

1. Website uploads files (via short-lived SAS token, restricted to the `uploads-quarantine` container).
2. Defender for Storage scans on upload, tags the blob with the verdict.
3. The Event Grid subscription fires `Microsoft.Security.MalwareScanningResult`, the Function moves:
   - clean files → `public-documents`
   - malicious files → `rejected`
   - inconclusive results → stay in quarantine (check manually, don't auto-publish)
4. Serve `public-documents` via SAS/CDN — don't flip it to anonymous public access unless that's a deliberate choice, since these will be documents with people's personal details (CVs) on them.

## Things I'm not fully certain of / verify before relying on this

- Event Grid field names (`blobUri`, `scanResultType`) — cross-confirmed against a second independent source (a dated OneUptime walkthrough using the same field names in its PowerShell handler), so reasonably confident, but still log one real event and check it before trusting this in production — neither source is Microsoft's own schema reference page.
- Current pricing for malware scanning (per-GB) — check the Defender for Cloud pricing page, this changes.
- API versions (`2023-01-01`, `2023-12-15-preview`) may have newer stable versions by the time you deploy — check `az provider show --namespace Microsoft.Security` / `Microsoft.EventGrid` for latest.
- I set `allowBlobPublicAccess: false` and kept all containers private, serving via SAS instead of anonymous public blob access — since these are CVs (personal data), that's the safer default; change deliberately if you actually want anonymous public reads.

## Also worth doing (from a walkthrough I checked this against)

- If you only want malware scanning on specific storage accounts rather than the whole subscription, `Update-AzSecurityDefenderForStorage -ResourceId <account> -IsEnabled -OverrideSubscriptionLevelSetting -OnUploadIsEnabled -OnUploadCapGbPerMonth 5000` is a simpler path than the per-account Bicep extension resource.
- Defender for Storage is a detective control, not preventive — pair it with private endpoints/firewall rules on the storage account.
- Turn on Sensitive Data Discovery too (same Defender for Storage plan) since CVs carry PII — note it's a periodic scan, not on-upload like malware scanning, so don't treat it as a gate before publishing.

## Client-side note

There's no reliable way to run true malware scanning in the browser. Client-side checks (file type/extension allow-list, size limits, magic-byte validation) are a UX filter only — the actual security boundary is server-side: files land in the private quarantine container first, and nothing is exposed publicly until Defender's scan verdict comes back clean.

## HTTP endpoints (for APIM / web apps) — revision 2

`function_app.py` now proxies uploads and downloads through the Function itself rather than issuing client-facing SAS tokens, to close the gaps identified against the enterprise File Upload Security Standard (see `design.md` §8–9):

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/uploads` | Accepts a `multipart/form-data` body with exactly one file part named `file`. Validates the part's filename extension, the actual file size (≤10MB by default, checked against the real extracted bytes — not just `Content-Length`), and its content via `_check_mime` (libmagic); writes to `uploads-quarantine` under a server-generated UUID name; writes an audit record (hash, uploader identity, timestamp) |
| GET | `/api/uploads/{blobId}/status` | Returns `pending`, `clean`, `malicious`, `scan_error`, or `not_found` |
| GET | `/api/documents/{blobId}/download` | Streams a cleared document back through the Function (not a redirect to storage), re-checking authorization each call, with `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and a restrictive CSP set on the response |

`openapi.yaml` and `apim-policies.xml` are updated to match (multipart upload body instead of a JSON SAS request, a CSRF header check, and a request-body-size ceiling on top of the Function's own per-file check).

### Multipart upload implementation notes

`upload_document` uses `req.files`/`req.form` (`azure.functions.HttpRequest`, backed by Werkzeug's form parser) rather than hand-rolling multipart parsing. Actually tested end-to-end (not just unit-level) against a real multipart body before shipping, covering: a genuine PDF (happy path), a missing `file` part, a non-multipart `Content-Type`, a disallowed extension, a content/extension mismatch, an oversized file, an empty file, and — the one that actually caught a bug — **two files both sent under the field name `file`**.

That last case is worth calling out: the first version of this endpoint checked `len(uploaded_files) > 1` to reject ambiguous requests, but Werkzeug's `ImmutableMultiDict` counts distinct **field names**, not total parts — two files both named `file` collapse to one key, `.get("file")` silently returns just the first one, and the request would have been accepted and one of the two files quietly uploaded with no indication the second was ever dropped. Fixed by checking `uploaded_files.getlist("file")` instead, which does return all parts under that key. Confirmed with a test that previously passed silently and now correctly returns 400.

Also enforced: `Content-Length` is checked early (before parsing) against `MAX_FILE_SIZE_BYTES` plus a small multipart-overhead allowance, purely as a cheap first rejection — the real enforcement is against the actual extracted file bytes after parsing, since `Content-Length` covers the whole multipart body (boundaries, headers, any other fields), not just the file's own size.

### What's now closed vs. still open (from design.md §8–9)

Closed by this revision: per-file size enforcement, UUID filename regeneration, authenticated-proxy download with required headers, and an audit log (Azure Table Storage — `uploadaudit` table, created automatically on cold start) recording SHA-256 hash, sanitized original filename, uploader identity, timestamp, and scan result.

**MIME content validation.** `_check_mime()` replaced the earlier hand-rolled magic-byte signature table with `python-magic` (libmagic), checked against `ALLOWED_MIME_TYPES` per extension. This was tested against real files before shipping, not assumed to work:
- Uses the **full file content**, not a fixed-size prefix. A commonly-suggested 2048-byte prefix is fine for images and OOXML (`.docx` producers write `[Content_Types].xml` as the first zip entry, so it's visible early regardless of file size), but testing showed it's **not enough for legacy `.doc`** — libmagic reported the generic `application/x-ole-storage` instead of `application/msword` when only given a short prefix, because the OLE directory sector isn't necessarily within the first 2KB. Files are already capped at `MAX_FILE_SIZE_BYTES` before this runs, so passing the full buffer is cheap.
- Fails closed if `libmagic` isn't importable (logs the failure rather than crashing the whole Function App at cold start), and rejects (422) rather than silently accepting when detection doesn't match.
- **Known limitation, not fixed here:** a hand-crafted zip that mimics enough OOXML structure could still be misidentified as a genuine `.docx`. Real structural validation (confirm `word/document.xml` etc. actually exist and parse) would close that gap.

**Deployment risk to verify before shipping:** `python-magic` is a ctypes wrapper around the native `libmagic1` shared library, not a pure-Python package. I could not confirm from documentation whether Azure Functions' default Python Consumption-plan image includes `libmagic1` — this is the same class of constraint as LibreOffice for `.doc` CDR below. If it's missing, every upload will be rejected (fails closed) until you either add `libmagic1` via a custom container image or switch to a pure-Python alternative.

**Closed in this revision: authentication model + per-document authorization.** Uploaders/viewers are decided to be authenticated users (candidates/applicants) — resolving design.md open item #1. This touched several things:

- `_get_authenticated_principal()` is the single source of truth for "who is making this request" — reads `X-Ms-Client-Principal-Id`, forwarded by APIM only after it validates the caller's JWT (`apim-policies.xml`'s `validate-jwt` block, now live rather than commented-out).
- `upload_document` now rejects (401) any request with no authenticated identity, instead of tagging it `"anonymous"`.
- `_authorize_document_access()` replaces the old `_authorize_download()` placeholder with real owner-only authorization, used by **both** `get_upload_status` and `download_document`: a caller can only see the status of, or download, documents they themselves uploaded. It distinguishes three failure modes deliberately — `401` unauthenticated (the audit table isn't even queried), `404` blobId never existed, `403` blobId is real but belongs to someone else — rather than collapsing them into one ambiguous response.
- Tested end-to-end (not just at the unit level) with two simulated users across upload → status → download: 10 cases including cross-user access attempts, unauthenticated access, and a nonexistent blobId, all confirmed to return the correct status code before this was considered done.
- **Two real bugs were caught by that testing and fixed before shipping:** first, my initial cut of the authorization check ran *before* checking whether the document even existed, which meant every nonexistent blobId returned a misleading `401` instead of `404` — restructured into the four-outcome model above. Second, in `apim-policies.xml`, several policy expressions turned out not to be valid XML at all — `&&` needs to be `&amp;&amp;` even inside an attribute value, and a `<tenant-id>` placeholder with literal angle brackets inside a URL attribute isn't legal either. Both were there since an earlier revision, silently broken (the CSRF and body-size-limit checks, specifically) until I validated the file with an XML parser while making it live — that policy would have failed to import into APIM at all.

**Explicitly not covered by this**: staff/recruiter access to review *other* candidates' submissions. The model above is strictly owner-only — a reviewer role or claim would need its own design decision, not assumed here.

**Still open:**
- **JWT validation is written for Azure AD / Microsoft Entra ID**, with placeholder tenant ID and audience — not verified against a real tenant. If a different identity provider is actually in use, the `<openid-config>` URL needs to change.
- **The whole model depends on the Function being unreachable except through APIM.** `_get_authenticated_principal()` trusts the forwarded header outright; if the Function could be reached directly, that header is trivially spoofable. This was already a recommended deployment step in earlier revisions — it's now a hard requirement, not a nice-to-have.

**Closed in this revision: CDR.** `cdr_engine.py` (uploaded, then reviewed and fixed) is now wired into `_run_cdr()` and actually runs before a file is promoted to `public-documents`. Three real bugs were found by testing before wiring it in — see the changelog at the top of `cdr_engine.py` — most importantly one where `sanitize_pdf` referenced a `writer.root` attribute that doesn't exist on the pypdf version tested, so PDF sanitization silently failed every single time before the fix. `test_cdr_engine.py` (original) and `test_cdr_engine_extra.py` (added — covers `sanitize_pdf`, `sanitize_image`, the legacy-`.doc` path end-to-end, and the two bug regressions) both pass: `python -m pytest test_cdr_engine.py test_cdr_engine_extra.py`.

**One real deployment constraint this doesn't resolve:** `.doc` sanitization shells out to LibreOffice via `subprocess`. That's not present on a default Azure Functions **Consumption plan**. Before deploying, pick one:
- Move this Function to a Premium or Dedicated (App Service) plan using a **custom container image** with `libreoffice` installed, or
- Drop `.doc` from `ALLOWED_EXTENSIONS` in `function_app.py` and only accept `.docx` (no LibreOffice dependency).

Not decided for you — see `design.md` §9.

A CDR failure now fails closed: the routing function leaves the blob in quarantine and marks its audit status `cdr_failed` rather than promoting an unsanitized file. `GET /uploads/{blobId}/status` surfaces this as `"status": "cdr_failed"`.

### Deploying

1. Publish: `func azure functionapp publish <funcname>`.
2. The Function's managed identity needs `Storage Table Data Contributor` in addition to `Storage Blob Data Contributor` (already granted in `storage-and-pipeline.bicep` for blobs — added for tables, but **verify the role GUID** with `az role definition list --name "Storage Table Data Contributor"` before deploying; I wasn't able to fully confirm it against Microsoft's live list).
3. Rest of the deployment/wiring steps from revision 1 (network-restrict the Function to APIM, import `openapi.yaml`, apply `apim-policies.xml`) are unchanged.
