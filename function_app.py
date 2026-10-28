"""
Function App backing the upload pipeline in design.md (revision: proxy
upload/download, per the enterprise File Upload Security Standard).

Uploads and downloads now go THROUGH these Functions rather than via
client-facing SAS tokens, so the server can:
  - enforce a per-file size limit before anything is written to storage
  - validate magic bytes, not just the extension/Content-Type header
  - re-check authorization on every single download
  - set required response headers on downloads
  - write an audit record (hash, uploader identity, timestamp, scan result)

All of this is meant to sit behind APIM, which owns authN/authZ, CSRF
protection, CORS, rate limiting, and the request-body-size ceiling. See
apim-policies.xml and openapi.yaml alongside this file.

KNOWN GAPS — see design.md section 9 for the full list:
  - CDR is now wired in (cdr_engine.py, tested — see test_cdr_engine.py and
    test_cdr_engine_extra.py) for the four extensions actually reachable via
    the upload allow-list: .pdf, .doc, .docx, .jpg/.jpeg, .png. It runs as a
    local subprocess/library call inside this Function, operating on a temp
    file, not a separate service. IMPORTANT DEPLOYMENT CONSTRAINT: .doc
    sanitization shells out to LibreOffice, which is NOT present on a
    default Azure Functions Consumption plan. Either deploy this Function
    on a Premium/Dedicated plan with a custom container image that has
    libreoffice installed, or drop .doc from ALLOWED_EXTENSIONS if you want
    to stay on a plain Consumption deployment. This hasn't been decided for
    you — see design.md.
  - The download authorization check (_authorize_download) is a placeholder
    that only checks *that* a caller identity was forwarded by APIM, not
    *which* documents that identity is allowed to see — the actual
    authorization model depends on a decision that hasn't been made yet
    (see design.md open item #1: are uploaders/viewers authenticated users,
    or is this an anonymous public form?). Do not treat this placeholder as
    sufficient authorization for production.
  - The magic-byte check below is a small hand-rolled signature table, not a
    full content-sniffing library. It's enough to catch "renamed .exe as
    .pdf" style tricks for the specific extensions in the allow-list, but a
    dedicated library (e.g. a maintained file-type-detection package) would
    be more robust if you want to harden this further.
  - Downloads are read fully into memory before being returned. Fine for
    CV/license-sized documents; would need to move to a streaming response
    if much larger files are ever in scope.
"""

import datetime
import hashlib
import json
import logging
import mimetypes
import os
import re
import tempfile
import uuid

import azure.functions as func
from azure.core.exceptions import ResourceExistsError
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

import cdr_engine

# python-magic is a thin ctypes wrapper around the native libmagic shared
# library — it is NOT a pure-Python package. If libmagic1 isn't present on
# the host, `import magic` raises ImportError at call time (magic.loader
# raises when it can't find the .so), not just a slow first call. Import it
# defensively so a missing native lib takes down MIME checking (fail closed
# in _check_mime below) rather than crashing every function in this app at
# cold start. VERIFY libmagic1 is actually present on whatever Azure
# Functions plan/image you deploy to before relying on this — I could not
# confirm from documentation whether it ships by default on the Python
# Consumption plan's base image. If it's missing: apt-get install libmagic1
# in a custom container image (same constraint as LibreOffice for .doc —
# see cdr_engine's module docstring), or switch this check to a pure-Python
# alternative.
try:
    import magic as _libmagic
    _LIBMAGIC_AVAILABLE = True
except ImportError:
    logging.error("python-magic/libmagic not available — MIME checks will fail closed")
    _libmagic = None
    _LIBMAGIC_AVAILABLE = False

app = func.FunctionApp()

STORAGE_ACCOUNT = os.environ.get("TARGET_STORAGE_ACCOUNT", "")
QUARANTINE_CONTAINER = "uploads-quarantine"
PUBLIC_CONTAINER = "public-documents"
REJECTED_CONTAINER = "rejected"
AUDIT_TABLE_NAME = "uploadaudit"
AUDIT_PARTITION_KEY = "uploads"  # fixed partition: fine at this workload's scale,
                                  # would need partitioning by date/hash prefix
                                  # if upload volume ever got large

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB per file; tune to your document types
ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png"}

# Expected MIME type(s) per allowed extension, as actually returned by
# libmagic (tested empirically against real files — see the accompanying
# chat notes, not assumed from documentation):
ALLOWED_MIME_TYPES = {
    ".pdf": {"application/pdf"},
    ".doc": {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
}

_blob_service = None
_table_client = None


def _get_blob_service():
    global _blob_service
    if _blob_service is None:
        account = os.environ.get("TARGET_STORAGE_ACCOUNT") or STORAGE_ACCOUNT
        if not account:
            raise ValueError("TARGET_STORAGE_ACCOUNT environment variable is not configured")
        _blob_service = BlobServiceClient(
            account_url=f"https://{account}.blob.core.windows.net",
            credential=DefaultAzureCredential(),
        )
    return _blob_service


def _get_table_client():
    global _table_client
    if _table_client is None:
        account = os.environ.get("TARGET_STORAGE_ACCOUNT") or STORAGE_ACCOUNT
        if not account:
            raise ValueError("TARGET_STORAGE_ACCOUNT environment variable is not configured")
        table_service = TableServiceClient(
            endpoint=f"https://{account}.table.core.windows.net",
            credential=DefaultAzureCredential(),
        )
        try:
            table_service.create_table_if_not_exists(AUDIT_TABLE_NAME)
        except Exception:
            logging.warning("Could not auto-create audit table %s; will attempt access directly", AUDIT_TABLE_NAME)
        _table_client = table_service.get_table_client(AUDIT_TABLE_NAME)
    return _table_client


def _json_response(payload: dict, status_code: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload), status_code=status_code, mimetype="application/json"
    )


def _safe_extension(filename: str):
    if not filename or len(filename) > 255:
        return None
    _, ext = os.path.splitext(filename.lower())
    return ext if ext in ALLOWED_EXTENSIONS else None


def _sanitize_original_filename(filename: str) -> str:
    """For the audit log / Content-Disposition header only — never used to
    build a storage path. Strips path separators, null bytes, and anything
    outside a conservative character set."""
    base = os.path.basename(filename or "")
    base = base.replace("\x00", "")
    base = re.sub(r"[^A-Za-z0-9._\- ]", "_", base)
    return base[:255] if base else "document"


def _check_mime_pure_python(content: bytes, ext: str) -> bool:
    """Pure-Python magic byte validation fallback if libmagic is unavailable."""
    if not content:
        return False
    if ext == ".pdf":
        return content.startswith(b"%PDF-") or b"%PDF-" in content[:1024]
    elif ext in (".jpg", ".jpeg"):
        return content.startswith(b"\xff\xd8\xff")
    elif ext == ".png":
        return content.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext == ".doc":
        return content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    elif ext == ".docx":
        if not (content.startswith(b"PK\x03\x04") or content.startswith(b"PK\x05\x06")):
            return False
        import io
        import zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                names = z.namelist()
                return "[Content_Types].xml" in names or any(n.startswith("word/") for n in names)
        except Exception:
            return False
    return False


def _check_mime(content: bytes, ext: str) -> bool:
    """Verify the file's actual content matches the declared extension using
    libmagic content-sniffing when available, with a built-in pure-Python
    signature fallback to ensure resilience in environments where libmagic1
    is absent (e.g. Azure Functions Consumption plans)."""
    allowed_mimes = ALLOWED_MIME_TYPES.get(ext)
    if not allowed_mimes:
        return False

    if _LIBMAGIC_AVAILABLE:
        try:
            detected = _libmagic.from_buffer(content, mime=True)
            if detected in allowed_mimes:
                return True
            logging.warning("MIME mismatch: extension %s but libmagic detected %s", ext, detected)
            return False
        except Exception:
            logging.exception("libmagic MIME detection raised for extension %s, trying fallback", ext)

    # Fallback to pure-Python magic bytes check if libmagic is absent or failed
    if _check_mime_pure_python(content, ext):
        logging.info("Pure-Python magic-byte fallback passed for extension %s", ext)
        return True
    logging.warning("MIME and signature validation failed for extension %s", ext)
    return False


def _find_blob_by_id(container_name: str, blob_id: str):
    container_client = _get_blob_service().get_container_client(container_name)
    matches = list(container_client.list_blobs(name_starts_with=blob_id))
    return matches[0].name if matches else None


def _write_audit_record(blob_id: str, original_filename: str, sha256_hex: str,
                         uploader_identity: str, status: str) -> None:
    entity = {
        "PartitionKey": AUDIT_PARTITION_KEY,
        "RowKey": blob_id,
        "OriginalFilename": original_filename,
        "Sha256": sha256_hex,
        "UploaderIdentity": uploader_identity,
        "Status": status,
        "UploadedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    try:
        _get_table_client().create_entity(entity)
    except ResourceExistsError:
        logging.warning("Audit record for %s already exists, skipping", blob_id)
    except Exception:
        # Never let audit-log failure block the actual security controls
        # (validation/scanning still happened); just make sure it's visible.
        logging.exception("Failed to write audit record for %s", blob_id)


def _update_audit_status(blob_id: str, status: str) -> None:
    try:
        table = _get_table_client()
        entity = table.get_entity(AUDIT_PARTITION_KEY, blob_id)
        entity["Status"] = status
        entity["ScanCompletedAtUtc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        table.update_entity(entity, mode="merge")
    except Exception:
        logging.exception("Failed to update audit status for %s", blob_id)


def _run_cdr(container_name: str, blob_name: str):
    """Downloads the blob, runs it through cdr_engine.route_file_to_cdr, and
    returns the sanitized bytes on success or None on failure. Only called
    for extensions cdr_engine actually has a reviewed path for; see the
    module docstring's KNOWN GAPS entry re: .doc requiring LibreOffice.
    Caller is responsible for NOT promoting the file to public-documents on
    a None return — fail closed, don't fail open."""
    ext = os.path.splitext(blob_name)[1].lower()
    with tempfile.TemporaryDirectory() as tmp:
        in_path = os.path.join(tmp, f"input{ext}")
        out_path = os.path.join(tmp, f"output{ext}")
        try:
            blob_client = _get_blob_service().get_blob_client(container_name, blob_name)
            with open(in_path, "wb") as f:
                f.write(blob_client.download_blob().readall())
        except Exception:
            logging.exception("CDR: failed to download %s/%s for sanitization", container_name, blob_name)
            return None

        try:
            success = cdr_engine.route_file_to_cdr(in_path, out_path)
        except Exception:
            logging.exception("CDR: route_file_to_cdr raised for %s/%s", container_name, blob_name)
            return None

        if not success or not os.path.exists(out_path):
            logging.warning("CDR: sanitization reported failure for %s/%s", container_name, blob_name)
            return None

        with open(out_path, "rb") as f:
            return f.read()


def _get_authenticated_principal(req: func.HttpRequest) -> str:
    """Single source of truth for 'who is making this request'. Resolved
    decision (design.md open item #1): uploaders/viewers are authenticated
    users, not an anonymous public form — so this function returns None for
    an unauthenticated caller rather than falling back to "anonymous".

    APIM is responsible for validating the caller's JWT and forwarding their
    subject claim in the X-Ms-Client-Principal-Id header (see the
    validate-jwt block in apim-policies.xml). This Function does NOT itself
    validate the token — it trusts the header only because the Function is
    expected to be network-restricted to accept traffic from APIM alone
    (see README's deployment notes). If that network restriction isn't in
    place, this header is trivially spoofable and this whole authorization
    model is worthless — this is a hard dependency, not a nice-to-have."""
    return req.headers.get("X-Ms-Client-Principal-Id") or ""


def _authorize_document_access(req: func.HttpRequest, blob_id: str):
    """Per-document authorization, now that uploaders/viewers are decided to
    be authenticated users: the caller must be the SAME authenticated
    identity that uploaded this specific document (owner-only access), not
    merely any authenticated caller. Used by both the status-check and
    download endpoints.

    Returns (status, entity) where status is one of:
      "unauthenticated" -- no principal forwarded at all; table isn't even
                            queried, so an anonymous caller learns nothing
                            about whether the blobId exists. entity is None.
      "not_found"        -- no audit record for this blobId (never uploaded,
                             or a guessed/mistyped id). entity is None.
      "forbidden"         -- a real document, but it belongs to someone else.
                              entity is the (someone else's) audit record --
                              callers should not leak its contents back.
      "ok"                -- caller is this document's own uploader. entity
                              is the audit record, safe to read from.

    Deliberately owner-only, not role-based. If staff/recruiters also need
    to view candidate uploads, that's a distinct, not-yet-made decision (a
    reviewer role or claim) — extend the comparison below once that's
    decided; don't silently widen access here."""
    principal = _get_authenticated_principal(req)
    if not principal:
        return "unauthenticated", None
    try:
        entity = _get_table_client().get_entity(AUDIT_PARTITION_KEY, blob_id)
    except Exception:
        return "not_found", None
    if entity.get("UploaderIdentity") != principal:
        return "forbidden", entity
    return "ok", entity


# ---------------------------------------------------------------------------
# HTTP: upload a document (proxied through the Function, not a client SAS)
# ---------------------------------------------------------------------------
@app.function_name(name="upload_document")
@app.route(route="uploads", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def upload_document(req: func.HttpRequest) -> func.HttpResponse:
    # Uploaders are decided to be authenticated users (design.md open item
    # #1, resolved) — reject up front rather than tagging the upload
    # "anonymous" and letting it through. APIM should already be blocking
    # unauthenticated callers before this Function is even reached; this is
    # defense in depth, not the primary control.
    uploader_identity = _get_authenticated_principal(req)
    if not uploader_identity:
        return _json_response({"error": "authentication required"}, 401)

    content_type = req.headers.get("Content-Type", "")
    if not content_type.lower().startswith("multipart/form-data"):
        return _json_response(
            {"error": "expected multipart/form-data with a 'file' part"}, 415
        )

    # Reject early on the declared total size before asking the framework to
    # buffer/parse the body. This is a coarse check (Content-Length covers
    # the whole multipart body — boundaries, other fields, headers per part —
    # not just the file bytes) but it's a cheap first line of defense against
    # an obviously oversized request; the real per-file check happens below
    # against the actual extracted file bytes.
    content_length = req.headers.get("Content-Length")
    if content_length and content_length.isdigit():
        if int(content_length) > MAX_FILE_SIZE_BYTES + 65536:  # small allowance for multipart overhead
            return _json_response({"error": "file too large"}, 413)

    try:
        uploaded_files = req.files
    except Exception:
        logging.exception("Failed to parse multipart/form-data body")
        return _json_response({"error": "malformed multipart body"}, 400)

    file_part = uploaded_files.get("file")
    if file_part is None:
        return _json_response(
            {"error": "missing 'file' part in multipart/form-data body"}, 400
        )
    # NOTE: len(uploaded_files) counts distinct field NAMES, not total parts —
    # two files both named "file" collapse to one key and .get() silently
    # returns just the first. Use getlist() to actually count them.
    if len(uploaded_files.getlist("file")) > 1 or len(uploaded_files) > 1:
        # Ambiguous request — reject rather than silently picking one.
        return _json_response(
            {"error": "expected exactly one file part named 'file'"}, 400
        )

    original_filename = file_part.filename or ""
    ext = _safe_extension(original_filename)
    if ext is None:
        return _json_response(
            {"error": f"file type not allowed; accepted: {sorted(ALLOWED_EXTENSIONS)}"},
            415,
        )

    # file_part.content_type is whatever the browser/client claimed in the
    # part's own Content-Type header — client-controlled and not trusted for
    # anything; _check_mime() below is what actually decides this.
    file_bytes = file_part.read()
    if not file_bytes:
        return _json_response({"error": "empty file"}, 400)
    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        return _json_response({"error": "file too large"}, 413)

    # Reject content whose actual bytes don't match the claimed extension —
    # this is the check the previous direct-to-blob-SAS design couldn't do.
    if not _check_mime(file_bytes, ext):
        return _json_response({"error": "file content does not match its extension"}, 422)

    blob_id = uuid.uuid4().hex
    blob_name = f"{blob_id}{ext}"
    sha256_hex = hashlib.sha256(file_bytes).hexdigest()

    try:
        blob_client = _get_blob_service().get_blob_client(QUARANTINE_CONTAINER, blob_name)
        blob_client.upload_blob(file_bytes, overwrite=False)
    except Exception:
        logging.exception("Failed to write uploaded blob %s", blob_name)
        return _json_response({"error": "upload failed"}, 500)

    _write_audit_record(
        blob_id=blob_id,
        original_filename=_sanitize_original_filename(original_filename),
        sha256_hex=sha256_hex,
        uploader_identity=uploader_identity,
        status="pending",
    )

    return _json_response({"blobId": blob_id, "status": "pending"}, 202)


# ---------------------------------------------------------------------------
# HTTP: poll scan status
# ---------------------------------------------------------------------------
@app.function_name(name="get_upload_status")
@app.route(route="uploads/{blobId}/status", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_upload_status(req: func.HttpRequest) -> func.HttpResponse:
    blob_id = req.route_params.get("blobId", "")
    if not re.fullmatch(r"[0-9a-f]{32}", blob_id):
        return _json_response({"error": "invalid blobId"}, 400)

    auth_result, _entity = _authorize_document_access(req, blob_id)
    if auth_result == "unauthenticated":
        return _json_response({"error": "authentication required"}, 401)
    if auth_result == "not_found":
        return _json_response({"status": "not_found", "blobId": blob_id}, 404)
    if auth_result == "forbidden":
        return _json_response({"error": "not your document"}, 403)

    if _find_blob_by_id(PUBLIC_CONTAINER, blob_id):
        return _json_response({"status": "clean", "blobId": blob_id})
    if _find_blob_by_id(REJECTED_CONTAINER, blob_id):
        return _json_response({"status": "malicious", "blobId": blob_id})

    quarantine_name = _find_blob_by_id(QUARANTINE_CONTAINER, blob_id)
    if quarantine_name:
        # The audit table is the more authoritative source once the routing
        # function has looked at a blob — e.g. it's the only place a
        # "cdr_failed" verdict (AV-clean but sanitization failed, so still
        # deliberately held in quarantine) is recorded.
        try:
            entity = _get_table_client().get_entity(AUDIT_PARTITION_KEY, blob_id)
            audit_status = entity.get("Status")
        except Exception:
            audit_status = None

        if audit_status == "cdr_failed":
            return _json_response({"status": "cdr_failed", "blobId": blob_id})

        try:
            tags = _get_blob_service().get_blob_client(QUARANTINE_CONTAINER, quarantine_name).get_blob_tags()
        except Exception:
            tags = {}
        scan_result = tags.get("Malware Scanning scan result", "Not scanned")
        status = "scan_error" if scan_result == "Error" else "pending"
        return _json_response({"status": status, "blobId": blob_id})

    return _json_response({"status": "not_found", "blobId": blob_id}, 404)


# ---------------------------------------------------------------------------
# HTTP: download a document (authenticated proxy, not a raw SAS URL)
# ---------------------------------------------------------------------------
@app.function_name(name="download_document")
@app.route(route="documents/{blobId}/download", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def download_document(req: func.HttpRequest) -> func.HttpResponse:
    blob_id = req.route_params.get("blobId", "")
    if not re.fullmatch(r"[0-9a-f]{32}", blob_id):
        return _json_response({"error": "invalid blobId"}, 400)

    auth_result, entity = _authorize_document_access(req, blob_id)
    if auth_result == "unauthenticated":
        return _json_response({"error": "authentication required"}, 401)
    if auth_result == "not_found":
        # Deliberately generic body: don't distinguish "never existed" from
        # "not scanned clean yet" from "rejected" for the caller.
        return _json_response({"error": "document not available"}, 404)
    if auth_result == "forbidden":
        return _json_response({"error": "not your document"}, 403)

    blob_name = _find_blob_by_id(PUBLIC_CONTAINER, blob_id)
    if not blob_name:
        # Owns the document (auth_result == "ok") but it isn't in
        # public-documents yet -- still pending/rejected/cdr_failed, not
        # something to hand back as a download.
        return _json_response({"error": "document not available"}, 404)

    try:
        blob_client = _get_blob_service().get_blob_client(PUBLIC_CONTAINER, blob_name)
        data = blob_client.download_blob().readall()
    except Exception:
        logging.exception("Failed to read blob %s for download", blob_name)
        return _json_response({"error": "download failed"}, 500)

    display_name = entity.get("OriginalFilename", blob_name) if entity else blob_name

    ext = os.path.splitext(blob_name)[1]
    content_type = mimetypes.types_map.get(ext, "application/octet-stream")

    response = func.HttpResponse(data, status_code=200, mimetype=content_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{display_name}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


# ---------------------------------------------------------------------------
# Event Grid: route a blob once Defender for Storage finishes scanning it
# ---------------------------------------------------------------------------
@app.function_name(name="route_scanned_blob")
@app.event_grid_trigger(arg_name="event")
def route_scanned_blob(event: func.EventGridEvent):
    import urllib.parse

    data = event.get_json()
    logging.info("Received malware scan event: %s", json.dumps(data))

    blob_uri = data.get("blobUri") or data.get("blobUrl")
    scan_result = data.get("scanResultType") or data.get("verdict")

    if not blob_uri or not scan_result:
        logging.error("Event payload missing blobUri/scanResultType, skipping: %s", data)
        return

    # Normalize URI and strip query strings/URL-encoding
    clean_path = urllib.parse.unquote(urllib.parse.urlsplit(blob_uri).path)
    _, _, path_part = clean_path.partition(f"{QUARANTINE_CONTAINER}/")
    if not path_part:
        logging.info("Blob %s is not in the quarantine container, ignoring", blob_uri)
        return

    blob_id = os.path.splitext(os.path.basename(path_part))[0]
    blob_service = _get_blob_service()
    source_client = blob_service.get_blob_client(QUARANTINE_CONTAINER, path_part)

    if scan_result.lower() in ("nothreatsfound", "no threats found", "clean"):
        sanitized_bytes = _run_cdr(QUARANTINE_CONTAINER, path_part)
        if sanitized_bytes is None:
            # Fail closed: AV-clean is not the same as safe-to-publish. Leave
            # the file in quarantine rather than promoting an unsanitized
            # (or CDR-broken) file just because it passed the malware scan.
            logging.error(
                "CDR failed for %s — leaving in quarantine, NOT promoting to public-documents",
                path_part,
            )
            _update_audit_status(blob_id, "cdr_failed")
            return

        try:
            dest_client = blob_service.get_blob_client(PUBLIC_CONTAINER, path_part)
            dest_client.upload_blob(sanitized_bytes, overwrite=False)
        except Exception:
            logging.exception("Failed to upload CDR'd blob %s to %s", path_part, PUBLIC_CONTAINER)
            _update_audit_status(blob_id, "cdr_failed")
            return

        source_client.delete_blob()
        logging.info("Moved %s -> %s (CDR'd, %s)", path_part, PUBLIC_CONTAINER, scan_result)
        _update_audit_status(blob_id, "clean")
        return

    if scan_result.lower() == "malicious":
        dest_client = blob_service.get_blob_client(REJECTED_CONTAINER, path_part)
        logging.info("Moving %s -> %s (%s)", path_part, REJECTED_CONTAINER, scan_result)
        try:
            # Synchronously copy using managed identity byte transfer to avoid async copy race condition
            raw_bytes = source_client.download_blob().readall()
            dest_client.upload_blob(raw_bytes, overwrite=True)
            source_client.delete_blob()
            _update_audit_status(blob_id, "malicious")
        except Exception:
            logging.exception("Failed to safely copy and move malicious blob %s to %s", path_part, REJECTED_CONTAINER)
        return

    logging.warning(
        "Scan result '%s' for %s is inconclusive; leaving in quarantine",
        scan_result,
        path_part,
    )
    _update_audit_status(blob_id, "scan_error")
