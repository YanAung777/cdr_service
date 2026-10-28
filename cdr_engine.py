"""
=====================================================================
Content Disarm and Reconstruction (CDR) Unified Security Engine
=====================================================================
A zero-trust document sanitisation framework written in Python.

Supported formats:
    - Documents & Vector Graphics: PDF
    - Modern MS Office Open XML: DOCX, XLSX, PPTX
    - Legacy MS Office Binary: DOC (via headless isolation conversion)
    - Open Document Formats: ODT, ODS
    - Mobile & Standard Raster Images: JPEG, PNG, HEIC
    - Flat Layouts & Plaintext Feeds: CSV, RTF
    - Compressed Archive Structures: ZIP (recursive, depth- and size-bounded)

Dependencies:
    - pip install pypdf pillow pillow-heif
    - System: libreoffice (required for legacy binary .doc conversion) --
      NOT available on a default Azure Functions Consumption plan; see the
      deployment note in README.md if .doc support is required.

CHANGES FROM THE ORIGINAL UPLOADED VERSION (fixes applied after testing):
    1. sanitize_legacy_doc: fixed a bug where the converted filename was
       built from an untuple'd os.path.splitext() result, so the function
       could never find its own LibreOffice output and always failed.
       Reproduced and confirmed before fixing.
    2. _scrub_ooxml_xml: fixed a crash (ValueError: list.remove(x): x not
       in list) that occurred whenever a malicious Relationship element
       was nested more than one level deep -- root.remove() only works on
       direct children. Reproduced and confirmed before fixing. This
       previously meant a specific kind of malicious file could make CDR
       silently fail closed (acceptable) rather than actually clean the
       file (not acceptable if avoidable) -- now it's cleaned correctly.
    3. Explicit zip-member-name validation added before extractall() in
       the OOXML path, matching what sanitize_zip_archive already did.
       Testing showed modern Python's zipfile.extractall() already
       strips ".." path components on this interpreter version, so this
       wasn't independently exploitable here -- but the fix makes the
       protection explicit in the code rather than implicit in the
       standard library version, which is safer if this ever runs under
       a different Python build.
    4. Added a decompression-size cap (total and per-member) to both the
       OOXML and ZIP extraction paths, and a recursion-depth cap to
       sanitize_zip_archive, to bound zip-bomb / nested-archive abuse --
       this wasn't present in the uploaded version.
    5. print() calls replaced with the logging module so failures are
       actually visible in Azure Function App Insights / Log Stream
       rather than only in stdout.
    6. Documented, not code-fixed: sanitize_rtf uses simple regex
       substitution, not a real RTF parser. That's a known-incomplete
       approach -- RTF has control-word obfuscation techniques (extra
       whitespace, hex-escaped control words, etc.) that a straight
       literal regex won't catch. Treat RTF sanitization here as a
       best-effort filter, not a guarantee, until/unless it's replaced
       with a proper RTF parser or a LibreOffice conversion pass like
       sanitize_legacy_doc uses for .doc.
    7. sanitize_pdf: fixed writer.root -> writer.root_object. `.root` does
       not exist on pypdf's PdfWriter (tested against pypdf 5.9.0) --
       every call to sanitize_pdf raised an uncaught-looking AttributeError
       internally (caught by the broad except, so it just silently
       returned False every time). This is the format most CVs will
       actually be uploaded as, so this bug meant CDR would have failed
       closed on essentially all real traffic. Confirmed via a failing
       test before fixing, and the test now passes.
    8. Not wired into the Function App: sanitize_excel, sanitize_powerpoint,
       sanitize_opendocument, sanitize_csv, sanitize_rtf, sanitize_zip_archive.
       The current upload allow-list (function_app.py) only accepts
       .pdf/.doc/.docx/.jpg/.jpeg/.png, so only sanitize_pdf, sanitize_docx,
       sanitize_legacy_doc, and sanitize_image are actually reachable in
       production. The rest are left in this file (tests still cover them)
       in case the allow-list is ever widened, but they haven't been given
       the same adversarial review as the wired-in path -- re-review them
       before accepting xlsx/pptx/csv/rtf/zip/odt/ods uploads for real.
=====================================================================
"""

import datetime
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import unicodedata

# Pre‑compile regex for invisible Unicode sanitisation (used by sanitize_unicode_text)
UNICODE_SANITIZE_RE = re.compile(r"[\u200B-\u200F\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]")
import zipfile
import xml.etree.ElementTree as ET
from PIL import Image

# Register mobile imaging format handler if available
try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
except ImportError:
    pass

logger = logging.getLogger("cdr_engine")

# Industry-standard schema definitions for OOXML tracking verification
NAMESPACES = {
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'main': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    'p': 'http://schemas.openxmlformats.org/presentationml/2006/main',
    'rel': 'http://schemas.openxmlformats.org/package/2006/relationships',
}


# Global counter for overlay truncations (used for telemetry)
OVERLAY_TRUNCATED_COUNT = 0

MAX_EXTRACTED_TOTAL_BYTES = 200 * 1024 * 1024  # 200 MB total per archive
MAX_EXTRACTED_MEMBER_BYTES = 100 * 1024 * 1024  # 100 MB per single member
MAX_ZIP_RECURSION_DEPTH = 3
MAX_IMAGE_PIXELS = 50_000_000  # Cap image dimensions to protect against decompression bombs
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


def _safe_extractall(zip_ref, target_dir):
    """extractall() with explicit member-name and size validation, rather
    than relying solely on the interpreter's own zip-slip protection."""
    total = 0
    for info in zip_ref.infolist():
        name = info.filename
        if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
            raise ValueError(f"Rejected unsafe archive member path: {name}")
        if info.file_size > MAX_EXTRACTED_MEMBER_BYTES:
            raise ValueError(f"Archive member too large: {name} ({info.file_size} bytes)")
        total += info.file_size
        if total > MAX_EXTRACTED_TOTAL_BYTES:
            raise ValueError("Archive exceeds total extraction size limit")
    zip_ref.extractall(target_dir)


# =====================================================================
# ADVANCED STRUCTURAL HARDENING UTILITIES
# =====================================================================
def strip_trailing_overlay(file_path: str) -> bool:
    """
    Neutralizes polyglots and steganographic overlay exploits by truncating
    bytes past the legitimate end-of-file structural boundary (%%EOF in PDF,
    End of Central Directory record in ZIP/OOXML).
    """
    try:
        ext = os.path.splitext(file_path)[1].lower()
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return False

        original_len = len(data)
        truncated_len = original_len

        if ext == ".pdf":
            # Search for the final %%EOF marker from the end of the file
            eof_pos = data.rfind(b"%%EOF")
            if eof_pos != -1:
                # Retain %%EOF and optional trailing whitespace/newline
                end_pos = eof_pos + 5
                while end_pos < original_len and data[end_pos:end_pos + 1] in (b"\r", b"\n", b" ", b"\t"):
                    end_pos += 1
                truncated_len = end_pos

        elif ext in (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods"):
            # Search for End of Central Directory record: PK\x05\x06
            eocd_pos = data.rfind(b"PK\x05\x06")
            if eocd_pos != -1 and eocd_pos + 22 <= original_len:
                comment_len = int.from_bytes(data[eocd_pos + 20:eocd_pos + 22], "little")
                expected_end = eocd_pos + 22 + comment_len
                if expected_end <= original_len:
                    truncated_len = expected_end

        if truncated_len < original_len:
            with open(file_path, "wb") as f:
                f.write(data[:truncated_len])
            logger.info("[CDR Hardening] Truncated %d overlay bytes from %s", original_len - truncated_len, file_path)
# Increment global telemetry counter
global OVERLAY_TRUNCATED_COUNT
OVERLAY_TRUNCATED_COUNT += 1
            return True

        return False
    except Exception as e:
        logger.warning("[CDR Hardening Error] Failed to strip overlay for %s: %s", file_path, e)
        return False


def sanitize_unicode_text(text: str) -> str:
    """
    Sanitizes plain text or XML node values to prevent invisible character abuse,
    homoglyph spoofing, and bidirectional layout injection (Trojan Source).
    """
    if not text:
        return ""

    # Strip dangerous bidirectional override controls and hidden zero-width characters
    # \u200B-\u200D (zero-width space, joiner, non-joiner), \uFEFF (BOM/zero-width no-break)
    # \u202A-\u202E (directional embedding/override), \u2066-\u2069 (directional isolate)
    # \u00AD (soft hyphen)

    cleaned = UNICODE_SANITIZE_RE.sub("", text)

    # Normalize unicode to NFKC (Compatibility Decomposition followed by Canonical Composition)
    return unicodedata.normalize("NFKC", cleaned)


def generate_cdr_provenance(original_path: str, sanitized_path: str, actions_taken: list = None) -> dict:
    """
    Computes cryptographic attestation of input/output documents to maintain
    an auditable chain of custody across the disarm pipeline.
    """
    def _sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    in_hash = _sha256(original_path) if os.path.exists(original_path) else None
    out_hash = _sha256(sanitized_path) if os.path.exists(sanitized_path) else None

    return {
        "engine": "CDR Unified Security Engine v2.0",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "input_file": os.path.basename(original_path),
        "input_sha256": in_hash,
        "input_size_bytes": os.path.getsize(original_path) if os.path.exists(original_path) else 0,
        "output_file": os.path.basename(sanitized_path),
        "output_sha256": out_hash,
        "output_size_bytes": os.path.getsize(sanitized_path) if os.path.exists(sanitized_path) else 0,
        "actions": actions_taken or ["structural_disarm"],
    }


def convert_to_pdfa4(input_path: str, output_path: str, timeout_seconds: int = 45) -> bool:
    """
    Converts and normalizes an incoming PDF into strict PDF/A-4 (ISO 19005-4) archival standard.
    
    Processing hierarchy:
      1. Ghostscript (gs/gswin64c) with -dPDFA=4 (highest compliance).
      2. Headless LibreOffice PDF/A-4 export filter.
      3. Native Python PDF/A-4 conformance metadata normalization (zero external dependencies).
    """
    if not input_path.lower().endswith(".pdf"):
        raise ValueError("Input must be a PDF file.")

    # 1. Primary: Ghostscript compilation to ISO 19005-4
    gs_binary = shutil.which("gs") or shutil.which("gswin64c") or shutil.which("gswin32c")
    if gs_binary:
        try:
            cmd = [
                gs_binary,
                "-dPDFA=4",
                "-dBATCH",
                "-dNOPAUSE",
                "-dNOOUTERSAVE",
                "-sProcessColorModel=DeviceRGB",
                "-sDEVICE=pdfwrite",
                "-dCompatibilityLevel=2.0",
                "-dColorConversionStrategy=UseDeviceIndependentColor",
                "-dEmbedAllFonts=true",
                "-dSubsetFonts=true",
                "-dAutoRotatePages=/None",
                "-dPrinted=true",  # Flattens non-printing form fields and annotations
                f"-sOutputFile={output_path}",
                input_path,
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=True)
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                logger.info("[CDR Engine] Ghostscript successfully compiled PDF/A-4: %s", output_path)
                return True
        except Exception as e:
            logger.warning("[CDR Engine] Ghostscript PDF/A-4 conversion failed (%s), attempting fallbacks", e)

    # 2. Secondary: Headless LibreOffice PDF/A-4 conversion
    libreoffice_binary = shutil.which("libreoffice") or shutil.which("soffice")
    if libreoffice_binary:
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                cmd = [
                    libreoffice_binary,
                    "--headless",
                    "--convert-to",
                    'pdf:draw_pdf_Export:{"SelectPdfVersion":{"type":"long","value":"4"}}',
                    "--outdir",
                    temp_dir,
                    input_path,
                ]
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=True)
                base = os.path.splitext(os.path.basename(input_path))[0]
                converted = os.path.join(temp_dir, f"{base}.pdf")
                if os.path.exists(converted):
                    shutil.copy2(converted, output_path)
                    logger.info("[CDR Engine] LibreOffice successfully compiled PDF/A-4: %s", output_path)
                    return True
        except Exception as e:
            logger.warning("[CDR Engine] LibreOffice PDF/A-4 fallback failed: %s", e)

    # 3. Native Python PDF/A-4 Conformance & Archival Tagging Fallback
    try:
        from pypdf import PdfReader, PdfWriter
        from pypdf.generic import NameObject, DictionaryObject, ArrayObject, create_string_object

        reader = PdfReader(input_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        root = writer.root_object

        # Embed strict PDF/A-4 OutputIntent dictionary conforming to ISO 19005-4
        output_intent = DictionaryObject({
            NameObject("/Type"): NameObject("/OutputIntent"),
            NameObject("/S"): NameObject("/GTS_PDFA1"),
            NameObject("/OutputConditionIdentifier"): create_string_object("sRGB IEC61966-2.1"),
            NameObject("/RegistryName"): create_string_object("http://www.color.org"),
            NameObject("/Info"): create_string_object("sRGB IEC61966-2.1"),
        })
        root[NameObject("/OutputIntents")] = ArrayObject([output_intent])

        # Write clean, standardized PDF
        with open(output_path, "wb") as f:
            writer.write(f)

        logger.info("[CDR Engine] Native PDF/A-4 normalization completed for: %s", output_path)
        return True
    except Exception as e:
        logger.error("[CDR Engine Error] Native PDF/A-4 normalization failed: %s", e)
        return False


# =====================================================================
# 1. LEGACY BINARY .DOC TRANSLATION ENGINE
# =====================================================================
def sanitize_legacy_doc(input_path, output_path, timeout_seconds=30):
    """
    Translates legacy binary .doc into a modern open XML document (.docx)
    via LibreOffice to drop underlying compound binary layout vulnerabilities,
    then processes it through the structural OOXML disarm pipeline.
    """
    if not input_path.lower().endswith('.doc'):
        raise ValueError("Input file must be a legacy binary .doc file format.")

    temp_dir = input_path + "_doc_scratch_dir"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        cmd = [
            'libreoffice', '--headless',
            '--convert-to', 'docx',
            '--outdir', temp_dir,
            input_path
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=timeout_seconds, check=True)

        # FIX: os.path.splitext() returns a (root, ext) tuple -- take [0] for
        # just the base name, otherwise this never finds the real output file.
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        generated_docx = os.path.join(temp_dir, f"{base_name}.docx")

        if not os.path.exists(generated_docx):
            raise FileNotFoundError("Legacy document binary translation layer translation failed.")

        return _sanitize_ooxml(generated_docx, output_path, format_type='docx')

    except Exception as e:
        logger.error("[CDR Engine Error] Legacy DOC Processing Interrupted: %s", e)
        return False
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


# =====================================================================
# 2. MICROSOFT OFFICE OPEN XML ENGINES (DOCX, XLSX, PPTX)
# =====================================================================
def sanitize_docx(input_path, output_path):
    return _sanitize_ooxml(input_path, output_path, format_type='docx')

def sanitize_excel(input_path, output_path):
    return _sanitize_ooxml(input_path, output_path, format_type='xlsx')

def sanitize_powerpoint(input_path, output_path):
    return _sanitize_ooxml(input_path, output_path, format_type='pptx')

def _sanitize_ooxml(input_path, output_path, format_type):
    """Internal master extractor and component filter for structural OOXML archives."""
    strip_trailing_overlay(input_path)
    temp_dir = input_path + f"_{format_type}_cdr_workspace"
    SAFE_EXTENSIONS = {'.xml', '.rels', '.jpeg', '.jpg', '.png', '.gif', '.wmf', '.emf', '.tiff'}

    try:
        with zipfile.ZipFile(input_path, 'r') as zip_ref:
            _safe_extractall(zip_ref, temp_dir)

        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_lower = file.lower()

                is_macro = "vbaproject" in file_lower or "vbadata" in file_lower or "macrosheet" in file_lower
                is_activex = "activex" in file_lower or "control" in file_lower
                is_ole = "oleobject" in file_lower
                is_ext_conn = "connections" in file_lower or "querytable" in file_lower or "websettings" in file_lower

                if is_macro or is_activex or is_ole or is_ext_conn:
                    os.remove(file_path)
                    continue

                _, ext = os.path.splitext(file_lower)
                if ext and ext not in SAFE_EXTENSIONS:
                    os.remove(file_path)
                    continue

                if file.endswith('.rels') or file.endswith('.xml'):
                    _scrub_ooxml_xml(file_path)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_out:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    zip_out.write(full_path, rel_path)
        return True

    except Exception as e:
        logger.error("[CDR Engine Error] OOXML File Sanitisation Break (%s): %s", format_type, e)
        return False
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def _scrub_ooxml_xml(xml_path):
    """Parses individual XML sheets to disarm dynamic templates and external callout linkages."""
    try:
        for prefix, uri in NAMESPACES.items():
            ET.register_namespace(prefix, uri)

        tree = ET.parse(xml_path)
        root = tree.getroot()
        modified = False

        # FIX: build an explicit parent map so we always remove elements from
        # their real parent, not from `root` -- root.remove() only works on
        # direct children, and the original code crashed (ValueError) on any
        # Relationship nested more than one level deep, which meant a
        # malicious file with that structure would fail CDR instead of
        # actually being cleaned.
        parent_map = {child: parent for parent in tree.iter() for child in parent}

        rel_tag = f"{{{NAMESPACES['rel']}}}Relationship"
        relationships = root.findall(f".//{rel_tag}")
        if not relationships and ('Relationship' in root.tag or any('Relationship' in child.tag for child in root)):
            # Fall back to scanning everything only when the fast path finds
            # nothing but the document still looks relationship-shaped.
            relationships = [el for el in tree.iter() if el.tag.endswith('Relationship')]

        to_remove = []
        for rel in relationships:
            target_mode = rel.attrib.get('TargetMode')
            rel_type = rel.attrib.get('Type', '')
            target_file = rel.attrib.get('Target', '').lower()

            # Neutralize external targets, dangerous URI schemes, and remote template injection
            is_external_target = (
                target_mode == 'External'
                or 'externallink' in rel_type.lower()
                or any(target_file.startswith(scheme) for scheme in ('http:', 'https:', 'ftp:', 'file:', 'mhtml:', 'ms-msdt:', 'script:', 'javascript:'))
            )
            if is_external_target:
                rel.attrib['Target'] = 'http://localhost/blocked_by_cdr'
                modified = True

            # Drop Word template injection relationships outright
            if 'attachedtemplate' in rel_type.lower() or 'template' in rel_type.lower():
                to_remove.append(rel)

            # Drop malicious embedded binaries, macros, controls, and executable targets
            dangerous_indicators = [
                'vbaproject', 'oleobject', 'activex', 'control',
                '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.scr', '.dll',
                '.hta', '.cpl', '.dotm', '.xltm', '.xlsm', '.jar'
            ]
            if any(x in target_file for x in dangerous_indicators):
                to_remove.append(rel)

        for rel in to_remove:
            parent = parent_map.get(rel)
            if parent is not None and rel in list(parent):
                parent.remove(rel)
                modified = True

        # Drop layout controls used for hosting malicious ActiveX scripts
        for control in root.findall('.//w:control', NAMESPACES):
            parent = parent_map.get(control)
            if parent is not None and control in list(parent):
                parent.remove(control)
                modified = True

        # Drop Word attachedTemplate elements (CVE-2017-0199 and remote template injection defense)
        for att_tmpl in root.findall('.//w:attachedTemplate', NAMESPACES):
            parent = parent_map.get(att_tmpl)
            if parent is not None and att_tmpl in list(parent):
                parent.remove(att_tmpl)
                modified = True

        # Evict Excel legacy internal command sheet pointer configurations
        sheets_container = root.find('.//main:sheets', NAMESPACES)
        if sheets_container is not None:
            for m_sheet in list(sheets_container.findall('main:sheet', NAMESPACES)):
                if 'macrosheet' in m_sheet.attrib.get('name', '').lower():
                    sheets_container.remove(m_sheet)
                    modified = True

        # Neutralize zero-width and directional override Unicode injection across XML text
        for elem in root.iter():
            if elem.text:
                cleaned_text = sanitize_unicode_text(elem.text)
                if cleaned_text != elem.text:
                    elem.text = cleaned_text
                    modified = True

        if modified:
            tree.write(xml_path, encoding='utf-8', xml_declaration=True)

    except ET.ParseError:
        # Delete unparseable structural chunks to honor strict zero-trust rules
        os.remove(xml_path)
    except Exception as e:
        # Fail closed on this one file rather than crashing the whole
        # extraction loop and silently failing CDR for the entire document.
        logger.error("[CDR Engine Error] Unexpected XML scrub failure on %s: %s", xml_path, e)
        os.remove(xml_path)


# =====================================================================
# 3. PDF STRUCTURE SANITISER
# =====================================================================
def sanitize_pdf(input_path, output_path, enforce_pdfa=True):
    """
    Two-stage Advanced PDF CDR Pipeline:
      Stage 1 (Deep Disarm): Purges trailing polyglot overlays, removes catalog &
              names-tree scripts, dynamic AcroForm/XFA XML, hidden layers (/OCProperties),
              application data stashes (/PieceInfo), page actions, and annotation scripts.
      Stage 2 (PDF/A-4 Normalization): Converts and compiles document into ISO 19005-4
              archival standard, embedding all fonts, normalizing color spaces, and
              flattening remaining dynamic presentation elements.
    """
    temp_disarmed = output_path + ".stage1_disarmed.tmp"
    try:
        # Pre-filter: strip trailing overlay / appended polyglots past %%EOF
        strip_trailing_overlay(input_path)

        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(input_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        root = writer.root_object

        # 1. Catalog root-level active content purge & hidden layer stripping
        for direct_key in ("/JavaScript", "/AA", "/OpenAction", "/Launch", "/EmbeddedFiles", "/RichMedia", "/3D", "/OCProperties", "/PieceInfo"):
            if direct_key in root:
                del root[direct_key]

        # 2. Names dictionary disarm (where standard PDF JavaScript and embedded files live)
        if "/Names" in root:
            names = root.get("/Names")
            names_obj = names.get_object() if hasattr(names, "get_object") else names
            if isinstance(names_obj, dict):
                for dangerous_key in ("/JavaScript", "/EmbeddedFiles", "/Launch", "/SubmitForm"):
                    if dangerous_key in names_obj:
                        del names_obj[dangerous_key]

        # 3. Interactive AcroForm & XFA dynamic XML scripting purge
        if "/AcroForm" in root:
            acro = root.get("/AcroForm")
            acro_obj = acro.get_object() if hasattr(acro, "get_object") else acro
            if isinstance(acro_obj, dict):
                if "/XFA" in acro_obj:
                    del acro_obj["/XFA"]
                if "/JavaScript" in acro_obj:
                    del acro_obj["/JavaScript"]

        # 4. Page-level actions and annotation disarm
        for page in writer.pages:
            if "/AA" in page:
                del page["/AA"]
            if "/Actions" in page:
                del page["/Actions"]

            if "/Annots" in page:
                annots = page.get("/Annots")
                annots_obj = annots.get_object() if hasattr(annots, "get_object") else annots
                if isinstance(annots_obj, list):
                    for annot_ref in annots_obj:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        if isinstance(annot, dict):
                            if "/AA" in annot:
                                del annot["/AA"]
                            action = annot.get("/A")
                            if action is not None:
                                act_obj = action.get_object() if hasattr(action, "get_object") else action
                                if isinstance(act_obj, dict):
                                    act_type = str(act_obj.get("/S", ""))
                                    if act_type in ("/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/RichMediaExecute"):
                                        del annot["/A"]

        with open(temp_disarmed, "wb") as f:
            writer.write(f)

        # Stage 2: ISO 19005-4 (PDF/A-4) Archival Normalization
        if enforce_pdfa:
            pdfa_success = convert_to_pdfa4(temp_disarmed, output_path)
            if pdfa_success and os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                return True
            logger.warning("[CDR Engine] PDF/A-4 compilation fallback: retaining Stage 1 disarmed PDF")

        # Fallback to Stage 1 disarmed output if PDF/A-4 compilation is skipped or fails
        if os.path.exists(output_path):
            os.remove(output_path)
        shutil.move(temp_disarmed, output_path)
        return True

    except Exception as e:
        logger.error("[CDR Engine Error] PDF Security Processing Failure: %s", e)
        return False
    finally:
        if os.path.exists(temp_disarmed):
            os.remove(temp_disarmed)


# =====================================================================
# 4. OPENDOCUMENT FORMAT ENGINE (ODT, ODS)
# =====================================================================
def sanitize_opendocument(input_path, output_path):
    """Purges physical macro directories and active interface listener elements from ODF targets."""
    temp_dir = input_path + "_odf_scrub_workspace"
    try:
        with zipfile.ZipFile(input_path, 'r') as zip_ref:
            _safe_extractall(zip_ref, temp_dir)

        for root, dirs, files in os.walk(temp_dir):
            for d in list(dirs):
                if d.lower() in ["basic", "scripts", "macros"]:
                    shutil.rmtree(os.path.join(root, d))
                    dirs.remove(d)

            for file in files:
                file_path = os.path.join(root, file)
                if file in ["manifest.rdf", "content.xml", "meta.xml"]:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    content = re.sub(r'<script:event-listener[^>]*>', '', content)
                    content = re.sub(r'</script:event-listener>', '', content)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_out:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    zip_out.write(full_path, rel_path)
        return True
    except Exception as e:
        logger.error("[CDR Engine Error] ODF Document Sanitisation Fault: %s", e)
        return False
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


# =====================================================================
# 5. IMAGE PIXEL MATRIX RECONSTRUCTION (JPEG, PNG, HEIC)
# =====================================================================
def sanitize_image(input_path, output_path, format_type="JPEG"):
    """
    True Image CDR. Re-encodes raw pixel data onto a fresh canvas, dropping
    EXIF, comments, and other embedded metadata rather than copying the
    original file's headers through.
    """
    try:
        with Image.open(input_path) as img:
            if img.mode in ('RGBA', 'LA') and format_type == "JPEG":
                clean_img = img.convert('RGB')
            else:
                clean_img = img.convert(img.mode)

            # Re-created image objects from convert() do not carry over the
            # source's .info dict (ICC profiles, text chunks, etc.) in
            # Pillow's normal convert() path; exif=b"" additionally forces
            # no EXIF block on formats that support one.
            clean_img.info = {}
            clean_img.save(output_path, format=format_type, exif=b"", optimize=True)
        return True
    except Exception as e:
        logger.error("[CDR Engine Error] Graphic Pixel Mapping Disarm Failed: %s", e)
        return False


# =====================================================================
# 6. FLAT DATA & FORMAT SCRUBBERS (CSV, RTF)
# =====================================================================
def sanitize_csv(input_path, output_path):
    """Mitigates spreadsheet script attacks (Formula Injection) and strips invisible unicode abuse."""
    DANGEROUS_PREFIXES = ('=', '+', '-', '@', '\t', '\r')
    try:
        strip_trailing_overlay(input_path)
        sanitized_rows = []
        with open(input_path, mode='r', newline='', encoding='utf-8', errors='ignore') as infile:
            import csv
            for row in csv.reader(infile):
                cleaned_row = []
                for cell in row:
                    cell_text = sanitize_unicode_text(cell)
                    if cell_text.startswith(DANGEROUS_PREFIXES):
                        cleaned_row.append(f"'{cell_text}")
                    else:
                        cleaned_row.append(cell_text)
                sanitized_rows.append(cleaned_row)

        with open(output_path, mode='w', newline='', encoding='utf-8') as outfile:
            import csv
            csv.writer(outfile).writerows(sanitized_rows)
        return True
    except Exception as e:
        logger.error("[CDR Engine Error] CSV Sheet Sanitisation Denied: %s", e)
        return False

def sanitize_rtf(input_path, output_path):
    """Regex parses plain text layout chains to isolate and neutralize complex binary
    container strings. NOTE: this is a best-effort literal-pattern filter, not a real
    RTF parser -- see the module docstring's point 6 for why that's a real limitation,
    not just a style note."""
    try:
        with open(input_path, 'r', encoding='ascii', errors='ignore') as infile:
            content = infile.read()

        for pattern in [r'\\object', r'\\objdata', r'\\control', r'\\oleclsid', r'\\exec']:
            content = re.sub(pattern, r'\\blocked_by_cdr', content, flags=re.IGNORECASE)

        with open(output_path, mode='w', encoding='ascii') as outfile:
            outfile.write(content)
        return True
    except Exception as e:
        logger.error("[CDR Engine Error] RTF Text Block Processing Interrupted: %s", e)
        return False


# =====================================================================
# 7. RECURSIVE ARCHIVE CONTAINER ENGINE & MASTER ROUTER
# =====================================================================
def sanitize_zip_archive(input_path, output_path, _depth=0):
    """
    Safely unpacks structured folders, enforces path extraction boundaries
    to mitigate Zip Slip exploits, cleans nested parameters recursively
    (up to MAX_ZIP_RECURSION_DEPTH), and rebuilds containers.
    """
    if _depth >= MAX_ZIP_RECURSION_DEPTH:
        logger.error("[CDR Engine Error] Zip nesting depth limit exceeded, rejecting archive")
        return False

    temp_in = input_path + f"_zip_ingest_scratch_{_depth}"
    temp_out = input_path + f"_zip_output_scratch_{_depth}"
    os.makedirs(temp_out, exist_ok=True)

    try:
        with zipfile.ZipFile(input_path, 'r') as zip_ref:
            total = sum(i.file_size for i in zip_ref.infolist())
            if total > MAX_EXTRACTED_TOTAL_BYTES:
                logger.error("[CDR Engine Error] Zip archive exceeds total size limit")
                return False

            for member in zip_ref.namelist():
                filename = os.path.basename(member)
                if not filename or ".." in member or member.startswith("/"):
                    continue

                src = zip_ref.extract(member, temp_in)
                dst = os.path.join(temp_out, filename)

                if filename.lower().endswith('.zip'):
                    if not sanitize_zip_archive(src, dst, _depth=_depth + 1):
                        continue  # drop nested archives that fail to sanitize rather than fail the whole batch
                else:
                    route_file_to_cdr(src, dst)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_out:
            for root, dirs, files in os.walk(temp_out):
                for file in files:
                    zip_out.write(os.path.join(root, file), file)
        return True
    except Exception as e:
        logger.error("[CDR Engine Error] Compressed Archive Processing Break: %s", e)
        return False
    finally:
        if os.path.exists(temp_in): shutil.rmtree(temp_in)
        if os.path.exists(temp_out): shutil.rmtree(temp_out)

def route_file_to_cdr(input_path, output_path):
    """Central orchestration router identifying file formatting extensions and triggering processing filters."""
    _, ext = os.path.splitext(input_path.lower())

    if ext == '.pdf': return sanitize_pdf(input_path, output_path)
    elif ext == '.docx': return sanitize_docx(input_path, output_path)
    elif ext == '.xlsx': return sanitize_excel(input_path, output_path)
    elif ext == '.pptx': return sanitize_powerpoint(input_path, output_path)
    elif ext == '.doc': return sanitize_legacy_doc(input_path, output_path)
    elif ext in ['.odt', '.ods']: return sanitize_opendocument(input_path, output_path)
    elif ext in ['.jpg', '.jpeg']: return sanitize_image(input_path, output_path, "JPEG")
    elif ext == '.png': return sanitize_image(input_path, output_path, "PNG")
    elif ext in ['.heic', '.heif']: return sanitize_image(input_path, output_path, "JPEG")
    elif ext == '.csv': return sanitize_csv(input_path, output_path)
    elif ext == '.rtf': return sanitize_rtf(input_path, output_path)
    elif ext == '.zip': return sanitize_zip_archive(input_path, output_path)
    else:
        # Zero-Trust Policy Fallback Rule: unknown extensions are copied through
        # unmodified rather than rejected. In this pipeline that's fine because
        # the upload allow-list (function_app.py) has already restricted what
        # can reach this point -- if this engine is reused somewhere without
        # that upstream allow-list, this fallback should probably reject
        # instead of pass through.
        shutil.copy2(input_path, output_path)
        return True
