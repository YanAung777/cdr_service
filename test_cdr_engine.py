import os
import zipfile
import csv
import pytest
import xml.etree.ElementTree as ET
from PIL import Image

# Import the functionality from your main file
from cdr_engine import (
    route_file_to_cdr,
    sanitize_pdf,
    sanitize_docx,
    sanitize_excel,
    sanitize_csv,
    sanitize_rtf,
    sanitize_zip_archive
)

# =====================================================================
# FIXTURES & CLEANUP ISOLATION
# =====================================================================
@pytest.fixture
def temp_files(tmp_path):
    """
    Manages transient test files safely inside an isolated temporary path matrix.
    Yields paths for processing input, safe processing output, and verification mapping.
    """
    files = {
        "in_file": str(tmp_path / "dirty_payload.tmp"),
        "out_file": str(tmp_path / "clean_reconstructed.tmp"),
        "extract_dir": str(tmp_path / "extracted_verify")
    }
    yield files
    # Cleanup steps run automatically after each test iteration closes
    if os.path.exists(files["extract_dir"]):
        shutil = __import__("shutil")
        shutil.rmtree(files["extract_dir"])


# =====================================================================
# 1. MICROSOFT OFFICE OOXML VALIDATION TESTS (DOCX / XLSX)
# =====================================================================
def test_docx_cdr_strips_vba_macro_binaries(temp_files):
    """Verifies that vbaProject.bin structures are dropped from DOCX files."""
    input_docx = temp_files["in_file"] + ".docx"
    output_docx = temp_files["out_file"] + ".docx"

    # Construct a simulated malicious DOCX archive containing a mock macro layer
    with zipfile.ZipFile(input_docx, 'w') as z:
        z.writestr("word/vbaProject.bin", b"\x00\x01\x02MaliciousVBAByteCode")
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>')
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')

    # Execute disarmament pipeline mapping
    result = sanitize_docx(input_docx, output_docx)
    assert result is True
    assert os.path.exists(output_docx)

    # Deconstruct output archive to verify the critical component is gone
    with zipfile.ZipFile(output_docx, 'r') as z:
        file_list = z.namelist()
        assert "word/vbaProject.bin" not in file_list
        assert "word/document.xml" in file_list


def test_excel_cdr_neutralizes_external_connections_and_dde(temp_files):
    """Ensures external queries and target templates are linked back to localhost."""
    input_xlsx = temp_files["in_file"] + ".xlsx"
    output_xlsx = temp_files["out_file"] + ".xlsx"

    # Inject an external relationship connection string (Remote Template / DDE vector)
    rels_content = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://openxmlformats.org" '
        'Target="http://attacker.com" TargetMode="External"/>'
        '</Relationships>'
    )

    with zipfile.ZipFile(input_xlsx, 'w') as z:
        z.writestr("xl/_rels/workbook.xml.rels", rels_content)
        z.writestr("xl/workbook.xml", '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>')

    # Run Excel structural sanitiser loop
    assert sanitize_excel(input_xlsx, output_xlsx) is True

    # Re-parse generated tree layout to verify the link replacement
    with zipfile.ZipFile(output_xlsx, 'r') as z:
        z.extractall(temp_files["extract_dir"])
    
    verified_xml = os.path.join(temp_files["extract_dir"], "xl/_rels/workbook.xml.rels")
    tree = ET.parse(verified_xml)
    root = tree.getroot()
    
    # Assert network path arrays point exclusively back to zero-trust loopbacks
    for rel in root.iter():
        if rel.attrib.get('TargetMode') == 'External':
            assert rel.attrib.get('Target') == "http://localhost/blocked_by_cdr"


# =====================================================================
# 2. FLAT LAYOUT & TEXT INJECTION TESTS (CSV / RTF)
# =====================================================================
def test_csv_formula_injection_mitigation(temp_files):
    """Validates that command injection triggers inside raw tables are safely prefix-escaped."""
    input_csv = temp_files["in_file"] + ".csv"
    output_csv = temp_files["out_file"] + ".csv"

    # Create hostile CSV data triggering spreadsheet calculation routines
    dirty_data = [
        ["Username", "FormulaPayload"],
        ["Alice", "=cmd|' /C calc'!A1"],
        ["Bob", "@SUM(A1:A2)"],
        ["Charlie", "+1+2;CHOOSE(1...)"]
    ]

    with open(input_csv, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(dirty_data)

    # Disarm
    assert sanitize_csv(input_csv, output_csv) is True

    # Validate output formatting records
    with open(output_csv, mode='r', newline='', encoding='utf-8') as f:
        reader = list(csv.reader(f))
        
        # Verify single-quote cell sanitisation prefix tags
        assert reader[1][1] == "'=cmd|' /C calc'!A1"
        assert reader[2][1] == "'@SUM(A1:A2)"
        assert reader[3][1] == "'+1+2;CHOOSE(1...)"


def test_rtf_payload_scrubbing_removes_ole_objects(temp_files):
    """Verifies that rich text controls tracking embedded OLE executable containers are blocked."""
    input_rtf = temp_files["in_file"] + ".rtf"
    output_rtf = temp_files["out_file"] + ".rtf"

    # Synthesize an exploit layout utilizing standard nested RTF tags (\object and \objdata)
    malicious_rtf_string = r"{\rtf1\ansi{\object\objdata 4d616c6963696f75734279746573} Safe Plain Text Here}"
    
    with open(input_rtf, 'w', encoding='ascii') as f:
        f.write(malicious_rtf_string)

    # Disarm text blocks
    assert sanitize_rtf(input_rtf, output_rtf) is True

    with open(output_rtf, 'r', encoding='ascii') as f:
        clean_content = f.read()
        
        # Confirm hostile structural blocks have been rewritten
        assert r"\object" not in clean_content.lower()
        assert r"\objdata" not in clean_content.lower()
        assert r"\blocked_by_cdr" in clean_content


# =====================================================================
# 3. CONTAINER ARCHIVE INTERCEPTION ENGINE (ZIP SLIP)
# =====================================================================
def test_zip_archive_cdr_prevents_directory_traversal_zip_slip(temp_files):
    """Defends host system runtime paths from path traversal extraction loops."""
    input_zip = temp_files["in_file"] + ".zip"
    output_zip = temp_files["out_file"] + ".zip"

    with zipfile.ZipFile(input_zip, 'w') as z:
        # Attempt to forge extraction mapping layout pointing way outside system directory paths
        z.writestr("../../../../../etc/passwd", "RootUserForcedWriteAttempt")
        z.writestr("safe_report.csv", "Column1,Column2\nStaticText,StaticData")

    # Run the recursive zip sanitizer framework
    assert sanitize_zip_archive(input_zip, output_zip) is True

    # Assert that malicious tree routes were completely discarded during reconstruction
    with zipfile.ZipFile(output_zip, 'r') as z:
        extracted_names = z.namelist()
        assert any("passwd" in name for name in extracted_names) is False
        assert "safe_report.csv" in extracted_names


# =====================================================================
# 4. ORCHESTRATION LAYER DISPATCH MATRIX TEST
# =====================================================================
def test_master_router_selects_correct_extension_logic(temp_files):
    """Confirms the file router handles routing targets natively via file extensions."""
    input_txt_disguised = temp_files["in_file"] + ".csv"
    output_txt_disguised = temp_files["out_file"] + ".csv"

    with open(input_txt_disguised, 'w', encoding='utf-8') as f:
        f.write("=1+1") # Triggers standard formula sanitizer execution rules

    # Pass format through master orchestrator endpoint routing controller
    routing_success = route_file_to_cdr(input_txt_disguised, output_txt_disguised)
    assert routing_success is True

    with open(output_txt_disguised, 'r', encoding='utf-8') as f:
        content = f.read()
        assert content.startswith("'=1+1") # Confirms CSV logic ran based on format map
