from tools.ingest_raw_hardware_eol_sources import (
    extract_rows,
    lifecycle_dates,
    parse_aruba_pdf_rows_from_text,
    parse_calix_pdf_rows_from_text,
    parse_date_any,
    parse_westermo_pdf_rows_from_text,
    rows_to_dicts,
)


def test_canonical_lifecycle_date_aliases():
    row = {
        "EoS Date": "2025/11/06",
        "EoL Date": "09/03/2026",
        "EOSL date": "12/31/2027",
        "Support Until": "Aug 2026",
    }

    dates = lifecycle_dates(row, dayfirst=True)

    assert dates["end_of_sale"] == "2025-11-06"
    assert dates["end_of_life"] == "2026-03-09"
    assert dates["end_of_service"] == "2027-12-31"
    assert dates["end_of_support"] == "2026-08-31"


def test_xlsx_serial_and_slash_date_parsing():
    assert parse_date_any("38127") == "2004-05-20"
    assert parse_date_any("August/2025") == "2025-08-31"
    assert parse_date_any("February/2024\u200b") == "2024-02-29"
    assert parse_date_any("Apr-14-2017") == "2017-04-14"
    assert parse_date_any("Sept 30, 2022") == "2022-09-30"
    assert parse_date_any("May 31,2026") == "2026-05-31"
    assert parse_date_any("09/03/2026", dayfirst=True) == "2026-03-09"
    assert parse_date_any("09/03/2026") == "2026-09-03"


def test_duplicate_colspan_header_does_not_overwrite_model():
    rows = [
        ["Product Name", "Product Name", "Product Status", "EoS Date", "EoL Date"],
        ["Vigor3900", "", "End of Sale", "09/03/2021", "09/03/2026"],
    ]

    parsed = rows_to_dicts(rows, "sample table")

    assert parsed[0]["Product Name"] == "Vigor3900"
    assert parsed[0]["Product Status"] == "End of Sale"


def test_split_product_and_milestone_tables_are_merged(tmp_path):
    html = """
    <table>
      <tr><th>Affected Product</th><th>Description</th><th>Replacement Products</th></tr>
      <tr><td>ABC-1<br>ABC-2</td><td>Example switch</td><td>XYZ-1<br>XYZ-2</td></tr>
    </table>
    <table>
      <tr><th>Milestone</th><th>Date</th></tr>
      <tr><td>Last day to order the products (End-of-Sale)</td><td>20 March 2026</td></tr>
      <tr><td>Last day to receive software bug fixes and support</td><td>20 March 2029</td></tr>
      <tr><td>End-of-Life of product</td><td>20 March 2031</td></tr>
    </table>
    """
    path = tmp_path / "notice.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "arista") if row.get("_source_hint")]

    assert [row["Affected Product"] for row in rows] == ["ABC-1", "ABC-2"]
    assert rows[0]["Replacement Products"] == "XYZ-1"
    assert rows[0]["End of Sale"] == "2026-03-20"
    assert rows[0]["End of Support"] == "2029-03-20"
    assert rows[0]["End of Life"] == "2031-03-20"


def test_perle_discontinuation_heading_date_is_applied(tmp_path):
    html = """
    <h3>Product Discontinuation Notice - 24 April 2026</h3>
    <table>
      <tr>
        <th>Discontinued Part Number</th>
        <th>Discontinued Model</th>
        <th>Replacement Part Number</th>
        <th>Replacement Model</th>
      </tr>
      <tr><td>05091300</td><td>SR-1000-SC05</td><td>05091640</td><td>SR-1110-SC05</td></tr>
    </table>
    """
    path = tmp_path / "discontinuations.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "perle") if row.get("_source_hint")]

    assert rows == [
        {
            "Part Number": "05091300",
            "Product Name": "SR-1000-SC05",
            "Description": "SR-1000-SC05",
            "End of Sale": "2026-04-24",
            "Replacement Products": "05091640; SR-1110-SC05",
            "_source_table": "discontinuations.html discontinuation notice table 1",
            "_source_hint": "Perle product discontinuation notice import",
        }
    ]


def test_calix_pdf_text_applies_milestones_to_affected_parts():
    text = """
    Calix
    CUSTOMER ADVISORY BULLETIN
    DATE: Apr-14-2017
    Current Part Number        Part Name               Part Description
    100-03719                  T071G HGU ONT MODULE    T071G HGU, 1 GE
    Milestone                  Definition              Date
    Product End of Sale announcement date              April 14, 2017
    End of Sale date*                                  July 14, 2017
    End of Support date                                Sept 30, 2022
    REPLACEMENT PRODUCT DETAILS
    100-04253                  801G                    replacement
    """

    rows = parse_calix_pdf_rows_from_text(text, "cab.pdf")

    assert rows[0]["Part Number"] == "100-03719"
    assert rows[0]["End of Sale"] == "2017-07-14"
    assert rows[0]["End of Support"] == "2022-09-30"


def test_aruba_pdf_text_extracts_sku_rows():
    text = """
    HPE ARUBA HARDWARE END OF SALE (EoS)
    JG297A     Switches -Web- mgd Hi     HPE 1920 48G Switch     3/31/2017     2/29/2020        8/31/2017 JL382A     OfficeConnect 1920S 48G 4SFP Switch
    """

    rows = parse_aruba_pdf_rows_from_text(text, "aruba.pdf")

    assert rows[0]["Part Number"] == "JG297A"
    assert rows[0]["Announcement Date"] == "2017-03-31"
    assert rows[0]["End of Sale"] == "2020-02-29"


def test_westermo_pdf_text_extracts_discontinuation_rows():
    text = """
    Westermo
    Part number     Sales part description     Discontinuation Date     Replaced by, part number     Replacement part description
    1100-0432       iSLC30-DDM                 October 23, 2024         1100-0532*                   SLC20-DDM
    """

    rows = parse_westermo_pdf_rows_from_text(text, "westermo.pdf")

    assert rows[0]["Part Number"] == "1100-0432"
    assert rows[0]["End of Sale"] == "2024-10-23"
