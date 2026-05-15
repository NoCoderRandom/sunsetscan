import json
from datetime import date

from tools.ingest_raw_hardware_eol_sources import (
    build_vendor_filter,
    choose_model,
    extract_amcrest_discontinued_firmware_rows,
    extract_balluff_product_lifecycle_rows,
    extract_beckhoff_service_product_rows,
    extract_broadcom_bluecoat_packetshaper_rows,
    extract_hanwha_discontinued_product_rows,
    extract_hp_designjet_eosl_json_rows,
    extract_kyocera_taskalfa_sales_end_rows,
    extract_lexmark_product_eosl_rows,
    extract_rows,
    extract_synology_product_status_rows,
    extract_zebra_discontinued_product_rows,
    import_dedupe_key,
    lifecycle_dates,
    load_database_for_ingest,
    orphan_raw_files,
    parse_advantech_ntron_pdf_rows_from_text,
    parse_alcatel_lucent_pdf_rows_from_text,
    parse_aruba_pdf_rows_from_text,
    parse_atx_digistream_pdf_rows_from_text,
    parse_avigilon_pdf_rows_from_text,
    parse_avaya_pdf_rows_from_text,
    parse_bosch_ip_video_firmware_pdf_rows_from_text,
    parse_broadcom_brocade_pdf_rows_from_text,
    parse_calix_pdf_rows_from_text,
    parse_celona_pdf_rows_from_text,
    parse_date_any,
    parse_eltako_safe_iv_pdf_rows_from_text,
    parse_genexis_psti_pdf_rows_from_text,
    parse_geovision_pdf_rows_from_text,
    parse_helmholz_myrex24_pdf_rows_from_text,
    parse_hikvision_discontinuation_pdf_rows_from_text,
    parse_hirschmann_belden_pdn_rows_from_text,
    parse_mobotix_product_news_pdf_rows_from_text,
    parse_nvidia_mellanox_pdf_rows_from_text,
    parse_pilz_pnozmulti_pdf_rows_from_text,
    parse_silver_peak_edgeconnect_pdf_rows_from_text,
    extract_siedle_discontinued_product_rows,
    parse_softing_product_support_dates,
    parse_weidmueller_datasheet_pdf_rows_from_text,
    parse_westermo_pdf_rows_from_text,
    row_to_record,
    rows_to_dicts,
    update_vendor_metadata,
    vendor_skip_reason,
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


def test_import_dedupe_key_preserves_plus_model_variants():
    base = {
        "vendor_slug": "synology",
        "hardware_version": "",
        "region": "",
    }

    assert import_dedupe_key({**base, "part_number": "DS214"}) != import_dedupe_key(
        {**base, "part_number": "DS214+"}
    )


def test_eos_abbreviation_does_not_override_end_of_support_header():
    row = {
        "End of Support Date (EOS)": "2031-01-13",
    }

    dates = lifecycle_dates(row)

    assert dates["end_of_sale"] is None
    assert dates["end_of_support"] == "2031-01-13"


def test_xlsx_serial_and_slash_date_parsing():
    assert parse_date_any("38127") == "2004-05-20"
    assert parse_date_any("August/2025") == "2025-08-31"
    assert parse_date_any("February/2024\u200b") == "2024-02-29"
    assert parse_date_any("Apr-14-2017") == "2017-04-14"
    assert parse_date_any("Sept 30, 2022") == "2022-09-30"
    assert parse_date_any("May 31,2026") == "2026-05-31"
    assert parse_date_any("01.06.2015") == "2015-06-01"
    assert parse_date_any("2026.12.31") == "2026-12-31"
    assert parse_date_any("25\u5e7412\u670831\u65e5") == "2025-12-31"
    assert parse_date_any("2025 \u5e7412\u670831\u65e5") == "2025-12-31"
    assert parse_date_any("2022-10") == "2022-10-31"
    assert parse_date_any("2024 December") == "2024-12-31"
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


def test_choose_model_ignores_internal_prefer_model_flag():
    row = {
        "_prefer_model": True,
        "Model": "PNOZ m1p",
        "Part Number": "773100",
    }

    model, part_number, _ = choose_model(row)

    assert model == "PNOZ m1p"
    assert part_number == "773100"


def test_gigaset_style_german_headers_are_canonicalized():
    row = {
        "Product": "A690 IP",
        "End of sale (EoS)": "2024 December",
        "End of live (EoL)": "2026 February",
        "Alternativ product": "BasicLine IP",
    }

    dates = lifecycle_dates(row)
    model, part_number, _ = choose_model(row)

    assert model == "A690 IP"
    assert part_number == "A690 IP"
    assert dates["end_of_sale"] == "2024-12-31"
    assert dates["end_of_life"] == "2026-02-28"


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


def test_advantech_ntron_pdf_text_imports_phase_out_as_review():
    text = """
    IIoT Product End-of-Life Notice
    Product Part Numbers Affected by This Announcement
     End of Life Product          Suggest Replacement Product          Replacement Available Date
     BB-102MC-SC-MDR              IMC-350I-M8-A                        Available Now
     BB-105FXESC15MDR             EKI-2525M-BE                         Available Now
    Reason for the Change
    Important Date          Description                                                                          Date
    Announcement            Announcement of this document                                                        2020/4/16
    Phase-out               The product is officially phased out.                                                2020/4/16
    """

    rows = parse_advantech_ntron_pdf_rows_from_text(text, "advantech.pdf")

    assert len(rows) == 2
    assert rows[0]["Model"] == "BB-102MC-SC-MDR"
    assert rows[0]["Replacement Products"] == "IMC-350I-M8-A"
    assert rows[0]["Announcement"] == "2020-04-16"
    assert rows[0]["Product Status"] == "End of Life / phase-out notice"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "advantech_phase_out_not_security_eol"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]


def test_pilz_pnozmulti_generation_change_imports_review_rows():
    text = """
    PNOZmulti generation change
    PNOZmulti Classic and PNOZmulti Mini - phasing out, discontinuation
    Last Order: 30.09.2024
    Last Delivery: 31.12.2024
    PNOZmulti Classic System
    Item number: 773100 - 773830 + clamps
    Designation: PNOZmulti Classic incl. expansions and fieldbus modules
    PNOZ m1p
    (773100, 773103)
    PNOZ m1p ETH (773104)
    PNOZmulti Mini
    Item number: 772000 - 772036
    Designation: PNOZmulti Mini incl. extensions
    PNOZ mm0p
    (772000)
    PNOZ mm0p-T
    (772010)
    """

    rows = parse_pilz_pnozmulti_pdf_rows_from_text(text, "pilz.pdf")

    assert [row["Model"] for row in rows] == [
        "PNOZmulti Classic",
        "PNOZmulti Mini",
        "PNOZ m1p",
        "PNOZ mm0p",
        "PNOZ mm0p-T",
    ]
    assert rows[0]["End of Sale"] == "2024-09-30"
    assert rows[0]["Product Status"] == "Phasing out and discontinuation"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "pilz_last_order_not_security_eol"
    assert "End of Support" not in rows[0]
    assert "773104" in rows[2]["_aliases"]


def test_broadcom_brocade_pdf_imports_part_rows_with_support_end():
    text = """
    Product EOL Notice
    Brocade G620 Switch
    End-of-Life (EOL) Notification Date                                                    July 26, 2024
    Last Time Order (LTO) Final, Non-Cancelable, Non-Returnable Order Due Date             November 26, 2024
    Last Customer Ship (LCS) Date                                                          January 31, 2025
    Brocade Fabric OS (FOS) End-of-Availability (EOA) Date                                 January 31, 2027
    End-of-Support (EOS) Date                                                              January 31, 2030
    Brocade Part Number                   Description                                             Replacement Part Numbers
    BR-G620-24-32G-F-1                    G620, 24P, 32GB SWLSFP, BR, AC, NON-PORTEXH             BR-G720-24-32G-F
    XBR-G620-24-F-1                       FRU, G620, 24P, BR, AC, NON-PORT SIDE EXHAUST           XBR-G720-24-F
    Revision History
    """

    rows = parse_broadcom_brocade_pdf_rows_from_text(text, "g620.pdf")

    assert [row["Part Number"] for row in rows] == [
        "BR-G620-24-32G-F-1",
        "XBR-G620-24-F-1",
    ]
    assert rows[0]["Announcement Date"] == "2024-07-26"
    assert rows[0]["End of Sale"] == "2024-11-26"
    assert rows[0]["Last Sale"] == "2025-01-31"
    assert rows[0]["End of Support"] == "2030-01-31"
    assert "End of Vulnerability Support" not in rows[0]
    assert rows[1]["Description"].startswith("Fibre Channel switch FRU;")


def test_broadcom_bluecoat_packetshaper_imports_stabilization_eol(tmp_path):
    html = """
    <html>
      <body>
        <h2>Updated PacketShaper product Stabilization and End of Life announcement</h2>
        <p>Broadcom is moving PacketShaper into Stabilization status and
        announcing new End of life date to allow support renewals for existing
        packet shaper customers.</p>
        <p>New date for end of life for PC-S200, PS-S200, PS-S400, PS-S500
        Models is : 31-OCT-2026</p>
        <p>New date for Last Date to Purchase the Maintenance Date is :
        31-OCT-2025</p>
      </body>
    </html>
    """
    path = tmp_path / "packetshaper-stabilization-and-eol-announcement.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_broadcom_bluecoat_packetshaper_rows(path)

    assert [row["Model"] for row in rows] == [
        "PC-S200",
        "PS-S200",
        "PS-S400",
        "PS-S500",
    ]
    assert {row["End of Support"] for row in rows} == {"2026-10-31"}
    assert {row["End of Life"] for row in rows} == {"2026-10-31"}
    assert {row["Last Maintenance Purchase"] for row in rows} == {"2025-10-31"}
    assert rows[0]["Product Status"] == "Stabilization; End of Life date announced"
    assert "Broadcom PacketShaper PC-S200" in rows[0]["_aliases"]


def test_hirschmann_belden_pdn_imports_mach102_service_dates():
    text = """
    Product Discontinuation Announcement - MACH102 Product Family
    This letter serves as your formal notification that Belden will discontinue
    the MACH102 product family, which is part of Hirschmann's Classic Software
    platform.

    Discontinued Products
    Last Order Date: December 31, 2023
    Discontinued products Description Suggested Alternative Description
    943969001                         MACH102-8TP
    943969101                         MACH102-8TP-R
    943969201                         MACH102-8TP-F
    943969301                         MACH102-8TP-FR
    943969401                         MACH102-24TP-F
    943969501                         MACH102-24TP-FR
    942298xxx                         GRS103

    Discontinuation Milestones:
    Milestones Date
    Discontinuation Announcement Date Jan 1st, 2023
    Last Order Date Dec 31st, 2023
    Last Delivery Date June 30th, 2024
    Last Service Date June 30th, 2029
    """

    rows = parse_hirschmann_belden_pdn_rows_from_text(text, "pdn-mach102.pdf")

    assert [row["Part Number"] for row in rows] == [
        "943969001",
        "943969101",
        "943969201",
        "943969301",
        "943969401",
        "943969501",
    ]
    assert rows[0]["Model"] == "MACH102-8TP"
    assert rows[0]["Announcement Date"] == "2023-01-01"
    assert rows[0]["End of Sale"] == "2023-12-31"
    assert rows[0]["End of Support"] == "2029-06-30"
    assert rows[0]["Replacement Products"] == "GRS103 family (942298xxx)"
    assert "last delivery date 2024-06-30" in rows[0]["Description"]
    assert rows[0]["_source_hint"] == (
        "Belden Hirschmann MACH102 product discontinuation notice import"
    )


def test_nvidia_mellanox_switchx_pdf_imports_support_end_dates():
    text = """
    Mellanox EOL Notification Procedure #: MLNX-15-4122
    EOL Title: EOL Notification for SwitchX integrated circuit devices
    Notice Date: August 07, 2014
    New Notice Date: September 19, 2014
    Effective immediately, Mellanox is announcing the manufacture discontinue
    and End of Life (EoL) of the following products:
    SwitchX InfiniBand, Ethernet and VPI integrated circuit devices

    Table 1: End of Life Milestones
    Last Time Buy (LTB)* Date The last date to order the product through a
    Mellanox point-of-sale mechanism. The product is no longer for sale after
    this date. March 28, 2015
    Last Ship Date The last possible ship date that can be requested of
    Mellanox and/or its distributors. June 30, 2015
    End of Service (EoS)** Contract Renewal Date The last date to extend or
    renew a service contract for the product. March 28, 2016

    Table 2: EoL'd Product OPNs and Replacement Product OPNs
    MT51224A1-FCCR-FE        MT51224A2-FCCR-FE
    MT51164A1-FCCR-X         MT51164A2-FCCR-X
    """

    rows = parse_nvidia_mellanox_pdf_rows_from_text(text, "switchx.pdf")

    assert [row["Part Number"] for row in rows] == [
        "MT51224A1-FCCR-FE",
        "MT51164A1-FCCR-X",
    ]
    assert rows[0]["Announcement Date"] == "2014-09-19"
    assert rows[0]["End of Sale"] == "2015-03-28"
    assert rows[0]["Last Sale"] == "2015-06-30"
    assert rows[0]["End of Support"] == "2016-03-28"
    assert rows[0]["Replacement Products"] == "MT51224A2-FCCR-FE"
    assert rows[0]["Product Status"] == (
        "End of Life; End of Service contract renewal date published"
    )


def test_nvidia_mellanox_switchx2_gateway_pdf_imports_status_only_eol():
    text = """
    END OF LIFE NOTIFICATION PROCEDURE
    EOL Notification Procedure # LCR-000844
    EOL Title EOL Notice for Mellanox SwitchX-2 InfiniBand to Ethernet Gateway
    Notice Date September 29, 2021
    Effective immediately, NVIDIA Networking is announcing the manufacture
    discontinue and End of Life (EoL) of the products listed in Table 1.

    Table 1: EoL'd Product Ordering Part Numbers (OPNs) and Replacement Product OPNs
    MSX6710G-FS2F2      Mellanox SwitchX-2       fw-SX-rel-9_4_5070   3.6.8010---2018-08   MGA100-HS2
    MSX6710G-FS2R2      Mellanox SwitchX-2       fw-SX-rel-9_4_5070   3.6.8010---2018-08   MGA100-HS2

    Table 2: End of Life Milestones
    Last Time Buy (LTB)* Date The last date to order the product through an
    NVIDIA point-of-sale mechanism. The product is no longer for sale after
    this date. March 31, 2022
    Last Ship Date The last possible ship date that can be requested of
    NVIDIA and/or its distributors. September 30, 2022
    """

    rows = parse_nvidia_mellanox_pdf_rows_from_text(text, "lcr-000844.pdf")

    assert [row["Part Number"] for row in rows] == [
        "MSX6710G-FS2F2",
        "MSX6710G-FS2R2",
    ]
    assert rows[0]["Announcement Date"] == "2021-09-29"
    assert rows[0]["End of Sale"] == "2022-03-31"
    assert rows[0]["Last Sale"] == "2022-09-30"
    assert rows[0]["Replacement Products"] == "MGA100-HS2"
    assert "last supported firmware fw-SX-rel-9_4_5070" in rows[0]["Description"]
    assert rows[0]["Product Status"] == (
        "End of Life notice; last supported firmware/software versions listed"
    )


def test_hikvision_discontinuation_pdf_imports_review_row():
    text = """
    Product Discontinuation Notification
    Product:              DS-3D2216P Network Switch
                          Date: February 8, 2016
    Effective Date: Immediately
    The products listed below are at end-of life.
    Hikvision will continue to support qualified product under currently published warranty policies.
    Discontinued                                                      MSRP Replacement
    Model             Description                                   (Jan. 18) Product
    DS-3D2216P        Switch, Ethernet, 16-Port 10/100M, 2-Port      $1,044 DS-3D2228P           Switch, Ethernet, 24-Port 10/100M      $1,250
    """

    rows = parse_hikvision_discontinuation_pdf_rows_from_text(text, "hikvision.pdf")

    assert rows == [
        {
            "Model": "DS-3D2216P",
            "Part Number": "DS-3D2216P",
            "Product Name": "Hikvision DS-3D2216P Network Switch",
            "Description": "Ethernet PoE network switch; Switch, Ethernet, 16-Port 10/100M, 2-Port",
            "Product Status": "End-of-life; discontinued; warranty support continues under policy",
            "Replacement Products": "DS-3D2228P / Switch, Ethernet, 24-Port 10/100M",
            "_source_table": "hikvision.pdf discontinued model table",
            "_source_hint": "Hikvision product discontinuation notification PDF import",
            "_status_only_review": True,
            "_review_policy": "hikvision_eol_warranty_support_no_exact_security_date",
            "_review_reason": (
                "Hikvision source says the product is end-of-life and discontinued, "
                "but it also says qualified products continue under warranty policy "
                "and does not provide an exact support or security-update end date."
            ),
            "_aliases": ["DS-3D2216P", "DS-3D2216P Network Switch"],
            "Announcement Date": "2016-02-08",
            "End of Sale": "2016-02-08",
        }
    ]


def test_helmholz_myrex24_pdf_imports_security_update_end_date():
    text = """
    Notification of discontinued product
    Discontinued product myREX24 V1 Date of notice 22.08.2024
    Due to the upcoming Cyber Resilience Act, we are unable to guarantee the
    availability and security of the myREX24 V1 portal any longer.
    Milestones Abbreviation Description Date
    Notification about product discontinuation EOL-NOT Defines the day on which the product discontinuation will be published 14.08.2024
    End of Service EOL-EOS Last day before server shutdown 31.03.2026
    Last order date EOL-ORD Last date on which licenses can be ordered 16.09.2024
    End of software support EOL-SWS* No software nor security updates will be offered anymore after this date 16.09.2024
    End of product support EOL-PS* The last date technical support is available 31.12.2024
    """

    rows = parse_helmholz_myrex24_pdf_rows_from_text(text, "myrex24.pdf")

    assert rows == [
        {
            "Model": "myREX24 V1 Portal",
            "Part Number": "myREX24 V1",
            "Product Name": "Helmholz myREX24 V1 Portal",
            "Description": (
                "Remote service portal; software and security updates ended "
                "2024-09-16; product support ended 2024-12-31; "
                "service shutdown 2026-03-31"
            ),
            "Product Status": (
                "Discontinued product; software and security updates ended; "
                "service shutdown scheduled"
            ),
            "End of Vulnerability Support": "2024-09-16",
            "_source_table": "myrex24.pdf myREX24 V1 lifecycle milestone table",
            "_source_hint": "Helmholz myREX24 V1 EOL document PDF import",
            "_aliases": [
                "myREX24 V1",
                "myREX24 V1 Portal",
                "myREX24 V1 Server",
                "myREX24.net",
                "web2go.myrex24.net",
                "vpn2.myREX24.net",
            ],
            "_prefer_model": True,
            "Announcement Date": "2024-08-14",
            "End of Sale": "2024-09-16",
            "End of Service": "2026-03-31",
        }
    ]
    assert "End of Support" not in rows[0]


def test_weidmueller_discontinued_datasheet_imports_review_row():
    text = """
    Data sheet
    IE-SR-2GT-LAN
    Weidmueller Industrial Security Routers
    General ordering data
    Version Security/NAT/VPN/u-link Router, Gigabit Ethernet, 2 * RJ45
    Order No. 1345270000
    Type IE-SR-2GT-LAN
    Delivery status Discontinued
    Available until 2022-10-31T00:00:00+01:00
    Alternative product IE-SR-4GT
    """

    rows = parse_weidmueller_datasheet_pdf_rows_from_text(text, "weidmueller.pdf")

    assert rows == [
        {
            "Model": "IE-SR-2GT-LAN",
            "Part Number": "1345270000",
            "Product Name": "Weidmueller IE-SR-2GT-LAN",
            "Description": "Industrial Ethernet security router",
            "Product Status": "Delivery status discontinued",
            "Replacement Products": "IE-SR-4GT",
            "_source_table": "weidmueller.pdf general ordering data",
            "_source_hint": "Weidmueller discontinued product datasheet PDF import",
            "_force_lifecycle_review": True,
            "_review_policy": "weidmueller_discontinued_available_until_not_security_eol",
            "_review_reason": (
                "Weidmueller datasheet marks this product discontinued and gives "
                "an availability end date, but it does not provide an exact support "
                "or security-update end date."
            ),
            "_aliases": ["IE-SR-2GT-LAN", "1345270000"],
            "_prefer_model": True,
            "End of Sale": "2022-10-31",
        }
    ]


def test_eltako_safe_iv_pdf_imports_discontinued_controllers_as_review():
    text = """
    PROFESSIONAL SMART HOME CONTROLLER SAFE IV
    Safe IV
    Safe IV-rw       Eltako Smart Home controller with software                    Discontinued on 30.09.2022 *
                     GFVS 4.0, pure white
    Safe IV-sz       Eltako Smart Home controller controller with                  Discontinued on 30.09.2022 *
                     software GFVS 4.0, black
    Alternative Smart Home controller:
    MiniSafe2
    MiniSafe2-REG
    WP2
    """

    rows = parse_eltako_safe_iv_pdf_rows_from_text(text, "safe-iv.pdf")

    assert [row["Model"] for row in rows] == ["Safe IV-rw", "Safe IV-sz"]
    assert rows[0]["Product Name"] == "Eltako Safe IV pure white"
    assert rows[1]["Product Name"] == "Eltako Safe IV black"
    assert rows[0]["End of Sale"] == "2022-09-30"
    assert rows[0]["Product Status"] == "Discontinued"
    assert rows[0]["Replacement Products"] == "MiniSafe2; MiniSafe2-REG; WP2"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "eltako_discontinued_not_security_eol"
    assert "End of Support" not in rows[0]


def test_siedle_discontinued_product_page_imports_variant_review_rows(tmp_path):
    html = """
    <html>
      <head>
        <title>Code lock module (discontinued) - COM 611-02 - Products - Siedle</title>
      </head>
      <body>
        <h2>Product information</h2>
        <div>Product designation</div>
        <div>Product description</div>
        <div>Colour/Material</div>
        <div>CG</div>
        <div>Article no.</div>
        <div>RSP (Germany, incl. VAT)</div>
        <div>COM 611-02 BG</div>
        <div>Code lock module (discontinued)</div>
        <div>Micaceous amber</div>
        <div>D</div>
        <div>200038884-00</div>
        <div>685,44 EUR</div>
        <div>COM 611-02 WH</div>
        <div>Code lock module (discontinued)</div>
        <div>High gloss white</div>
        <div>D</div>
        <div>200038882-00</div>
        <div>685,44 EUR</div>
        <div>Loading</div>
      </body>
    </html>
    """
    path = tmp_path / "com-611-02-code-lock-module-discontinued.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_siedle_discontinued_product_rows(path)

    assert [row["Model"] for row in rows] == ["COM 611-02 BG", "COM 611-02 WH"]
    assert rows[0]["Part Number"] == "200038884-00"
    assert rows[0]["Description"] == "Code lock module; color/material Micaceous amber"
    assert rows[0]["Product Status"] == "Discontinued"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "siedle_discontinued_product_page_not_security_eol"
    assert "End of Support" not in rows[0]


def test_balluff_product_lifecycle_page_imports_review_row(tmp_path):
    html = """
    <html>
      <head>
        <title>BNI00H3 (BNI IOW-560-W01-K022) IO-Link Wireless Hub und Bridge - BALLUFF USA</title>
      </head>
      <body>
        <div>Soon no longer available</div>
        <span>Available until:</span>
        <span>2027-03-01</span>
        <h1>BNI00H3</h1>
        <div>BNI IOW-560-W01-K022</div>
        <a>Datasheet</a>
        <h2>IO-Link Wireless Bridge</h2>
        <h3>Alternative products</h3>
        <div>Soon no longer available</div>
        <div>Recommended alternative</div>
        <div>BNI00H3</div>
        <div>BNI00KW</div>
        <div>BNI IOW-560-W01-K022</div>
        <div>BNI IOW-560-W01-K093</div>
      </body>
    </html>
    """
    path = tmp_path / "bni00h3-bni-iow-560-w01-k022.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_balluff_product_lifecycle_rows(path)

    assert rows == [
        {
            "Model": "BNI00H3",
            "Part Number": "BNI IOW-560-W01-K022",
            "Product Name": "Balluff BNI00H3",
            "Description": (
                "IO-Link Wireless Hub and Bridge; IO-Link Wireless Bridge"
            ),
            "Product Status": "Soon no longer available",
            "Replacement Products": "BNI00KW / BNI IOW-560-W01-K093",
            "_source_table": "bni00h3-bni-iow-560-w01-k022.html product lifecycle status",
            "_source_hint": "Balluff product lifecycle status page review import",
            "_status_only_review": True,
            "_force_lifecycle_review": True,
            "_review_policy": "balluff_available_until_not_security_eol",
            "_review_reason": (
                "Balluff product page shows a lifecycle status, but it does not "
                "provide an exact support or security-update end date."
            ),
            "_aliases": [
                "BNI00H3",
                "BNI IOW-560-W01-K022",
                "IO-Link Wireless Hub and Bridge",
                "IO-Link Wireless Bridge",
            ],
            "_prefer_model": True,
            "End of Sale": "2027-03-01",
        }
    ]


def test_beckhoff_service_products_imports_rowspan_review_rows(tmp_path):
    html = """
    <html>
      <head>
        <title>I/O service products | Beckhoff USA</title>
      </head>
      <body>
        <div class="accordion-item">
          <button class="accordion-button">EtherCAT Terminals</button>
          <table>
            <thead>
              <tr>
                <th>Product</th>
                <th>Short description</th>
                <th>Product status</th>
                <th>Discontinuation</th>
                <th>Successor product</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>EL3413</td>
                <td rowspan="2">3-channel analog input, power measurement</td>
                <td>Service phase</td>
                <td>2023-03-01</td>
                <td>EL3453</td>
              </tr>
              <tr>
                <td>EL3413-0010</td>
                <td>Service phase</td>
                <td>31.01.2023</td>
                <td>Contact our service</td>
              </tr>
            </tbody>
          </table>
        </div>
      </body>
    </html>
    """
    path = tmp_path / "io-service-products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_beckhoff_service_product_rows(path)

    assert rows[0]["Model"] == "EL3413"
    assert rows[0]["Description"] == (
        "EtherCAT Terminals; 3-channel analog input, power measurement"
    )
    assert rows[0]["Product Status"] == "Service phase"
    assert rows[0]["End of Sale"] == "2023-03-01"
    assert rows[0]["Replacement Products"] == "EL3453"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "beckhoff_service_phase_not_security_eol"
    assert rows[1]["Model"] == "EL3413-0010"
    assert rows[1]["End of Sale"] == "2023-01-31"
    assert "Replacement Products" not in rows[1]


def test_kyocera_taskalfa_sales_end_notice_imports_review_rows(tmp_path):
    html = """
    <html>
      <head>
        <title>Monochrome A2 MFP TASKalfa 4012w series sales-end notice</title>
      </head>
      <body>
        <h1>Monochrome A2 MFP TASKalfa 4012w series sales-end notice</h1>
        <p>2025年01月20日</p>
        <p>
          TASKalfa 4012w series will end sales when current inventory is
          exhausted.
        </p>
        <h2>販売終了製品</h2>
        <p>モノクロA2複合機 TASKalfa 4012w/4011w</p>
        <h2>備考</h2>
        <p>No successor products are planned.</p>
      </body>
    </html>
    """
    path = tmp_path / "taskalfa-4012w-sales-end-notice.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_kyocera_taskalfa_sales_end_rows(path)

    assert [row["Model"] for row in rows] == ["TASKalfa 4012w", "TASKalfa 4011w"]
    assert rows[0]["Product Status"] == "Sales ending when stock is exhausted"
    assert rows[0]["Announcement Date"] == "2025-01-20"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "kyocera_sales_end_notice_not_security_eol"
    assert "End of Sale" not in rows[0]


def test_lexmark_product_eosl_page_imports_status_only_unsupported_row(tmp_path):
    html = """
    <html>
      <head><title>Printer</title></head>
      <body>
        <div>Support</div>
        <div>Printers</div>
        <h1>Lexmark C792</h1>
        <p>Printer features: Laser, print only, color</p>
        <a>End of Service Life Bulletin</a>
        <p>
          This device has reached the end of its service life. Firmware Support,
          Maintenance Services (including call support and training services)
          and Parts Support have been discontinued.
        </p>
      </body>
    </html>
    """
    path = tmp_path / "lexmark-c792.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_lexmark_product_eosl_rows(path)

    assert rows == [
        {
            "Model": "C792",
            "Part Number": "C792",
            "Product Name": "Lexmark C792",
            "Description": "Printer; Laser, print only, color",
            "Product Status": (
                "End of Service Life; Firmware Support discontinued; "
                "Maintenance Services discontinued; Parts Support discontinued"
            ),
            "_source_table": "lexmark-c792.html end-of-service-life support page",
            "_source_hint": "Lexmark product support end-of-service-life page import",
            "_allow_status_only": True,
            "_review_policy": "lexmark_eosl_firmware_support_discontinued",
            "_review_reason": (
                "Lexmark states this device has reached end of service life "
                "and that firmware support, maintenance services, and parts "
                "support have been discontinued."
            ),
            "_aliases": ["C792", "Lexmark C792"],
            "_prefer_model": True,
        }
    ]


def test_synology_product_status_imports_firmware_eol_rows(tmp_path):
    payload = {
        "filters": {
            "status": {
                "options": {
                    "Published": "Generally Available",
                    "Phase Out": "Discontinued",
                }
            },
            "firmware_support": {
                "options": {
                    "full": "Full",
                    "limited": "Limited",
                    "suspended": "End of Life",
                }
            },
            "support": {"options": {"full": "Full", "limited": "Limited"}},
        },
        "product_types": {
            "DiskStation": {"title": "DiskStation Series"},
        },
        "product_items": {
            "DS214": {
                "category": "NAS",
                "type": "DiskStation",
                "name": "DS214",
                "firmware_support": "suspended",
                "status": "Phase Out",
                "support": "limited",
            },
            "DS923+": {
                "category": "NAS",
                "type": "DiskStation",
                "name": "DS923+",
                "firmware_support": "full",
                "status": "Published",
                "support": "full",
            },
        },
    }
    path = tmp_path / "product-support-status-all.html"
    path.write_text(
        f"<html><script>var ret = {json.dumps(payload)};</script></html>",
        encoding="utf-8",
    )

    rows = extract_synology_product_status_rows(path)

    assert rows == [
        {
            "Model": "DS214",
            "Part Number": "DS214",
            "Product Name": "Synology DS214",
            "Description": "NAS storage device; DiskStation Series",
            "Product Status": (
                "Product Availability Discontinued; OS/Firmware Update End of Life; "
                "future firmware, software, "
                "and security/vulnerability updates discontinued"
            ),
            "Technical Support Status": "Limited",
            "_source_table": "product-support-status-all.html product support status data",
            "_source_hint": "Synology product support status page import",
            "_source_url": "https://www.synology.com/en-global/products/status?status=all",
            "_allow_status_only": True,
            "_review_policy": "synology_firmware_update_end_of_life",
            "_review_reason": (
                "Synology defines OS/Firmware Update End of Life as future "
                "firmware, software, and security/vulnerability updates "
                "being discontinued."
            ),
            "_aliases": ["DS214", "Synology DS214"],
            "_prefer_model": True,
        }
    ]


def test_hp_designjet_eosl_json_imports_security_update_end_dates(tmp_path):
    metadata = {
        "data": {
            "title": "HP DesignJet Printer Series- EOSL Customer Newsletter",
            "documentId": "c08587777",
            "languageCode": "en",
        }
    }
    html = """
    <c_support_doc>
      <h1>HP DesignJet Printer Series- EOSL Customer Newsletter</h1>
      <div>Effective on the 30th of April 2023, HP will discontinue all
      services and support for:</div>
      <div>&bull; CQ890B HP DesignJet T520 24-in Printer</div>
      <div>Effective on the 30th of October 2023, the following SKUs will be
      discontinued as well as their associated services and support:</div>
      <div>&bull; T0B52B - HP DesignJet Z2600 24-in PostScript Printer for US Government</div>
      <div>Software support - HP will no longer provide any kind of support for
      drivers, printer firmware, or utilities related to the EOSL printers. This
      includes no support for new operating systems or eventual new
      vulnerabilities.</div>
    </c_support_doc>
    """
    metadata_path = tmp_path / "designjet-end-of-service-life-2023.metadata.json"
    path = tmp_path / "designjet-end-of-service-life-2023.content.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    path.write_text(json.dumps({"data": html}), encoding="utf-8")

    rows = extract_hp_designjet_eosl_json_rows(path)

    assert [row["Part Number"] for row in rows] == ["CQ890B", "T0B52B"]
    assert rows[0]["Model"] == "HP DesignJet T520 24-in Printer"
    assert rows[0]["End of Support"] == "2023-04-30"
    assert rows[0]["End of Vulnerability Support"] == "2023-04-30"
    assert rows[0]["_source_url"] == "https://support.hp.com/us-en/document/c08587777"
    assert rows[0]["_prefer_model"] is True
    assert rows[1]["End of Support"] == "2023-10-30"
    assert rows[1]["Product Status"] == (
        "End of Service Life; all services and support discontinued"
    )
    assert "T0B52B" in rows[1]["_aliases"]
    assert (
        "DesignJet Z2600 24-in PostScript Printer for US Government"
        in rows[1]["_aliases"]
    )


def test_zebra_discontinued_product_page_imports_region_support_dates(tmp_path):
    html = """
    <html>
      <body>
        <div class="eyebrow">Industrial Printers</div>
        <h1>ZT410 Industrial Printer Support</h1>
        <p><b>MODELS:</b> ZT410</p>
        <p>Zebra is no longer offering this product for sale. The product
        resources will no longer be updated but will remain accessible below
        for your use and convenience. Please note that Customer Support is not
        available after the Service and Support Discontinuation date.</p>
        <p>Product Discontinuation Date: <b>October 1, 2020</b></p>
        <p><b>EMEA, LATAM &amp; NA</b></p>
        <p>Service and Support Discontinuation Date:
        <b>September 1, 2025</b></p>
        <p><b>APAC</b></p>
        <p>Service and Support Discontinuation Date:
        <b>December 1, 2025</b></p>
        <p>Replacement: ZT411</p>
      </body>
    </html>
    """
    path = tmp_path / "zt410.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_zebra_discontinued_product_rows(path)

    assert [row["Region"] for row in rows] == [
        "EMEA, LATAM and North America",
        "APAC",
    ]
    assert [row["End of Support"] for row in rows] == [
        "2025-09-01",
        "2025-12-01",
    ]
    assert rows[0]["End of Vulnerability Support"] == "2025-09-01"
    assert rows[0]["End of Sale"] == "2020-10-01"
    assert rows[0]["Replacement Products"] == "ZT411"
    assert rows[0]["Description"] == "Industrial Printers; ZT410 Industrial Printer"
    assert rows[0]["_source_hint"] == "Zebra discontinued product support page import"


def test_zebra_discontinued_product_page_imports_model_scoped_dates(tmp_path):
    html = """
    <html>
      <body>
        <div class="eyebrow">General Purpose Hands-Free Barcode Scanners</div>
        <h1>DS9800 Series Scanner Support</h1>
        <p><b>MODELS:</b> DS9808, DS9808R</p>
        <p>Zebra is no longer offering this product for sale. The product
        resources will no longer be updated but will remain accessible below
        for your use and convenience. Please note that Customer Support is not
        available after the Service and Support Discontinuation date.</p>
        <p><b>For DS9808R only</b></p>
        <p>Last Sale Date: <b>January 30, 2020</b></p>
        <p>Service and Support Discontinuation Date:
        <b>March 28, 2025</b></p>
        <p><b>For DS9808 only</b></p>
        <p>Last Sale Date: <b>August 2, 2019</b></p>
        <p>Service and Support Discontinuation Date:
        <b>October 1, 2024</b></p>
        <p>Replacement: DS9908</p>
        <p>Replacement: DS9908r</p>
      </body>
    </html>
    """
    path = tmp_path / "ds9800-series.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_zebra_discontinued_product_rows(path)

    assert [row["Model"] for row in rows] == ["DS9808R", "DS9808"]
    assert [row["Last Sale Date"] for row in rows] == [
        "2020-01-30",
        "2019-08-02",
    ]
    assert [row["End of Support"] for row in rows] == [
        "2025-03-28",
        "2024-10-01",
    ]
    assert rows[0]["Replacement Products"] == "DS9908 / DS9908r"
    assert "DS9800 Series Scanner" in rows[0]["_aliases"]


def test_atx_digistream_pdf_imports_software_maintenance_end_dates():
    text = """
    End-of-Sale and End-of-Life Notification - (DigiStream Product Line)

    End-of-Life Milestones
    Milestone
    End-of-Life Announcement
    Date of communication announcing start of the end-of-life process
    Dec 9, 2016
    End-of-Sale
    Last day on which affected product SKUs can be purchased
    Mar 31, 2017
    End-of-Software Maintenance
    Last day beyond which FW updates with maintenance and/or bug fixes will no
    longer be released.
    Sep 30, 2017
    End-of-Support
    Last day beyond which technical support and warranty or non-warranty repair
    or replacement will no longer be offered.
    Mar 31, 2018

    End-of-Life Products
    ATX Part Number
    Description
    DSLQ20-00
    EPG + 2 Internal Streams with QAM Output
    DSI80-00
    8 Internal Streams with IP Output
    Table 2: End-of-Life Products
    """

    rows = parse_atx_digistream_pdf_rows_from_text(text, "digistream-eol.pdf")

    assert [row["Model"] for row in rows] == ["DSLQ20-00", "DSI80-00"]
    assert rows[0]["Announcement Date"] == "2016-12-09"
    assert rows[0]["End of Sale"] == "2017-03-31"
    assert rows[0]["End of Vulnerability Support"] == "2017-09-30"
    assert (
        "Technical support and warranty or non-warranty repair ended 2018-03-31"
        in rows[0]["Description"]
    )
    assert rows[0]["_source_hint"] == (
        "ATX DigiStream end-of-sale and end-of-life notice import"
    )


def test_softing_discontinued_product_support_table_is_split(tmp_path):
    html = """
    <table>
      <tr>
        <td>Product Name</td>
        <td>Order Nr.</td>
        <td>Successor Product</td>
        <td>Order Nr.</td>
        <td>Discontinuation<br>Product / Support</td>
      </tr>
      <tr>
        <td>FFusb Interface</td>
        <td>DUA-KK-020300</td>
        <td>mobiLink HART<br>linkPlus FF</td>
        <td>DBA-KM-020410<br>LAR-KK-021973</td>
        <td>01.08.2018 / 30.09.2019</td>
      </tr>
      <tr>
        <td>FBK-2/HW</td>
        <td>EAA-KS-020200<br>ECA-KS-020201</td>
        <td>commModule MBP</td>
        <td>EIA-KS-022220</td>
        <td>15.02.2023 / 31.12.2024</td>
      </tr>
    </table>
    """
    path = tmp_path / "discontinued-products.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "softing_industrial") if row.get("_source_hint")]

    assert rows[0]["Product Name"] == "FFusb Interface"
    assert rows[0]["Part Number"] == "DUA-KK-020300"
    assert rows[0]["End of Sale"] == "2018-08-01"
    assert rows[0]["End of Support"] == "2019-09-30"
    assert rows[0]["Product Status"] == "discontinued product/support schedule"
    assert [row["Part Number"] for row in rows[1:]] == [
        "EAA-KS-020200",
        "ECA-KS-020201",
    ]


def test_softing_combined_product_support_dates():
    assert parse_softing_product_support_dates("01.08.2018 / 30.09.2019") == (
        "2018-08-01",
        "2019-09-30",
    )


def test_amcrest_discontinued_firmware_rows_import_as_review_rows(tmp_path):
    html = """
    <h2 class="frmwr-h2">Discontinued Products</h2>
    <h3>
      ATTENTION! The following products are discontinued. These products will
      only receive security firmware updates.
    </h3>
    <h2 class="frmwr-h2">Amcrest IP WiFi Cameras</h2>
    <table>
      <tr>
        <th>Products</th>
        <th>Update Version/Build No.</th>
        <th>Attention</th>
      </tr>
      <tr>
        <td><span class="frmwr-badge">IPM-721</span></td>
        <td>V2.420</td>
        <td>For IPM-721B, IPM-721W and IPM-721S - DISCONTINUED</td>
      </tr>
      <tr>
        <td><span class="frmwr-badge">AMDV7204</span></td>
        <td>SV10003</td>
        <td>SV10003 - DISCONTINUED</td>
      </tr>
      <tr>
        <td><span class="frmwr-badge">AMDV960H4</span></td>
        <td>1611300 GA 3.1</td>
        <td>Only for 960H4+ - DISCONTINUED</td>
      </tr>
    </table>
    """
    path = tmp_path / "firmware.20260512_111100.2.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_amcrest_discontinued_firmware_rows(path)

    assert [row["Model"] for row in rows] == [
        "IPM-721B",
        "IPM-721W",
        "IPM-721S",
        "AMDV7204",
        "AMDV960H4",
    ]
    assert rows[0]["Product Status"] == "discontinued; security firmware updates only"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "amcrest_discontinued_security_firmware_only"
    assert "IPM-721" in rows[0]["_aliases"]
    assert "960H4+" in rows[-1]["_aliases"]
    assert "SV10003" not in [row["Model"] for row in rows]


def test_acti_discontinued_list_imports_status_only_review_rows(tmp_path):
    html = """
    <table>
      <tr><td>Box Camera<br>ACM-5001<br>D21F</td></tr>
      <tr><td>Bullet Camera<br>ACM-1011<br>E42</td></tr>
    </table>
    """
    path = tmp_path / "discontinued-products.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "acti") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["ACM-5001", "D21F", "ACM-1011", "E42"]
    assert rows[0]["Description"] == "Box Camera"
    assert rows[0]["Product Status"] == "discontinued"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "discontinued_not_security_eol"


def test_arris_discontinued_products_import_as_review_rows(tmp_path):
    html = """
    <title>ARRIS Consumer Care - Discontinued</title>
    <h5>Discontinued Products</h5>
    <div class="prodContainer">
      <div class="boxTitle1"><h6>SBG6580 / SBG6580-2</h6></div>
    </div>
    <div class="prodContainer">
      <div class="boxTitle1"><h6>DCX3200-M</h6></div>
    </div>
    """
    path = tmp_path / "Discontinued-Products-test.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "arris_commscope_cpe") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["SBG6580 / SBG6580-2", "DCX3200-M"]
    assert rows[0]["Description"] == "Cable gateway discontinued product SBG6580 / SBG6580-2"
    assert rows[1]["Description"] == "Cable set-top box discontinued product DCX3200-M"
    assert rows[0]["Product Status"] == "discontinued"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "arris_discontinued_not_security_eol"
    assert "SBG6580-2" in rows[0]["_aliases"]
    assert "SURFboard SBG6580-2" in rows[0]["_aliases"]


def test_arris_vendor_short_names_are_registered_as_aliases(tmp_path):
    raw_root = tmp_path / "RawData"
    vendor_dir = raw_root / "arris_commscope_cpe"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "source_manifest.json").write_text(
        json.dumps(
            {
                "vendor": "arris_commscope_cpe",
                "display_name": "ARRIS / Motorola / CommScope CPE",
            }
        ),
        encoding="utf-8",
    )

    class FakeBuilder:
        VENDOR_NAMES = {}
        VENDOR_ALIASES = {}

        @staticmethod
        def normalize_lookup_key(value):
            return str(value).lower().replace("/", " ").strip()

    update_vendor_metadata(FakeBuilder, raw_root)

    for alias in ("arris", "motorola", "commscope", "surfboard"):
        assert FakeBuilder.VENDOR_ALIASES[alias] == "arris_commscope_cpe"


def test_insys_discontinued_categories_import_as_review_rows(tmp_path):
    state = {
        "3205145092": {
            "b": {
                "result": {
                    "canonicalUrl": "https://docs.insys-icom.com/docs/discontinued-products-en",
                    "categories": {
                        "children": [
                            {
                                "slug": "productinformation",
                                "title": "Product Information",
                                "children": [
                                    {
                                        "slug": "discontinued-products-en",
                                        "title": "Discontinued Products",
                                        "children": [
                                            {"slug": "mro-info-en", "title": "MRO"},
                                            {
                                                "slug": "etsm-and-etsu-info-en",
                                                "title": "ETSM and ETSU",
                                            },
                                            {"slug": "modems-en-info-en", "title": "Modems"},
                                            {
                                                "slug": "e-mobility-sgm-pilot-box-info-en",
                                                "title": "e-mobility SGM Pilot Box",
                                            },
                                        ],
                                    }
                                ],
                            }
                        ]
                    },
                }
            }
        }
    }
    html = (
        "<title>Discontinued Products</title>"
        f"<script id=\"serverApp-state\" type=\"application/json\">{json.dumps(state)}</script>"
    )
    path = tmp_path / "discontinued-products.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "insys_icom") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == [
        "INSYS MRO",
        "ETSM and ETSU",
        "e-mobility SGM Pilot Box",
    ]
    assert rows[0]["Description"] == "Industrial communication device discontinued product family MRO"
    assert rows[0]["Product Status"] == "discontinued"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "insys_discontinued_category_not_security_eol"
    assert rows[0]["_source_url"] == "https://docs.insys-icom.com/docs/discontinued-products-en"
    assert "MRO" not in rows[0]["_aliases"]
    assert "INSYS ETSM" in rows[1]["_aliases"]
    assert "INSYS icom ETSU" in rows[1]["_aliases"]


def test_insys_short_vendor_name_is_registered_as_alias(tmp_path):
    raw_root = tmp_path / "RawData"
    vendor_dir = raw_root / "insys_icom"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "source_manifest.json").write_text(
        json.dumps(
            {
                "vendor": "insys_icom",
                "display_name": "INSYS icom",
            }
        ),
        encoding="utf-8",
    )

    class FakeBuilder:
        VENDOR_NAMES = {}
        VENDOR_ALIASES = {}

        @staticmethod
        def normalize_lookup_key(value):
            return str(value).lower().replace("/", " ").strip()

    update_vendor_metadata(FakeBuilder, raw_root)

    assert FakeBuilder.VENDOR_ALIASES["insys"] == "insys_icom"
    assert FakeBuilder.VENDOR_ALIASES["insys icom"] == "insys_icom"


def test_hanwha_discontinued_articles_import_exact_models_only(tmp_path):
    section = [
        {
            "articles": [
                {
                    "url": "/hc/en-001/articles/1-Discontinued-Recorder",
                    "title": (
                        "Discontinued: Network Recorder - RAID FAQs "
                        "SRN-1000 & SRN-4000 (Discontinued Models)"
                    ),
                    "snippet": "FAQ article for the discontinued recorder models.",
                },
                {
                    "url": "/hc/en-001/articles/2-Discontinued-Smartcam",
                    "title": "Discontinued: Why am I unable to view playback video?",
                    "snippet": (
                        "Applies to Models: SNH-V6435DN, SNH-P6415BN "
                        "Summary playback troubleshooting."
                    ),
                },
                {
                    "url": "/hc/en-001/articles/3-Discontinued-All",
                    "title": "Discontinued: What resolution does smartcam support?",
                    "snippet": "Applies to Models: All Smartcam Models",
                },
            ]
        }
    ]
    html = f"<script>const nestedSection = {json.dumps(section)}[0]</script>"
    path = tmp_path / "discontinued-products-section.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_hanwha_discontinued_product_rows(path)

    assert [row["Model"] for row in rows] == [
        "SRN-1000",
        "SRN-4000",
        "SNH-P6415BN",
        "SNH-V6435DN",
    ]
    assert rows[0]["Description"] == "Video surveillance recorder discontinued product SRN-1000"
    assert rows[2]["Description"] == "SmartCam network camera discontinued product SNH-P6415BN"
    assert rows[0]["Product Status"] == "discontinued"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "hanwha_discontinued_article_not_security_eol"
    assert rows[0]["_source_url"].startswith("https://support.hanwhavision.com/")
    assert "Samsung Techwin SRN-1000" in rows[0]["_aliases"]
    assert all(row["Model"] != "All Smartcam Models" for row in rows)


def test_hanwha_vendor_lineage_names_are_registered_as_aliases(tmp_path):
    raw_root = tmp_path / "RawData"
    vendor_dir = raw_root / "hanwha"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "source_manifest.json").write_text(
        json.dumps(
            {
                "vendor": "hanwha",
                "display_name": "Hanwha Vision",
            }
        ),
        encoding="utf-8",
    )

    class FakeBuilder:
        VENDOR_NAMES = {}
        VENDOR_ALIASES = {}

        @staticmethod
        def normalize_lookup_key(value):
            return str(value).lower().replace("/", " ").strip()

    update_vendor_metadata(FakeBuilder, raw_root)

    for alias in (
        "hanwha",
        "hanwha vision",
        "samsung techwin",
        "samsung smartcam",
        "wisenet",
    ):
        assert FakeBuilder.VENDOR_ALIASES[alias] == "hanwha"


def test_edgeconnect_vendor_lineage_names_are_registered_as_aliases(tmp_path):
    raw_root = tmp_path / "RawData"
    vendor_dir = raw_root / "silver_peak_aruba_edgeconnect"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "source_manifest.json").write_text(
        json.dumps(
            {
                "vendor": "silver_peak_aruba_edgeconnect",
                "display_name": "Silver Peak / HPE Aruba EdgeConnect",
            }
        ),
        encoding="utf-8",
    )

    class FakeBuilder:
        VENDOR_NAMES = {}
        VENDOR_ALIASES = {}

        @staticmethod
        def normalize_lookup_key(value):
            return str(value).lower().replace("/", " ").strip()

    update_vendor_metadata(FakeBuilder, raw_root)

    for alias in (
        "silver peak",
        "aruba edgeconnect",
        "hpe aruba edgeconnect",
        "hpe aruba networking edgeconnect",
        "edgeconnect",
    ):
        assert FakeBuilder.VENDOR_ALIASES[alias] == "silver_peak_aruba_edgeconnect"


def test_red_lion_ntron_eol_replacement_list_imports_status_only_review_rows(tmp_path):
    html = """
    <table>
      <tr><th>Product Number</th><th>Unmanaged</th><th>Managed</th></tr>
      <tr><td>110FX2-SC</td><td>NT-110-FX2-SC00</td><td></td></tr>
      <tr><td>105TX</td><td></td><td>NT-105TX</td></tr>
    </table>
    """
    path = tmp_path / "red-lion-ntron-eol-replacements.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "red_lion_ntron") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["110FX2-SC", "105TX"]
    assert rows[0]["Replacement Products"] == "NT-110-FX2-SC00"
    assert rows[1]["Replacement Products"] == "NT-105TX"
    assert rows[0]["Product Status"] == "end-of-life replacement list"
    assert rows[0]["_status_only_review"] is True


def test_qnap_support_status_table_imports_security_update_date(tmp_path):
    html = """
    <table>
      <tr>
        <th>Model</th>
        <th>Product Availability</th>
        <th>Hardware Repair or Replacement</th>
        <th>OS and Application Updates and Maintenance</th>
        <th>Technical Support and Security Updates</th>
        <th>Successor model</th>
      </tr>
      <tr>
        <td>TS-259 Pro+</td>
        <td>EOL</td>
        <td>Discontinued</td>
        <td>2017-12 (QTS 4.2)</td>
        <td>2022-10</td>
        <td>TS-264</td>
      </tr>
    </table>
    """
    path = tmp_path / "product-support-status-filtered-nas.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "qnap") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "TS-259 Pro+",
            "Product Name": "TS-259 Pro+",
            "Description": "NAS Storage",
            "Product Status": "EOL",
            "End of Support": "2022-10-31",
            "End of Vulnerability Support": "2017-12-31",
            "Replacement Products": "TS-264",
            "_source_table": "product-support-status-filtered-nas.html support status table 1",
            "_source_hint": "QNAP product support status table import",
        }
    ]


def test_versa_eol_table_imports_software_release_dates(tmp_path):
    html = """
    <h2>Windows SASE Client</h2>
    <table>
      <tr><th>Release</th><th>End of Support (EOS)</th></tr>
      <tr><td>7.8.x</td><td>Jan 30, 2025</td></tr>
    </table>
    <h2>Concerto</h2>
    <table>
      <tr><th>Release</th><th>End of Life (EOL)</th><th>End of Support (EOS)</th></tr>
      <tr><td>11.3.x</td><td>November 30, 2024</td><td>November 30, 2025</td></tr>
    </table>
    """
    path = tmp_path / "eol-eos.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "versa") if row.get("_source_hint")]

    assert rows[0]["Model"] == "Windows SASE Client 7.8.x"
    assert rows[0]["End of Support"] == "2025-01-30"
    assert rows[0]["Description"] == "Software - Windows SASE Client"
    assert rows[1]["Model"] == "Concerto 11.3.x"
    assert rows[1]["End of Life"] == "2024-11-30"
    assert rows[1]["End of Support"] == "2025-11-30"


def test_wd_my_cloud_os3_imports_security_update_end_date(tmp_path):
    html = """
    <p>On April 15, 2022, support for prior generations of My Cloud OS,
    including My Cloud OS 3, ended.</p>
    <p>After April 15, 2022, your device will no longer receive remote
    access, security updates, or technical support.</p>
    <table>
      <tr><th>Model</th><th>Firmware Version</th><th>Release Date</th></tr>
      <tr><td>My Cloud EX2100 & EX4100</td><td>2.42.115</td><td>1/18/2022</td></tr>
    </table>
    """
    path = tmp_path / "my-cloud-os3-end-of-support-and-service.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "wd_my_cloud") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["My Cloud EX2100", "My Cloud EX4100"]
    assert rows[0]["End of Support"] == "2022-04-15"
    assert rows[0]["End of Vulnerability Support"] == "2022-04-15"
    assert rows[0]["Product Status"] == "support ended; security updates ended"


def test_wd_lifecycle_policy_table_imports_status_only_review(tmp_path):
    html = """
    <table>
      <tr><td>Networking</td></tr>
      <tr><td>Product</td><td>Name</td><td>Last Manufactured Date</td><td>Support Status</td></tr>
      <tr><td></td><td>My Net N900</td><td>2016 or earlier</td><td>End of Updates End of Support</td></tr>
    </table>
    """
    path = tmp_path / "western-digital-product-lifecycle-support-policy.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "wd_my_cloud") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "My Net N900",
            "Product Name": "My Net N900",
            "Description": "Networking; last manufactured 2016 or earlier",
            "Product Status": "End of Updates End of Support",
            "_source_table": "western-digital-product-lifecycle-support-policy.html lifecycle policy table 1",
            "_source_hint": "WD product lifecycle support policy table review import",
            "_status_only_review": True,
            "_review_policy": "status_only_support_updates_no_exact_date",
            "_review_reason": (
                "Source status says updates/support have ended, but no exact "
                "support or security-update end date is present in this row."
            ),
            "Device Type": "Network Device",
        }
    ]


def test_reolink_discontinuation_notice_imports_eol_date_as_review(tmp_path):
    html = """
    <p>Discontinuation Notice for Certain Models</p>
    <p>C1 Pro (EOL: April 3, 2020), suggested replacement: E1 Pro;</p>
    <p>We will maintain our commitment to after-sales service and technical support.</p>
    """
    path = tmp_path / "product-eol.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "reolink") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "C1 Pro",
            "Product Name": "C1 Pro",
            "Description": "IP Camera",
            "EoL Date": "2020-04-03",
            "Replacement Products": "E1 Pro",
            "Product Status": "end-of-life",
            "_source_table": "product-eol.html discontinuation list",
            "_source_hint": "Reolink discontinuation notice review import",
            "_force_lifecycle_review": True,
            "_review_policy": "discontinued_not_security_eol",
        }
    ]


def test_vivotek_eol_list_imports_products_but_skips_group_headers_and_accessories(tmp_path):
    html = """
    <table>
      <tr><td>End-of-life Product List</td><td>End-of-life Product List</td></tr>
      <tr><td>Network Camera</td><td>Network Camera</td></tr>
      <tr><td>Dome</td><td>FD8134V, FD8135H</td></tr>
      <tr><td>Networking</td><td>Networking</td></tr>
      <tr><td>Commercial Network Switch</td><td>AW-FET-053C-120</td></tr>
      <tr><td>Accessories</td><td>Accessories</td></tr>
      <tr><td>Cable</td><td>AO-001</td></tr>
    </table>
    """
    path = tmp_path / "end-of-life-product-list.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "vivotek") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == [
        "FD8134V",
        "FD8135H",
        "AW-FET-053C-120",
    ]
    assert rows[0]["Description"] == "Dome IP Camera"
    assert rows[2]["Description"] == "Network Switch"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "status_only_not_security_eol"


def test_ipro_panasonic_discontinued_firmware_imports_model_headers_as_review(tmp_path):
    html = """
    <h1>Panasonic i-PRO discontinued firmware</h1>
    <h2>WV-X6533LNJ / WV-S6532LNJ / WV-X6533LNSJ / WV-S6532LNSJ</h2>
    <h2>WV-SMR10</h2>
    """
    path = tmp_path / "panasonic-ipro-eol-firmware-ptz.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "ipro_panasonic") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == [
        "WV-X6533LNJ",
        "WV-S6532LNJ",
        "WV-X6533LNSJ",
        "WV-S6532LNSJ",
        "WV-SMR10",
    ]
    assert rows[0]["Description"] == "PTZ security camera"
    assert rows[0]["Product Status"] == "Production discontinued product firmware page"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "production_discontinued_no_exact_support_date"


def test_seagate_lacie_nas_os4_imports_security_update_end_from_sibling_page(tmp_path):
    (tmp_path / "seagate-nas-os-4.html").write_text(
        """
        <p>NAS OS 4 will be officially End-of-Life effective July 18th, 2022.</p>
        <p>NAS OS will no longer be receiving any updates, including security updates.</p>
        """,
        encoding="utf-8",
    )
    html = """
    <h1>Seagate &amp; LaCie NAS OS 4 End of Life</h1>
    <p>The Seagate and LaCie NAS OS 4 operating systems have reached the final steps of support.</p>
    <p>This article applies to the following devices:</p>
    <ul>
      <li>Personal Cloud</li>
      <li>LaCie 5big NAS Pro</li>
    </ul>
    <h4>What effects do these final steps have on NAS OS 4?</h4>
    <ul>
      <li>No more Security or Feature Updates</li>
    </ul>
    """
    path = tmp_path / "seagate-lacie-nas-os-4-end-of-life-de.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "seagate_lacie_nas") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["Personal Cloud", "LaCie 5big NAS Pro"]
    assert rows[0]["End of Support"] == "2022-07-18"
    assert rows[0]["End of Vulnerability Support"] == "2022-07-18"
    assert rows[0]["End of Service"] == "2022-07-18"
    assert rows[0]["Product Status"] == (
        "NAS OS 4 End of Life; security updates discontinued"
    )


def test_screenbeam_eol_headings_import_status_only_review(tmp_path):
    html = """
    <h1>End of Life Products</h1>
    <h2>ECB6200 - Bonded MoCA 2.0 Network Adapter Branded Actiontec</h2>
    <h2>WCB6200Q - 802.11ac Wireless Network Extender</h2>
    """
    path = tmp_path / "end-of-life-products.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "screenbeam_actiontec") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["ECB6200", "WCB6200Q"]
    assert rows[0]["Description"] == "Bonded MoCA 2.0 Network Adapter Branded Actiontec"
    assert rows[0]["Product Status"] == "end-of-life and end-of-support product"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "status_only_support_updates_no_exact_date"


def test_digi_product_model_table_imports_eol_status_review_rows(tmp_path):
    html = """
    <table>
      <tr><th>Part Number</th><th>Description</th></tr>
      <tr><td>IX20-00N4</td><td>End-of-life Digi IX20 - LTE Cat 4 North America</td></tr>
      <tr><td>IX20-00M1</td><td>Digi IX20 - LTE Cat M1 Global</td></tr>
    </table>
    """
    path = tmp_path / "product-models.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "digi") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "IX20-00N4",
            "Part Number": "IX20-00N4",
            "Product Name": "Digi IX20",
            "Description": "End-of-life Digi IX20 - LTE Cat 4 North America",
            "Product Status": "End-of-life",
            "_source_table": "product-models.html part number table 1",
            "_source_hint": "Digi product model end-of-life status table review import",
            "_status_only_review": True,
            "_review_policy": "status_only_not_security_eol",
            "_review_reason": (
                "Source marks the part number End-of-life, but does not provide "
                "an exact support or security-update end date."
            ),
        }
    ]


def test_edgecore_product_page_eol_date_is_lifecycle_review(tmp_path):
    html = """
    <h3>DCS208(AS5812-54X) Warranty Support Period: 3 year.</h3>
    <p>The product has completed the End of Life (EOL) process effective on January 1, 2026</p>
    """
    path = tmp_path / "dcs208-eol.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "edgecore") if row.get("_source_hint")]

    assert rows[0]["Model"] == "DCS208"
    assert rows[0]["Product Name"] == "DCS208 (AS5812-54X)"
    assert rows[0]["End of Life"] == "2026-01-01"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "eol_process_not_security_eol"


def test_edgecore_datacenter_notice_imports_eol_table_with_review(tmp_path):
    html = """
    <p>Effective January, 31 2021: The following products and parts have completed the End of Sales (EOS)
    process and are now End of Life (EOL).</p>
    <table>
      <tr><th>EOL Equipment</th><th>Replacement</th><th>Reason</th></tr>
      <tr><td>Wedge100S-32X</td><td>AS7726-32X, AS7712-32X</td><td>Replaced by later generation</td></tr>
    </table>
    """
    path = tmp_path / "datacenter-switch-eol-notice-2021.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "edgecore") if row.get("_source_hint")]

    assert rows[0]["Model"] == "Wedge100S-32X"
    assert rows[0]["Replacement Products"] == "AS7726-32X, AS7712-32X"
    assert rows[0]["End of Life"] == "2021-01-31"
    assert rows[0]["_force_lifecycle_review"] is True


def test_edgecore_wifi_eol_headings_import_only_product_headings(tmp_path):
    html = """
    <h1>EOL Product List</h1>
    <h2>Access Point</h2>
    <h3>Indoor AP</h3>
    <h4>SP-W2-AC1200</h4>
    <h4>ECW5410-L</h4>
    """
    path = tmp_path / "wifi-eol-product-list.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "edgecore") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["SP-W2-AC1200", "ECW5410-L"]
    assert rows[0]["Description"] == "Indoor AP"
    assert rows[0]["_status_only_review"] is True


def test_sophos_products_now_eol_imports_update_end_date(tmp_path):
    html = """
    <h2>Sophos Products Now End of Life</h2>
    <p>The following products have reached their end of life and are no longer supported.</p>
    <p>They will no longer receive updates.</p>
    <p>Customers who continue to use these products after July 20, 2023 may see updating errors.</p>
    <p>If you still use one of the products below, please refer to the migration section on this page.</p>
    <p>Sophos Web Appliance</p>
    <p>Sophos Email Appliance</p>
    <h2>Upgrade to the latest cybersecurity products</h2>
    """
    path = tmp_path / "product-lifecycle.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "sophos") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["Sophos Web Appliance", "Sophos Email Appliance"]
    assert rows[0]["End of Support"] == "2023-07-20"
    assert rows[0]["End of Vulnerability Support"] == "2023-07-20"
    assert rows[0]["Product Status"] == (
        "end of life; no longer supported; no longer receive updates"
    )


def test_axis_product_support_page_imports_os_security_update_end(tmp_path):
    html = """
    <p>Product support for</p>
    <p>AXIS M2026-LE Network Camera</p>
    <h2>Product end of support</h2>
    <p>We have replaced this product with:</p>
    <p>AXIS M2036-LE</p>
    <p>See the datasheet for specifications for this product.</p>
    <p>Hardware support and RMA service expired on 2022-11-30.</p>
    <p>AXIS OS support expired on 2025-12-31.</p>
    <p>When the AXIS OS support period has expired no further updates will be released.</p>
    """
    path = tmp_path / "axis-m2026-le-support.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "axis") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "AXIS M2026-LE",
            "Product Name": "AXIS M2026-LE Network Camera",
            "Description": "Network Camera",
            "Product Status": "Product end of support",
            "Replacement Products": "AXIS M2036-LE",
            "_source_table": "axis-m2026-le-support.html product end-of-support section",
            "_source_hint": "Axis product support end-of-support page import",
            "End of Service": "2022-11-30",
            "End of Support": "2025-12-31",
            "End of Vulnerability Support": "2025-12-31",
        }
    ]


def test_fiberhome_chinese_milestone_table_imports_translated_terms(tmp_path):
    html = """
    <table>
      <tr><td>\u5173\u952e\u91cc\u7a0b\u7891\u70b9</td><td>\u5b9a\u4e49</td></tr>
      <tr><td>\u505c\u6b62\u9500\u552e\u65e5\uff08EOM\uff09</td><td>\u505c\u6b62\u9500\u552e\u65e5\u671f\u3002</td></tr>
      <tr><td>\u505c\u6b62\u5168\u9762\u652f\u6301\u65e5(EOFS)</td><td>\u505c\u6b62\u8f6f\u4ef6\u652f\u6301\u548c\u8865\u4e01\u670d\u52a1\u3002</td></tr>
      <tr><td>\u505c\u6b62\u670d\u52a1\u65e5(E0S)</td><td>\u505c\u6b62\u4efb\u4f55\u4ea7\u54c1\u670d\u52a1\u548c\u652f\u6301\u3002</td></tr>
    </table>
    <table>
      <tr><td>\u4ea7\u54c1 \u578b\u53f7</td><td colspan="3">\u5173\u952e\u91cc\u7a0b\u7891\u8282\u70b9</td></tr>
      <tr><td>EOM</td><td>EOFS\uff08\u8ba1\u5212\uff09</td><td>EOS\uff08\u8ba1\u5212\uff09</td></tr>
      <tr><td>GPOE (2170985T1A)</td><td>25\u5e7412\u670831\u65e5</td><td>28\u5e7412\u670831\u65e5</td><td>30\u5e7412\u670831\u65e5</td></tr>
    </table>
    <table>
      <tr><td>\u9000\u51fa\u4ea7\u54c1\u578b\u53f7</td><td>\u66ff\u4ee3\u4ea7\u54c1</td></tr>
      <tr><td>GPOE (2170985T1A)</td><td>GPOE-2</td></tr>
    </table>
    """
    path = tmp_path / "olt-board-eom-eofs-eos-notice.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "fiberhome") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "GPOE",
            "Part Number": "2170985T1A",
            "Product Name": "GPOE (2170985T1A)",
            "Description": "FiberHome broadband access lifecycle schedule",
            "Product Status": "EOM/EOFS/EOS lifecycle schedule",
            "Replacement Products": "GPOE-2",
            "_source_table": "olt-board-eom-eofs-eos-notice.html FiberHome milestone table 2",
            "_source_hint": "FiberHome translated EOM/EOFS/EOS milestone schedule import",
            "_prefer_model": True,
            "End of Sale": "2025-12-31",
            "End of Support": "2028-12-31",
            "End of Vulnerability Support": "2028-12-31",
            "End of Service": "2030-12-31",
        }
    ]


def test_fiberhome_rowspan_style_rows_reuse_previous_milestone_dates(tmp_path):
    html = """
    <table>
      <tr><td>\u4ea7\u54c1\u578b\u53f7</td><td></td><td>\u5173\u952e\u91cc\u7a0b\u7891\u8282\u70b9</td><td></td></tr>
      <tr><td>EOM</td><td>EOFS</td><td>EOS</td></tr>
      <tr><td>BSR2800</td><td>2025 \u5e7412\u670830\u65e5</td><td>2025 \u5e7412\u670830\u65e5</td><td>2025 \u5e7412\u670830\u65e5</td></tr>
      <tr><td>BSR3800</td></tr>
    </table>
    """
    path = tmp_path / "eom-eop-eos.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "fiberhome") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["BSR2800", "BSR3800"]
    assert rows[1]["End of Sale"] == "2025-12-30"
    assert rows[1]["End of Support"] == "2025-12-30"
    assert rows[1]["End of Service"] == "2025-12-30"


def test_hms_ewon_product_page_imports_eol_as_review(tmp_path):
    html = """
    <h1>Ewon Flexy 103 (End of Life)</h1>
    <p>Item number FLEXY10300_00MA</p>
    <p>The Ewon Flexy 103 has been designed for simple and cost effective
    remote data collection application.</p>
    """
    path = tmp_path / "ewon-flexy-103-end-of-life.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "hms_ewon") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "Ewon Flexy 103",
            "Part Number": "FLEXY10300_00MA",
            "Product Name": "Ewon Flexy 103 (End of Life)",
            "Description": (
                "The Ewon Flexy 103 has been designed for simple and cost "
                "effective remote data collection application."
            ),
            "Product Status": "End of Life",
            "_source_table": "ewon-flexy-103-end-of-life.html product page",
            "_source_hint": "HMS Ewon product page end-of-life status review import",
            "_status_only_review": True,
            "_prefer_model": True,
            "_review_policy": "status_only_not_security_eol",
            "_review_reason": (
                "Source marks this product End of Life, but does not provide "
                "an exact support or security-update end date."
            ),
        }
    ]


def test_oring_phase_out_notice_imports_models_as_review(tmp_path):
    html = """
    <h1>Phase-out Model\uff1aIGMC-111GP,IMC-111PB</h1>
    <p>Product End of Life / Change Notification</p>
    <p>Details</p>
    <p>2022-05-04</p>
    """
    path = tmp_path / "phase-out-igmc-imc.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "oring") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["IGMC-111GP", "IMC-111PB"]
    assert rows[0]["Announcement Date"] == "2022-05-04"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "phase_out_notice_not_security_eol"


def test_phoenix_contact_sfn_article_imports_family_as_review(tmp_path):
    html = """
    <h1>The end of an era, the sun is setting on SFN.</h1>
    <p>The FL SWITCH SFN family came into the Phoenix Portfolio in 2011.</p>
    <p>The product family that is to replace the SFN is the FL SWITCH 1000 family.</p>
    <p>The FL SWITCH SFN is due to be discontinued in 2022 Q2.</p>
    """
    path = tmp_path / "fl-switch-sfn-discontinuation.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "phoenix_contact") if row.get("_source_hint")]

    assert rows[0]["Model"] == "FL SWITCH SFN"
    assert rows[0]["Replacement Products"] == "FL SWITCH 1000"
    assert rows[0]["_status_only_review"] is True


def test_cradlepoint_ibr1700_page_imports_last_support_date(tmp_path):
    html = """
    <h1>Cradlepoint IBR1700-600M Series Ruggedized Router Support Information for End of Life</h1>
    <p>The lifecycle milestones for this product include the following dates:</p>
    <p>End-of-Sale Announcement Date</p><p>: May 08, 2024</p>
    <p>End-of-Sale Date</p><p>: July 16, 2024</p>
    <p>Last Date of Support (End of Life)</p><p>: July 16, 2029</p>
    """
    path = tmp_path / "ibr1700-600m-end-of-life-general-information.html"
    path.write_text(html, encoding="utf-8")

    rows = [
        row
        for row in extract_rows(path, "cradlepoint_ericsson")
        if row.get("_source_hint")
    ]

    assert rows[0]["Model"] == "IBR1700-600M Series"
    assert rows[0]["Announcement Date"] == "2024-05-08"
    assert rows[0]["End of Sale"] == "2024-07-16"
    assert rows[0]["End of Support"] == "2029-07-16"
    assert rows[0]["End of Vulnerability Support"] == "2029-07-16"


def test_avigilon_h5a_fisheye_pdf_text_imports_support_date():
    text = """
    Notice of Product Discontinuation
    Date of Issue: Feb. 1, 2025
    Re: Product End of Life (EOL) - Avigilon Unity H5A Fisheye
    8.0C-H5A-FE-DO1        H5A Fisheye, 8MP, Outdoor        8.0C-H6A-FE-360-DO1
    12.0W-H5A-FE-DO1- IR   H5A Fisheye, 12MP, Outdoor, IR   12.0C-H6A-FE-360-DO1-IR
    Avigilon will continue to support the above-listed discontinued products until March 1, 2030
    """

    rows = parse_avigilon_pdf_rows_from_text(text, "h5a.pdf")

    assert [row["Model"] for row in rows] == [
        "8.0C-H5A-FE-DO1",
        "12.0W-H5A-FE-DO1-IR",
    ]
    assert rows[0]["Replacement Products"] == "8.0C-H6A-FE-360-DO1"
    assert rows[0]["Announcement Date"] == "2025-02-01"
    assert rows[0]["End of Support"] == "2030-03-01"


def test_baicells_nova233_html_imports_support_and_bug_fix_end(tmp_path):
    html = """
    <h1>Baicells Nova233 End of Life</h1>
    <p>This bulletin is to formally announce the End of Life for the following Baicells product(s):</p>
    <ul>
      <li>The Nova233 outdoor small cell and all of its predecessors or variations (Nova R9)</li>
      <li>Product End of Life: December 31, 2023</li>
    </ul>
    <p>The Nova233 product will continue to be supported through 2023.
    This includes remote support and bug fixes.</p>
    <p>Beginning January 1, 2024, support and bug fixes will not be available.</p>
    <p>The Baicells Nova436Q is the recommended replacement product for the Nova233.</p>
    """
    path = tmp_path / "nova233-end-of-life-announcement.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "baicells") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["Nova233", "Nova R9"]
    assert rows[0]["End of Life"] == "2023-12-31"
    assert rows[0]["End of Support"] == "2023-12-31"
    assert rows[0]["End of Vulnerability Support"] == "2023-12-31"
    assert rows[0]["Replacement Products"] == "Nova436Q"


def test_lorex_psti_policy_imports_security_update_end_dates(tmp_path):
    html = """
    <h1>PSTI Product End-of-Life Policy</h1>
    <p>Before the expiration of EOS date, Lorex will provide firmware updates
    (including security updates) and relevant service support.</p>
    <table>
      <tr>
        <td>Product Name</td>
        <td>Product Model</td>
        <td>Service &amp; Support End Date</td>
      </tr>
      <tr>
        <td>Network Camera</td>
        <td>U424AA-Z, U424AAG-E</td>
        <td>December 31, 2025</td>
      </tr>
      <tr>
        <td>Video Recorder</td>
        <td>N910A6-Z</td>
        <td>December 31, 2028</td>
      </tr>
    </table>
    """
    path = tmp_path / "product-use-policy.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "lorex") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["U424AA-Z", "U424AAG-E", "N910A6-Z"]
    assert rows[0]["Description"] == "Network Camera"
    assert rows[0]["End of Support"] == "2025-12-31"
    assert rows[0]["End of Vulnerability Support"] == "2025-12-31"
    assert rows[2]["End of Support"] == "2028-12-31"


def test_auerswald_product_page_imports_software_update_end_date(tmp_path):
    html = """
    <h1>COMfortel 3600 IP</h1>
    <p><strong>End-of-Support: Apr. 2025</strong><br>
    No further software updates guaranteed</p>
    <p><strong>End-of-Service: Apr. 2027</strong><br>
    No further technical advice available</p>
    <p><strong>End-of-Repair: Apr. 2027</strong><br>
    No further repair service available</p>
    """
    path = tmp_path / "comfortel-3600-ip.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "auerswald") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "COMfortel 3600 IP",
            "Part Number": "COMfortel 3600 IP",
            "Product Name": "COMfortel 3600 IP",
            "Description": "IP communications product",
            "Product Status": (
                "End-of-Support listed; no further software updates guaranteed"
            ),
            "End of Support": "2025-04-30",
            "End of Vulnerability Support": "2025-04-30",
            "End of Service": "2027-04-30",
            "End of Repair": "2027-04-30",
            "_source_table": "comfortel-3600-ip.html product lifecycle fields",
            "_source_hint": "Auerswald product page End-of-Support/End-of-Service lifecycle import",
            "_prefer_model": True,
        }
    ]


def test_asustor_support_status_imports_ended_updates_as_review(tmp_path):
    html = """
    <h1>Product Support Status</h1>
    <p>Software Support</p>
    <p>Ended: Device will not receive updates.</p>
    <table>
      <tbody>
        <tr>
          <th><b>AS7009RD / AS7009RDX</b></th>
          <th></th>
          <th>Discontinued</th>
          <th>Ended</th>
          <th>Limited</th>
          <th>3</th>
          <th>Download</th>
        </tr>
      </tbody>
    </table>
    """
    path = tmp_path / "product-support-status-ended.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "asustor_nas") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["AS7009RD", "AS7009RDX"]
    assert rows[0]["Product Status"] == (
        "Software support ended; device will not receive updates"
    )
    assert rows[0]["Product Availability"] == "Discontinued"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "asustor_software_support_ended_no_exact_date"


def test_terramaster_support_termination_imports_update_end_date(tmp_path):
    html = """
    <article>
      <p>The technical support and maintenance services for these products
      will end on December 31, 2019.</p>
      <p>The product models involved are: F2-NAS, F2-NAS 2, F4-NAS</p>
      <p>What does end of technical support and maintenance services mean?</p>
      <p>The applications and systems will no longer be updated.</p>
      <p>F2-NAS 2 can be replaced with F2-221</p>
      <p>F4-NAS can be replaced with F5-221</p>
    </article>
    """
    path = tmp_path / "technical-support-termination-f2-nas.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "terramaster") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["F2-NAS", "F2-NAS 2", "F4-NAS"]
    assert rows[0]["End of Support"] == "2019-12-31"
    assert rows[0]["End of Vulnerability Support"] == "2019-12-31"
    assert rows[1]["Replacement Products"] == "F2-221"
    assert rows[2]["Replacement Products"] == "F5-221"


def test_buffalo_terastation_family_eol_imports_status_only_review(tmp_path):
    html = """
    <title>Announcing That The TeraStation 7000 Family of NAS Devices Has Entered EOL</title>
    <h1>TeraStation 7000 Family Has Entered EOL</h1>
    """
    path = tmp_path / "terastation-7000-eol.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "buffalo_nas") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "TeraStation 7000 Series",
            "Part Number": "TeraStation 7000 Series",
            "Product Name": "TeraStation 7000 Series",
            "Description": "NAS storage family",
            "Product Status": "Entered EOL",
            "_source_table": "terastation-7000-eol.html end-of-life announcement",
            "_source_hint": "Buffalo Americas TeraStation 7000 EOL announcement review import",
            "_status_only_review": True,
            "_review_policy": "buffalo_family_eol_no_exact_support_date",
            "_review_reason": (
                "Buffalo announces that this NAS family entered EOL, but the "
                "captured source does not provide an exact support or "
                "security-update end date."
            ),
            "_prefer_model": True,
        }
    ]


def test_celona_pdf_text_imports_eost_as_support_and_security_patch_end():
    text = """
    End-of-Life (EoL) Announcement:
    AP21-48
    Date: July 15, 2025
    Product: Celona Outdoor 5G Access Point - AP21-48
    Recommended Replacement: AP25-48
    Key Milestones
    Milestone Date
    EoL Announcement August 1, 2025
    End-of-Sale (Last Order) September 30, 2025
    End of Support (EoST) September 30, 2030
    """

    rows = parse_celona_pdf_rows_from_text(text, "ap21.pdf")

    assert rows == [
        {
            "Model": "AP21-48",
            "Part Number": "AP21-48",
            "Product Name": "Celona Outdoor 5G Access Point - AP21-48",
            "Description": "Celona Outdoor 5G Access Point",
            "Product Status": "End-of-Life announcement; End of Support (EoST) listed",
            "End of Support": "2030-09-30",
            "End of Vulnerability Support": "2030-09-30",
            "Replacement Products": "AP25-48",
            "_source_table": "ap21.pdf product lifecycle announcement",
            "_source_hint": "Celona product lifecycle EoL announcement PDF import",
            "_prefer_model": True,
            "Announcement Date": "2025-08-01",
            "End of Sale": "2025-09-30",
        }
    ]


def test_alcatel_lucent_pdf_text_imports_end_of_sales_only():
    text = """
    The Alcatel-Lucent OmniSwitch 6850 and OmniSwitch
    6850E switch families entered End-of-Sales product life
    cycles effective May 1, 2012, and April 30, 2016
    respectively, due to customers adopting the next generation
    Stackable LAN OmniSwitch 6860 product family.
    """

    rows = parse_alcatel_lucent_pdf_rows_from_text(text, "6850.pdf")

    assert [row["Model"] for row in rows] == ["OmniSwitch 6850", "OmniSwitch 6850E"]
    assert rows[0]["End of Sale"] == "2012-05-01"
    assert rows[1]["End of Sale"] == "2016-04-30"
    assert "End of Support" not in rows[0]


def test_avaya_pdf_text_imports_software_eoms_as_security_update_end():
    text = """
    End of Sale Notice
    Notification Date: December 5, 2016
    Subject: End of Sale for non-PoE ERS 4800 (TAA) models
    Avaya will no longer be selling the Ethernet Routing Switch 4800 non-PoE TAA models.
    Discontinued Order Codes
    Order Code Description
    AL4800A78-E6GS ERS 4850GTS with 48 10/100/1000 ports.
    AL4800A79-E6GS ERS 4826GTS with 24 10/100/1000 ports.
    Schedule
    End of Sale Date (last day to order)*** June 12, 2017
    End of Manufacturer Support for SOFTWARE * June 12, 2018
    End of Manufacturer Support for HARDWARE * June 12, 2020
    Targeted End of Services Support (note 1) June 12, 2023
    Avaya Product Lifecycle Policy
    """

    rows = parse_avaya_pdf_rows_from_text(text, "ers-4800.html")

    assert [row["Part Number"] for row in rows] == ["AL4800A78-E6GS", "AL4800A79-E6GS"]
    assert rows[0]["Model"] == "ERS 4850GTS"
    assert rows[0]["Announcement Date"] == "2016-12-05"
    assert rows[0]["End of Sale"] == "2017-06-12"
    assert rows[0]["End of Vulnerability Support"] == "2018-06-12"
    assert rows[0]["End of Service"] == "2023-06-12"
    assert "_force_lifecycle_review" not in rows[0]


def test_avaya_pdf_text_preserves_plus_suffix_models():
    text = """
    End of Sale Notice
    Notification Date: July 1, 2014
    Discontinued Order Codes
    Order Code Description
    AL4500A22-E6GS
    ERS 4550T-PWR+ with 48 10/100 802.3at PoE+ ports.
    Schedule
    End of Sale Date (last day to order)*** December 7, 2014
    End of Manufacturer Support for SOFTWARE * May 4, 2016
    Avaya Product Lifecycle Policy
    """

    rows = parse_avaya_pdf_rows_from_text(text, "ers-4500.html")

    assert rows[0]["Model"] == "ERS 4550T-PWR+"


def test_avaya_pdf_text_forces_review_without_software_eoms_date():
    text = """
    End of Sale Notice
    Notification Date: July 1, 2014
    Subject: Ethernet Routing Switch 5600-GS-DC models
    Avaya will no longer be offering the Ethernet Routing Switch 5600-GS models.
    Software versions 6.3.x and 6.6.x are not affected by this action.
    Discontinued Order Codes
    Material/Offer Code Description
    AL1001012-E5GS Ethernet Routing Switch 5698TFD with 96 ports.
    Schedule
    End of Sale Date (last day to order)*** December 7, 2014
    End of Manufacturer Support for SOFTWARE * NA
    End of Manufacturer Support for HARDWARE * December 31, 2017
    Targeted End of Services Support (EoSS) December 31, 2020
    Avaya Product Lifecycle Policy
    """

    rows = parse_avaya_pdf_rows_from_text(text, "ers-5600.html")

    assert rows[0]["Model"] == "ERS 5698TFD"
    assert rows[0]["End of Sale"] == "2014-12-07"
    assert "End of Vulnerability Support" not in rows[0]
    assert rows[0]["_force_lifecycle_review"] is True


def test_geovision_pdf_text_imports_eol_devices_as_review():
    text = """
    GeoVision Security Advisory
    Release Date: Nov 20, 2024
    Affected Product
    CVE-2024-6047
    DSP LPR           IP Camera              Video Server:        DVR
    GV_DSP_LPR_V2     GV_IPCAMD_GV_BX130     GV_GM8186_VS14       GVLX 4 V2
                      GV_IPCAMD_GV_BX1500    GV-VS14_VS14         GVLX 4 V3
                      GV_IPCAMD_GV_CB220     GV_VS03
                      GV_IPCAMD_GV_EBL1100   GV_VS2410
                      GV_IPCAMD_GV_EFD1100   GV_VS28XX
                      GV_IPCAMD_GV_FD2410    GV_VS216XX
                      GV_IPCAMD_GV_FD3400    GV VS04A
                      GV_IPCAMD_GV_FE3401    GV VS04H
                      GV_IPCAMD_GV_FE420
    CVE-2024-11120
    DSP LPR           Video Server:    DVR
    GV_DSP_LPR_V3     GV-VS12          GVLX 4 V2
                      GV-VS11          GVLX 4 V3
    Resolution
    The affected devices are no longer maintained and have reached their end of life (EOL).
    It is recommended that users replace these devices with those currently offered by GeoVision.
    """

    rows = parse_geovision_pdf_rows_from_text(text, "geovision.pdf")

    assert rows[0]["Model"] == "GV_DSP_LPR_V2"
    assert rows[0]["Announcement Date"] == "2024-11-20"
    assert rows[0]["Product Status"] == "EOL; no longer maintained"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "geovision_eol_no_longer_maintained_no_exact_date"
    assert "GVLX 4 V2" in [row["Model"] for row in rows]
    assert len(rows) == 23


def test_mobotix_product_news_imports_discontinued_products_as_review():
    text = """
    MOBOTIX NEWS - February 2026
    4. Product Discontinuation: Other Products
    The remaining hemispheric products in the Mx6 series listed here will only be available until May 15, 2026, at the latest.
    This means that the MOBOTIX c26 is now completely discontinued.
    Product discontinuations (EoL)
    c26B Complete camera 6MP, B016, Day
    Mx-c26B-6D016
    MOBOTIX MOVE NVR Network Video Recorder 8 channels (4GB model)
    Mx-S-NVR1B-8-POE
    """

    rows = parse_mobotix_product_news_pdf_rows_from_text(text, "mobotix-2026.pdf")

    assert [row["Part Number"] for row in rows] == [
        "Mx-S-NVR1B-8-POE",
        "Mx-c26B-6D016",
    ]
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "mobotix_product_discontinuation_not_security_eol"
    assert "End of Sale" not in rows[0]
    assert rows[1]["End of Sale"] == "2026-05-15"


def test_mobotix_2023_functional_boxes_import_end_of_sale_as_review():
    text = """
    PRODUCTS END OF LIFE (EOL)
    AS OF DECEMBER 1, 2023
    Product discontinuations as of December 1, 2023 (EoL)
    MX-BPA box
    MX-OPT-BPA1-EXT
    MX proximity box
    MX-PROX-BOX
    EoL of Certified Apps for MOBOTIX 7 Cameras
    Mx-APP-VIS-FR-1
    """

    rows = parse_mobotix_product_news_pdf_rows_from_text(text, "mobotix-2023.pdf")

    assert [row["Part Number"] for row in rows] == [
        "MX-OPT-BPA1-EXT",
        "MX-PROX-BOX",
    ]
    assert all(row["End of Sale"] == "2023-12-01" for row in rows)
    assert all(row["_force_lifecycle_review"] is True for row in rows)
    assert "Mx-APP-VIS-FR-1" not in [row["Part Number"] for row in rows]


def test_bosch_ip_video_platform_pdf_imports_eos_eop_as_update_end():
    text = """
    IP Video Firmware Info Brief
    2.2 Extended firmware support for EOL platforms
    PLATFORM                         EOF                  EOM                 EOS/EOP   VERSION   STATUS   AVAILABILITY   NOTES
    CPP5                             07/2016              07/2019             10/2025   6.31      ES       public
    CPP4                             05/2019              05/2022             05/2024   7.10      ES       public
    CPP3 cameras                     10/2018              12/2018             12/2023   5.75      ES       public
    CPP3 encoders                    10/2018              12/2018             12/2023   5.75      ES       public
    CPP-ENC                          10/2014              03/2018             03/2026   5.97      ES       public
    Legend
    EOS/EOP End of service / end of provisioning.
    Status EOS Final firmware release, no fixes or updates will follow.
    """

    rows = parse_bosch_ip_video_firmware_pdf_rows_from_text(text, "bosch.pdf")

    assert [row["Model"] for row in rows] == [
        "CPP5",
        "CPP4",
        "CPP3 cameras",
        "CPP3 encoders",
        "CPP-ENC",
    ]
    assert rows[0]["End of Support"] == "2025-10-31"
    assert rows[0]["End of Vulnerability Support"] == "2025-10-31"
    assert rows[-1]["End of Support"] == "2026-03-31"
    assert rows[-1]["_source_hint"] == "Bosch IP Video firmware lifecycle platform PDF import"
    assert "no firmware fixes or updates after EOS" in rows[0]["Product Status"]


def test_silver_peak_edgeconnect_policy_pdf_imports_hardware_examples():
    text = """
    HPE Aruba Networking EdgeConnect Product Lifecycle Policy
    End of Software Support (EoSS)
    The EoSS is a date-based milestone that indicates the end of software support for a specific hardware model.
    The 4GB version of EC-XS was declared as End of Sale (EoS) on December 31,2016.
    ECOS 9.4 is planned to be EoM on December 31, 2026. EOST for ECOS 9.4 will be December 31, 2028.
    Examples
    EC-US end of sale announcement July 2024
    EC-US end of sale (EoS) Jan 31, 2025
    Last date to renew HW Maintenance Jan 31, 2029
    EC-US end of HW maintenance (EoSL) Jan 31, 2030
    EC-US end of software support Jan 31, 2032 (as per old policy)
    EC-XL-H end of sale announcement June 2025
    EC-XL-H end of sale (EoS) Mar 31, 2026
    Last date to renew HW Maintenance Mar 31, 2030
    EC-XL-H end of HW maintenance (EoSL) Mar 31, 2031
    EC-XL-H end of software support Mar 31, 2031 (old policy: Mar 31, 2033)
    """

    rows = parse_silver_peak_edgeconnect_pdf_rows_from_text(text, "edgeconnect.pdf")

    assert [row["Model"] for row in rows] == [
        "EC-XS 4GB",
        "EC-XS 4GB",
        "EC-US",
        "EC-XL-H",
    ]
    assert [row["Part Number"] for row in rows[:2]] == ["200889", "200900"]
    assert rows[0]["End of Sale"] == "2016-12-31"
    assert rows[0]["End of Support"] == "2028-12-31"
    assert rows[0]["Description"] == "SD-WAN gateway appliance"
    assert "ECOS 9.4 is the last compatible software release" in rows[0]["Product Status"]
    assert rows[2]["End of Sale"] == "2025-01-31"
    assert rows[2]["End of Support"] == "2032-01-31"
    assert rows[3]["End of Support"] == "2031-03-31"
    assert rows[3]["_source_hint"] == "HPE Aruba Networking EdgeConnect lifecycle policy PDF import"


def test_genexis_psti_pdf_imports_support_life_security_dates():
    text = """
    Genexis UK Product Support
    The Product Security and Telecommunications Infrastructure (PSTI) legislation came into
    effect on 29 April 2024 in the UK. Part of this legislation is to specify the product support
    period. Genexis offers product support to customers from the market introduction date of
    the product until the End of Support Life date. Within this period, your device will receive
    security fixes when needed.

    The End of Support Life dates stated below only apply to products sold in the UK.

           Product name               Market introduction date           End of Support Life
     FiberTwist P2110B                     January 2021                     January 2027
     FiberBox G2110-2.5G                      May 2024                        May 2030
    """

    rows = parse_genexis_psti_pdf_rows_from_text(text, "genexis.pdf")

    assert [row["Model"] for row in rows] == ["FiberTwist P2110B", "FiberBox G2110-2.5G"]
    assert rows[0]["End of Support"] == "2027-01-31"
    assert rows[0]["End of Vulnerability Support"] == "2027-01-31"
    assert rows[0]["Region"] == "UK"
    assert rows[0]["Description"] == "Fiber CPE"
    assert "market introduction January 2021" in rows[0]["Product Status"]
    assert rows[1]["End of Support"] == "2030-05-31"
    assert rows[1]["_source_hint"] == "Genexis UK PSTI product support PDF import"


def test_known_false_positive_html_table_vendors_skip_generic_tables(tmp_path):
    html = """
    <table>
      <tr><th>Advisory ID</th><th>Advisory</th><th>Status</th><th>Date Published</th></tr>
      <tr><td>GV-IP-2024-11-1</td><td>EOL IP devices OS injection vulnerabilities</td><td>Completed</td><td>20-Nov-24</td></tr>
    </table>
    """
    path = tmp_path / "cyber-security-advisories.html"
    path.write_text(html, encoding="utf-8")

    assert extract_rows(path, "geovision") == []


def test_sonicwall_sonicos_csv_imports_release_as_software_model(tmp_path):
    csv_text = """Release,Model,Type,Release Date,EOS Date,Status,Recommended Upgrade
SonicOS 7.1.x and 7.0.X,"TZ270 series, TZ370 series",MR,2025-01-07,2025-09-30,End of Support,7.3.0
"""
    path = tmp_path / "sonicwall_sonicos_release_eos_status.csv"
    path.write_text(csv_text, encoding="utf-8")

    rows = [row for row in extract_rows(path, "sonicwall") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "SonicOS 7.1.x and 7.0.X",
            "Product Name": "SonicOS 7.1.x and 7.0.X",
            "Description": "SonicOS release for TZ270 series, TZ370 series",
            "Product Status": "End of Support",
            "End of Support": "2025-09-30",
            "Replacement Products": "7.3.0",
            "_source_table": "sonicwall_sonicos_release_eos_status.csv",
            "_source_hint": "SonicWall SonicOS release EOS status CSV import",
        }
    ]


def test_sonicwall_lifecycle_csv_preserves_product_family_in_model(tmp_path):
    csv_text = """Model,Last Order Day,ARM Begin,LRM Begin,1 Year LOD,End Of Support
10,2022-04-15,2022-04-16,2024-04-16,2025-04-15,2026-04-16
"""
    path = tmp_path / "sonicwall_nsv_series_hardware_lifecycle_dates.csv"
    path.write_text(csv_text, encoding="utf-8")

    rows = [row for row in extract_rows(path, "sonicwall") if row.get("_source_hint")]

    assert rows == [
        {
            "Model": "NSv 10",
            "Part Number": "10",
            "Product Name": "NSv 10",
            "Description": "NSv Series Firewall",
            "Device Type": "Virtual Firewall",
            "Product Status": "lifecycle schedule",
            "_source_table": "sonicwall_nsv_series_hardware_lifecycle_dates.csv",
            "_source_hint": "SonicWall lifecycle dates CSV import",
            "_prefer_model": True,
            "Last Order Day": "2022-04-15",
            "End of Support": "2026-04-16",
        }
    ]


def test_sonicwall_firewall_lifecycle_csv_prefixes_tz_numeric_models(tmp_path):
    csv_text = """Model,Last Order Day,ARM Begin,LRM Begin,1 Year LOD,End Of Support
100W,2012-11-16,2012-11-17,2014-11-17,2016-11-16,2017-11-15
SOHO 250,2021-07-31,2021-08-01,2023-08-01,2025-09-30,2026-10-01
"""
    path = tmp_path / "sonicwall_firewall_lifecycle_dates.csv"
    path.write_text(csv_text, encoding="utf-8")

    rows = [row for row in extract_rows(path, "sonicwall") if row.get("_source_hint")]

    assert rows[0]["Model"] == "TZ100W"
    assert rows[0]["Part Number"] == "100W"
    assert rows[1]["Model"] == "SOHO 250"


def test_orphan_raw_files_are_opt_in_manifest_supplement(tmp_path):
    vendor_dir = tmp_path / "example"
    raw_dir = vendor_dir / "raw"
    raw_dir.mkdir(parents=True)
    known = raw_dir / "known.csv"
    orphan = raw_dir / "orphan.csv"
    unsupported = raw_dir / "notes.txt"
    known.write_text("Model,End of Support\nA,2026-01-01\n", encoding="utf-8")
    orphan.write_text("Model,End of Support\nB,2026-01-01\n", encoding="utf-8")
    unsupported.write_text("ignore", encoding="utf-8")

    files = orphan_raw_files(vendor_dir, {known.resolve()})

    assert [path.name for path, _ in files] == ["orphan.csv"]
    assert files[0][1]["status"] == 200
    assert files[0][1]["url"] is None


def test_vendor_batch_filter_helpers(tmp_path):
    vendor_file = tmp_path / "vendors.txt"
    vendor_file.write_text(
        """
        # pilot vendors
        moxa
        westermo, teltonika
        """,
        encoding="utf-8",
    )

    selected = build_vendor_filter(["avm_fritzbox, DrayTek"], [vendor_file])

    assert selected == {
        "avm_fritzbox",
        "draytek",
        "moxa",
        "teltonika",
        "westermo",
    }
    assert (
        vendor_skip_reason(
            vendor_slug="axis",
            selected_vendors=selected,
            skipped_vendors=set(),
            existing_vendors=set(),
            include_existing_vendors=False,
        )
        == "not_selected"
    )
    assert (
        vendor_skip_reason(
            vendor_slug="moxa",
            selected_vendors=selected,
            skipped_vendors={"moxa"},
            existing_vendors=set(),
            include_existing_vendors=False,
        )
        == "explicitly_skipped"
    )
    assert (
        vendor_skip_reason(
            vendor_slug="tplink",
            selected_vendors=set(),
            skipped_vendors=set(),
            existing_vendors=set(),
            include_existing_vendors=False,
        )
        == "default_existing_builder_vendor"
    )


def test_status_only_eol_row_is_forced_to_lifecycle_review(tmp_path):
    class FakeBuilder:
        def make_record(self, **kwargs):
            return {
                "id": "hw_example_abc",
                "vendor": kwargs["display_name"] if "display_name" in kwargs else "Example",
                "vendor_slug": kwargs["vendor_slug"],
                "model": kwargs["model"],
                "model_key": "abc_1",
                "product_name": kwargs["product_name"],
                "part_number": kwargs["part_number"],
                "hardware_version": None,
                "region": None,
                "device_type": kwargs["device_type"],
                "device_class": "network_device",
                "description": kwargs["description"],
                "dates": {
                    "announcement": None,
                    "last_sale": None,
                    "end_of_sale": None,
                    "end_of_life": None,
                    "end_of_support": None,
                    "end_of_service": None,
                    "end_of_vulnerability": None,
                    "end_of_security_updates": None,
                },
                "lifecycle": {
                    "status": "unsupported_status_only",
                    "risk": "high",
                    "receives_security_updates": False,
                    "replacement_recommended": True,
                    "confidence": "medium",
                    "reason": "Vendor/source status indicates unsupported.",
                    "days_to_security_eol": None,
                },
                "replacement": kwargs["replacement"] or None,
                "match": {
                    "aliases": [kwargs["model"]],
                    "alias_keys": ["abc_1"],
                    "vendor_model_key": "example|abc_1",
                },
                "source": {
                    "url": kwargs["source_url"],
                    "raw_file": str(kwargs["raw_file"]),
                    "status_text": kwargs["raw_status"],
                    "source_hint": kwargs["source_hint"],
                },
                "netwatch": {
                    "match_priority": 50,
                    "finding_title": "Example ABC-1 no longer receives security updates",
                },
            }

        def match_priority(self, device_class, lifecycle_status):
            return 50

    row = {
        "Model": "ABC-1",
        "Product Status": "end-of-life",
        "Product Name": "Example ABC-1 gateway",
        "_status_only_review": True,
        "_review_policy": "status_only_not_security_eol",
    }

    record = row_to_record(
        builder=FakeBuilder(),
        vendor_slug="example",
        display_name="Example",
        raw_file=tmp_path / "example.html",
        row=row,
        source_url="https://example.invalid/eol",
        source_hint="Example raw lifecycle table import",
        as_of=date(2026, 5, 14),
    )

    assert record is not None
    assert record["product_name"] == "Example ABC-1 gateway"
    assert record["source"]["status_text"] == "end-of-life"
    assert "netwatch" not in record
    assert "sunsetscan" in record
    assert record["lifecycle"]["status"] == "lifecycle_review"
    assert record["lifecycle"]["receives_security_updates"] is None
    assert "vendor-declared EOL" in record["lifecycle"]["reason"]
    assert "vendor-declared EOL" in record["sunsetscan"]["finding_title"]
    assert record["quality"]["interpretation_policy"] == "status_only_not_security_eol"


def test_allow_status_only_row_preserves_unsupported_status(tmp_path):
    class FakeBuilder:
        def make_record(self, **kwargs):
            return {
                "id": "hw_example_abc",
                "vendor": "Example",
                "vendor_slug": kwargs["vendor_slug"],
                "model": kwargs["model"],
                "model_key": "abc_1",
                "product_name": kwargs["product_name"],
                "part_number": kwargs["part_number"],
                "hardware_version": None,
                "region": None,
                "device_type": kwargs["device_type"],
                "device_class": "printer",
                "description": kwargs["description"],
                "dates": {
                    "announcement": None,
                    "last_sale": None,
                    "end_of_sale": None,
                    "end_of_life": None,
                    "end_of_support": None,
                    "end_of_service": None,
                    "end_of_vulnerability": None,
                    "end_of_security_updates": None,
                },
                "lifecycle": {
                    "status": "unsupported_status_only",
                    "risk": "high",
                    "receives_security_updates": False,
                    "replacement_recommended": True,
                    "confidence": "medium",
                    "reason": "Vendor/source status indicates unsupported.",
                    "days_to_security_eol": None,
                },
                "replacement": None,
                "match": {
                    "aliases": [kwargs["model"]],
                    "alias_keys": ["abc_1"],
                    "vendor_model_key": "example|abc_1",
                },
                "source": {
                    "url": kwargs["source_url"],
                    "raw_file": str(kwargs["raw_file"]),
                    "status_text": kwargs["raw_status"],
                    "source_hint": kwargs["source_hint"],
                },
                "sunsetscan": {
                    "match_priority": 20,
                    "finding_title": "Example ABC-1 unsupported",
                },
            }

    row = {
        "Model": "ABC-1",
        "Product Status": "End of Service Life; Firmware Support discontinued",
        "Product Name": "Example ABC-1 printer",
        "_allow_status_only": True,
    }

    record = row_to_record(
        builder=FakeBuilder(),
        vendor_slug="example",
        display_name="Example",
        raw_file=tmp_path / "example.html",
        row=row,
        source_url="https://example.invalid/eosl",
        source_hint="Example status-only unsupported import",
        as_of=date(2026, 5, 14),
    )

    assert record is not None
    assert record["lifecycle"]["status"] == "unsupported_status_only"
    assert record["lifecycle"]["receives_security_updates"] is False
    assert "quality" not in record


def test_row_alias_fields_extend_existing_match_aliases(tmp_path):
    class FakeBuilder:
        def normalize_lookup_key(self, value):
            chars = [
                char.lower() if char.isascii() and char.isalnum() else " "
                for char in str(value or "")
            ]
            return " ".join("".join(chars).split())

        def make_record(self, **kwargs):
            return {
                "id": "hw_example_abc",
                "vendor": "Example",
                "vendor_slug": kwargs["vendor_slug"],
                "model": kwargs["model"],
                "model_key": "abc 1",
                "product_name": kwargs["product_name"],
                "part_number": kwargs["part_number"],
                "hardware_version": None,
                "region": None,
                "device_type": kwargs["device_type"],
                "device_class": "network_device",
                "description": kwargs["description"],
                "dates": {
                    "announcement": None,
                    "last_sale": None,
                    "end_of_sale": None,
                    "end_of_life": None,
                    "end_of_support": "2026-05-14",
                    "end_of_service": None,
                    "end_of_vulnerability": None,
                    "end_of_security_updates": "2026-05-14",
                },
                "lifecycle": {
                    "status": "unsupported",
                    "risk": "high",
                    "receives_security_updates": False,
                    "replacement_recommended": True,
                    "confidence": "high",
                    "reason": "Support has ended.",
                    "days_to_security_eol": None,
                },
                "replacement": kwargs["replacement"] or None,
                "match": {
                    "aliases": [kwargs["model"]],
                    "alias_keys": ["abc 1"],
                    "vendor_model_key": "example|abc 1",
                },
                "source": {
                    "url": kwargs["source_url"],
                    "raw_file": str(kwargs["raw_file"]),
                    "status_text": kwargs["raw_status"],
                    "source_hint": kwargs["source_hint"],
                },
                "netwatch": {
                    "match_priority": 50,
                    "finding_title": "Example ABC-1 support has ended",
                },
            }

    original_name = "\u5bb6\u5ead\u7f51\u5173"
    row = {
        "Model": "ABC-1",
        "End of Support": "2026-05-14",
        "Also Known As": f"ABC One; Legacy ABC / ABC Pro; {original_name}",
    }

    record = row_to_record(
        builder=FakeBuilder(),
        vendor_slug="example",
        display_name="Example",
        raw_file=tmp_path / "example.html",
        row=row,
        source_url="https://example.invalid/eol",
        source_hint="Example raw lifecycle table import",
        as_of=date(2026, 5, 14),
    )

    assert record is not None
    assert "ABC One" in record["match"]["aliases"]
    assert "Legacy ABC" in record["match"]["aliases"]
    assert "ABC Pro" in record["match"]["aliases"]
    assert "Example ABC One" in record["match"]["aliases"]
    assert original_name in record["match"]["aliases"]
    assert "abc one" in record["match"]["alias_keys"]
    assert "example abc one" in record["match"]["alias_keys"]
    assert original_name in record["match"]["alias_keys"]


def test_split_index_input_is_expanded_for_ingest(tmp_path):
    records_dir = tmp_path / "records"
    records_dir.mkdir()
    shard_path = records_dir / "network_infrastructure.json"
    shard_path.write_text(
        """
        {
          "category": "network_infrastructure",
          "records": [{"id": "hw_example_1", "vendor_slug": "example"}],
          "indexes": {"by_id": {"hw_example_1": 0}}
        }
        """,
        encoding="utf-8",
    )
    index_path = tmp_path / "sunsetscan_hardware_eol_index.json"
    index_path.write_text(
        """
        {
          "metadata": {
            "schema": "sunsetscan.hardware_eol.v1",
            "artifact_layout": {"format": "split"}
          },
          "summary": {"total_records": 1},
          "indexes": {"by_id": {"hw_example_1": 0}},
          "model_summaries": [],
          "record_shards": {
            "network_infrastructure": {
              "path": "records/network_infrastructure.json",
              "record_count": 1
            }
          },
          "record_locations": {"hw_example_1": "network_infrastructure"}
        }
        """,
        encoding="utf-8",
    )

    database = load_database_for_ingest(index_path)

    assert database["records"] == [{"id": "hw_example_1", "vendor_slug": "example"}]
    assert "record_shards" not in database
    assert "record_locations" not in database
    assert "artifact_layout" not in database["metadata"]
