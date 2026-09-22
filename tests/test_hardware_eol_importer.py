import json
from datetime import date

import tools.ingest_raw_hardware_eol_sources as importer_module
from tools.ingest_raw_hardware_eol_sources import (
    builder_compatible_raw_file,
    build_vendor_filter,
    choose_model,
    extract_2n_discontinued_rows,
    extract_threeonedata_discontinued_rows,
    extract_adtran_aos_support_rows,
    extract_aaeon_network_appliance_phaseout_rows,
    extract_acrosser_eol_product_rows,
    extract_adlink_product_eol_rows,
    extract_aiphone_discontinued_product_rows,
    extract_akuvox_security_update_rows,
    extract_amcrest_discontinued_firmware_rows,
    extract_antaira_phaseout_rows,
    extract_arbor_eol_product_rows,
    extract_axiomtek_product_eol_rows,
    extract_balluff_product_lifecycle_rows,
    extract_bcm_advanced_research_eol_notice_rows,
    extract_beckhoff_service_product_rows,
    extract_birddog_previous_lines_rows,
    extract_broadcom_bluecoat_packetshaper_rows,
    extract_cincoze_eol_rows,
    extract_clavister_end_of_sales_rows,
    extract_comnet_discontinued_product_rows,
    extract_crestron_discontinued_product_rows,
    extract_ctsystem_fos_ies_eol_rows,
    extract_cyberdata_eol_product_rows,
    extract_dfi_product_status_rows,
    extract_digital_loggers_discontinued_rows,
    extract_epiphan_pearl_status_rows,
    extract_etherwan_eol_notice_rows,
    extract_ezurio_part_eol_rows,
    extract_exfo_discontinued_product_rows,
    extract_fanvil_eol_rows,
    extract_fluke_networks_dtx_eol_rows,
    extract_glinet_eol_rows,
    extract_grandstream_status_rows,
    extract_yealink_lifecycle_rows,
    extract_hanwha_discontinued_product_rows,
    extract_hillstone_eol_policy_rows,
    extract_milesight_eol_announcement_rows,
    extract_mitel_lifecycle_rows,
    extract_hp_designjet_eosl_json_rows,
    extract_icp_das_lifecycle_rows,
    extract_idis_discontinued_product_rows,
    extract_iei_networking_eol_rows,
    extract_inhand_networks_eol_rows,
    extract_iogear_eol_product_json_rows,
    extract_ip_com_eol_product_rows,
    extract_ivanti_pulse_release_matrix_rows,
    extract_kontron_product_eol_rows,
    extract_kramer_product_eol_rows,
    extract_kyocera_taskalfa_sales_end_rows,
    extract_lantronix_discontinued_product_rows,
    extract_legrand_luxul_discontinued_search_rows,
    extract_lenovo_networking_withdrawn_product_rows,
    extract_lexmark_product_eosl_rows,
    extract_matrox_video_eol_rows,
    extract_multitech_eol_product_rows,
    extract_netally_legacy_product_rows,
    extract_netberg_lifecycle_rows,
    extract_netapp_software_version_support_rows,
    extract_netgate_product_lifecycle_rows,
    extract_netmodule_eol_rows,
    extract_nexcom_aiot_mart_eol_product_rows,
    extract_netskope_sdwan_lifecycle_rows,
    extract_neousys_eol_product_rows,
    extract_nvt_phybridge_eol_rows,
    extract_patton_sunset_rows,
    extract_pepperl_fuchs_archive_rows,
    extract_peplink_legacy_product_rows,
    extract_pica8_product_bulletin_rows,
    extract_qnap_os_lifecycle_rows,
    extract_qnap_product_status_api_rows,
    extract_ricoh_discontinued_printer_rows,
    extract_rockwell_stratix_lifecycle_rows,
    extract_robustel_eol_policy_rows,
    extract_rows,
    extract_ruijie_lifecycle_rows,
    extract_sangoma_eol_rows,
    extract_siemens_ruggedcom_lifecycle_rows,
    extract_stormshield_firewall_lifecycle_rows,
    extract_synology_product_status_rows,
    extract_split_milestone_rows,
    extract_status_marked_product_page_rows,
    extract_telrad_breezeview_rows,
    extract_teradek_cube_serv_pro_eol_rows,
    extract_thecus_nas_archive_rows,
    extract_tippingpoint_eol_dates_rows,
    extract_uniview_discontinued_product_rows,
    extract_uplogix_lantronix_rows,
    extract_verkada_end_of_sale_rows,
    extract_volktek_eos_eol_rows,
    extract_wago_discontinued_product_rows,
    extract_zebra_discontinued_product_rows,
    extract_zte_lifecycle_rows,
    import_dedupe_key,
    ingest_raw_sources,
    lifecycle_dates,
    load_database_for_ingest,
    local_rawdata_files,
    orphan_raw_files,
    parse_advantech_ntron_pdf_rows_from_text,
    parse_alcatel_lucent_pdf_rows_from_text,
    parse_adtran_bluesocket_pdf_rows_from_text,
    parse_aruba_pdf_rows_from_text,
    parse_atx_digistream_pdf_rows_from_text,
    parse_audiocodes_pdf_rows_from_text,
    parse_avigilon_pdf_rows_from_text,
    parse_avaya_pdf_rows_from_text,
    parse_beijer_korenix_pdf_rows_from_text,
    parse_bosch_ip_video_firmware_pdf_rows_from_text,
    parse_broadcom_brocade_pdf_rows_from_text,
    parse_calix_pdf_rows_from_text,
    parse_celona_pdf_rows_from_text,
    parse_ctsystem_eol_products_pdf_rows_from_text,
    parse_ctc_union_pdf_rows_from_text,
    parse_date_any,
    parse_eaton_pdf_rows_from_text,
    parse_eltako_safe_iv_pdf_rows_from_text,
    parse_genexis_psti_pdf_rows_from_text,
    parse_garland_pdf_rows_from_text,
    parse_geovision_pdf_rows_from_text,
    parse_helmholz_myrex24_pdf_rows_from_text,
    parse_hikvision_discontinuation_pdf_rows_from_text,
    parse_hirschmann_belden_pdn_rows_from_text,
    parse_idirectgov_pdf_rows_from_text,
    parse_ligowave_pdf_rows_from_text,
    parse_mimosa_eol_pdf_rows_from_text,
    parse_mobotix_product_news_pdf_rows_from_text,
    parse_netcontrol_pdf_rows_from_text,
    parse_nvidia_mellanox_pdf_rows_from_text,
    parse_pilz_pnozmulti_pdf_rows_from_text,
    parse_ribbon_pdf_rows_from_text,
    parse_schneider_apc_connexium_pdf_rows_from_text,
    parse_sierra_airlink_pdf_rows_from_text,
    parse_silicom_pdf_rows_from_text,
    parse_silver_peak_edgeconnect_pdf_rows_from_text,
    parse_spectralink_pdf_rows_from_text,
    parse_telrad_cpe8100_pdf_rows_from_text,
    parse_vertiv_avocent_pdf_rows_from_text,
    parse_vertiv_pdf_rows_from_text,
    extract_siedle_discontinued_product_rows,
    parse_softing_product_support_dates,
    parse_weidmueller_datasheet_pdf_rows_from_text,
    parse_westermo_pdf_rows_from_text,
    parse_winmate_pcn_pdf_rows_from_text,
    parse_zpe_systems_pdf_rows_from_text,
    record_dedupe_score,
    row_to_record,
    rows_to_dicts,
    raw_vendor_dirs,
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


def test_record_dedupe_score_prefers_later_equal_strength_lifecycle_dates():
    older = {
        "dates": {
            "announcement": "2014-05-20",
            "end_of_sale": "2014-10-10",
            "end_of_support": "2017-10-10",
        }
    }
    newer = {
        "dates": {
            "announcement": "2015-03-09",
            "end_of_sale": "2016-01-15",
            "end_of_support": "2019-01-15",
        }
    }

    assert record_dedupe_score(newer) > record_dedupe_score(older)


def test_builder_compatible_raw_file_preserves_external_source_path(tmp_path):
    class Builder:
        ROOT = tmp_path / "scraper"

    external = tmp_path / "vendorRawData" / "example" / "rawdata" / "eol.html"
    external.parent.mkdir(parents=True)
    external.write_text("<html></html>", encoding="utf-8")

    compatible, is_external = builder_compatible_raw_file(Builder, external, "example")

    assert is_external is True
    assert compatible == Builder.ROOT / "_external_rawdata" / "example" / "eol.html"


def test_manifestless_rawdata_vendor_dir_is_discovered(tmp_path):
    raw_root = tmp_path / "eol-rawdata-scraper"
    adlink_raw = raw_root / "adlink" / "rawdata"
    adlink_raw.mkdir(parents=True)
    html_path = adlink_raw / "product_example.html"
    html_path.write_text("<html></html>", encoding="utf-8")
    (raw_root / "no_rawdata").mkdir()

    assert raw_vendor_dirs(raw_root) == [raw_root / "adlink"]

    files = local_rawdata_files(raw_root / "adlink")

    assert files == [
        (
            html_path,
            {
                "url": None,
                "status": 200,
                "notes": "Local rawdata file present without source_manifest.json",
                "local_path": str(html_path),
            },
        )
    ]


def test_ingest_dedupes_new_same_key_before_duplicate_id_skip(tmp_path, monkeypatch):
    raw_root = tmp_path / "raw"
    vendor_raw = raw_root / "audiocodes" / "rawdata"
    vendor_raw.mkdir(parents=True)
    sale_pdf = vendor_raw / "sale.pdf"
    support_pdf = vendor_raw / "support.pdf"
    sale_pdf.write_bytes(b"%PDF sale")
    support_pdf.write_bytes(b"%PDF support")

    class FakeBuilder:
        ROOT = tmp_path / "builder"
        VENDOR_NAMES = {}
        VENDOR_ALIASES = {}

        @staticmethod
        def normalize_lookup_key(value):
            return str(value).lower().replace(" ", "_")

        @staticmethod
        def make_record(**kwargs):
            model = kwargs["model"]
            part_number = kwargs.get("part_number") or model
            return {
                "id": f"hardware_eol:audiocodes:{part_number.lower().replace(' ', '_')}",
                "vendor_slug": kwargs["vendor_slug"],
                "vendor": "AudioCodes",
                "model": model,
                "model_key": model.lower(),
                "part_number": part_number,
                "hardware_version": kwargs.get("hardware_version") or "",
                "region": kwargs.get("region") or "",
                "dates": kwargs["dates"],
                "lifecycle": {"status": "unknown"},
                "device_class": "network_device",
                "source": {"raw_file": str(kwargs["raw_file"])},
                "match": {"aliases": [], "alias_keys": []},
                "quality": {},
                "sunsetscan": {},
            }

        @staticmethod
        def dedupe_records(records):
            return records

        @staticmethod
        def build_model_summaries(records):
            return []

        @staticmethod
        def build_indexes(records):
            return {}

        @staticmethod
        def build_summary(records, model_summaries):
            return {"vendors": sorted({record["vendor_slug"] for record in records})}

    def fake_extract_rows(path, vendor_slug):
        base = {
            "Model": "Voca CIC Non-Managed Offerings",
            "Part Number": "Voca CIC Non-Managed Offerings",
            "Product Status": "AudioCodes product notice",
        }
        if path.name == "sale.pdf":
            return [
                {
                    **base,
                    "End of Sale": "2025-03-14",
                    "_force_lifecycle_review": True,
                }
            ]
        return [{**base, "End of Support": "2025-12-31"}]

    monkeypatch.setattr(importer_module, "extract_rows", fake_extract_rows)
    monkeypatch.setattr(importer_module, "rebuild_model_summaries", lambda database: None)
    monkeypatch.setattr(importer_module, "rebuild_summary", lambda database: None)

    database, report = ingest_raw_sources(
        builder=FakeBuilder,
        database={"records": [], "summary": {"vendors": []}},
        scraper_root=tmp_path,
        raw_root=raw_root,
        as_of=date(2026, 6, 4),
        include_existing_vendors=False,
        selected_vendors={"audiocodes"},
    )

    assert report["deduped_new_rows_by_vendor"] == {"audiocodes": 1}
    assert report["duplicate_record_ids_skipped_by_vendor"] == {}
    assert len(database["records"]) == 1
    assert database["records"][0]["dates"]["end_of_support"] == "2025-12-31"


def test_extract_adlink_product_eol_row_uses_product_name_over_generic_title(tmp_path):
    path = tmp_path / "product_mxc_6300_series.html"
    path.write_text(
        """
        <html>
          <head>
            <meta name="title" content="Industrial PCs | Embedded Computer | ADLINK" />
            <meta name="description" content="The MXC-6300 Series of industrial PCs has 2 GbE LAN ports." />
            <link rel="canonical" href="https://www.adlinktech.com/products/industrial_pcs_fanless_embedded_pcs/expandablefanlessembeddedcomputers/mxc-6300_series" />
          </head>
          <body>
            <h2 class="Product-name">MXC-6300 Series</h2>
            <span class="Product-tip maroon">END OF LIFE</span>
            <div class="Product-sub">Expandable fanless embedded computer with 2 GbE LAN ports</div>
            <div class="Product-eol">The MXC-6300 Series is scheduled for discontinuation as of 2019/08/09. The recommended replacement product is <a>MXC-6400 Series</a>.</div>
            <p>Last buy date: August 9, 2019<br>Last shipment date: February 7, 2020</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_adlink_product_eol_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "MXC-6300 Series"
    assert rows[0]["Replacement"] == "MXC-6400 Series"
    assert rows[0]["End of Sale"] == "2019-08-09"
    assert rows[0]["Last Shipment Date"] == "2020-02-07"
    assert rows[0]["_status_only_review"] is True
    assert "End of Life" not in rows[0]


def test_extract_adlink_product_eol_row_strips_vendor_prefix_and_keeps_review_only(tmp_path):
    path = tmp_path / "product_adlink_ava_3501.html"
    path.write_text(
        """
        <html>
          <head>
            <meta name="title" content="ADLINK AVA-3501 | Autonomous Driving Solutions | ADLINK" />
            <link rel="canonical" href="https://www.adlinktech.com/products/connected-autonomous-vehicle-solutions/autonomous-vehicles/adlink_ava-3501" />
          </head>
          <body>
            <h2 class="Product-name">ADLINK AVA-3501</h2>
            <span class="Product-tip maroon">END OF LIFE</span>
            <div class="Product-sub">This model is EOL; suggested replacement is AVA-3510</div>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_adlink_product_eol_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "AVA-3501"
    assert rows[0]["Product Name"] == "ADLINK AVA-3501"
    assert rows[0]["Replacement"] == "AVA-3510"
    assert rows[0]["_status_only_review"] is True
    assert "End of Sale" not in rows[0]
    assert "End of Life" not in rows[0]


def test_extract_fanvil_eol_rows_splits_grouped_models_and_uses_sale_only_date(tmp_path):
    path = tmp_path / "20260105_9979.html"
    path.write_text(
        """
        <html>
          <head><title>X3S Lite/X3SP Lite Entry Level IP Phone EOL Notice</title></head>
          <body>
            <h1>X3S Lite/X3SP Lite Entry Level IP Phone<br/>EOL Notice</h1>
            <p>Fanvil hereby informs you that the Fanvil X3S Lite/X3SP Lite Entry Level IP Phone has been discontinued since December 22, 2025. After the date, new orders for the product would not be accepted. After the End-of-Life date, Fanvil will not pursue any new feature development on X3S Lite/X3SP Lite Entry Level IP Phone, but we will provide software support of the discontinued (EOL) products following the industry standard practices.</p>
            <p>For the first year from the End of Life date, Fanvil will offer technical support for hardware and software. Software technical support includes Existing Bug Fixes, New Security Fixes and Critical Compatibility Problem Fixes. Since the sixth year from the End of Life, Fanvil will not offer any Support.</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_fanvil_eol_rows(path)

    assert [row["Model"] for row in rows] == ["X3S Lite", "X3SP Lite"]
    assert {row["End of Sale"] for row in rows} == {"2025-12-22"}
    assert all(row["_status_only_review"] is True for row in rows)
    assert all("End of Life" not in row for row in rows)
    assert all("End of Support" not in row for row in rows)
    assert rows[0]["_source_url"] == "https://www.fanvil.com/products/p8/20260105/9979.html"


def test_extract_fanvil_eol_rows_accepts_no_visible_date_as_review_only(tmp_path):
    path = tmp_path / "20210921_5073.html"
    path.write_text(
        """
        <html>
          <body>
            <h1>BW210/BW210P IP Phones<br/>EOL Notice</h1>
            <p>Fanvil hereby announces the manufacture discontinue and End-of-Life (EOL) of Fanvil BW210/BW210P. The products are being discontinued due to market demand and shifts in technology.</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_fanvil_eol_rows(path)

    assert [row["Model"] for row in rows] == ["BW210", "BW210P"]
    assert all(row["_status_only_review"] is True for row in rows)
    assert all("End of Sale" not in row for row in rows)
    assert all("End of Life" not in row for row in rows)


def test_extract_icp_das_product_page_phase_out_is_status_only(tmp_path):
    path = tmp_path / "product_ns_200ft.html"
    path.write_text(
        """
        <html>
          <head><title>NS-200FT</title><meta name="description" content="Ethernet to Fiber Optic converter"></head>
          <body>
            <div class="pro_title_area">
              <h2 class="st">NS-200FT</h2>
              <div class="tag_box"><span class="triangle type_yellow"></span><label>Will be phased out</label></div>
              <div class="demo_txt editor"><a href="../../en/news/show.php?num=1640">EOL Notification</a></div>
            </div>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_icp_das_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "NS-200FT"
    assert rows[0]["Product Status"] == "ICP DAS product status: Will be phased out"
    assert rows[0]["_status_only_review"] is True
    assert "End of Sale" not in rows[0]
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]


def test_extract_icp_das_eol_news_maps_last_order_to_sale_only(tmp_path):
    path = tmp_path / "eol_news_2654.html"
    path.write_text(
        """
        <html>
          <head>
            <title>M2M-710D: Remote Maintenance Ethernet Device Terminal Unit</title>
            <meta property="og:url" content="https://www.icpdas.com/en/news/show.php?num=2654">
          </head>
          <body>
            <strong>Phased out model: M2M-710D</strong>
            <strong>Last Order Date: <span>2025/4/29</span></strong>
            <p>ICP DAS hereby formally announces the manufacturing discontinue and End of Life (EOL) of M2M-710D. The replacement product is the M2M-711D or tDS-718i.</p>
            <p>Within the effective warranty period, ICP DAS is committed to continue providing comprehensive after-sales service and technical support.</p>
            <p>Suggested replacement device: <strong>M2M-711D</strong> or <strong>tDS-718i</strong> - Status: Available</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_icp_das_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "M2M-710D"
    assert rows[0]["End of Sale"] == "2025-04-29"
    assert rows[0]["Replacement"] == "M2M-711D; tDS-718i"
    assert rows[0]["_status_only_review"] is True
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]


def test_extract_netberg_product_page_is_status_only(tmp_path):
    path = tmp_path / "product_aurora_705.html"
    path.write_text(
        """
        <html>
          <body>
            <h2>EOL Aurora 705 <small>32 x 100G network switch</small></h2>
            <p>Support materials and specifications for Aurora 705.</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_netberg_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "Aurora 705"
    assert rows[0]["Product Status"] == "Netberg product page marked EOL"
    assert rows[0]["_source_url"] == "https://netbergtw.com/products/aurora-705/"
    assert rows[0]["_status_only_review"] is True
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]


def test_extract_netberg_july_2025_notice_keeps_security_unknown(tmp_path):
    path = tmp_path / "article_2025_july_eol_notice.html"
    path.write_text(
        """
        <html>
          <body>
            <h2>2025 July EOL Notice</h2>
            <div>Effective July 7, 2025: The following products are now End of Life (EOL): Aurora 750, Aurora 710, and Aurora 610.</div>
            <p>The EOL products are still eligible for maintenance support up to <strong>3 years</strong> following their EOL date.</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_netberg_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == ["Aurora 750", "Aurora 710", "Aurora 610"]
    assert {row["End of Life"] for row in rows} == {"2025-07-07"}
    assert all(row["_status_only_review"] is True for row in rows)
    assert all("End of Support" not in row for row in rows)
    assert all("End of Security Updates" not in row for row in rows)


def test_extract_dfi_product_status_rows_keeps_cpu_lifecycle_as_status_only(tmp_path):
    path = tmp_path / "product_ku553_1429.html"
    path.write_text(
        """
        <html>
          <head>
            <title>KU553|Intel|Industrial Motherboards|DFI</title>
            <meta property="og:url" content="https://www.dfi.com/product/index/1429">
            <meta name="description" content="3.5 SBC, 2 Intel GbE, 4 USB 3.0">
          </head>
          <body>
            <p>15-Year CPU Life Cycle Support Until Q1' 32 (Based on Intel IOTG Roadmap)</p>
            <p>Status : EOL</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_dfi_product_status_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "KU553"
    assert rows[0]["Description"] == "Industrial Motherboard"
    assert rows[0]["_source_url"] == "https://www.dfi.com/product/index/1429"
    assert rows[0]["_status_only_review"] is True
    assert "CPU Life Cycle Support Until Q1' 32" in rows[0]["Product Status"]
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]


def test_extract_dfi_product_status_rows_requires_visible_eol_status(tmp_path):
    path = tmp_path / "product_cs100_1410.html"
    path.write_text(
        """
        <html>
          <head><title>CS100|Intel|Industrial Motherboards|DFI</title></head>
          <body><p>Rich I/O: 2 Intel GbE</p></body>
        </html>
        """,
        encoding="utf-8",
    )

    assert extract_dfi_product_status_rows(path) == []


def test_extract_iogear_eol_product_json_rows_uses_sku_as_review_model(tmp_path):
    path = tmp_path / "product_gcs1322taa3.json"
    path.write_text(
        json.dumps(
            {
                "title": "2-Port Dual View HDMI Secure KVM Switch (TAA)",
                "handle": "gcs1322taa3",
                "vendor": "IOGEAR",
                "tags": ["label_EOL"],
                "description": "<p>NIAP-certified secure KVM switch.</p>",
                "variants": [
                    {
                        "sku": "GCS1322TAA3",
                        "title": "Default Title",
                        "barcode": "881317516343",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rows = extract_iogear_eol_product_json_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "GCS1322TAA3"
    assert rows[0]["Part Number"] == "GCS1322TAA3"
    assert rows[0]["Description"] == "Secure KVM Switch"
    assert rows[0]["Product Status"].startswith("IOGEAR EOL-tagged product")
    assert rows[0]["Lifecycle Status Source"] == "https://iogear.com/collections/eol"
    assert rows[0]["_source_url"] == "https://iogear.com/products/gcs1322taa3"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "iogear_eol_collection_status_only"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]


def test_extract_iogear_eol_product_json_rows_requires_eol_tag(tmp_path):
    path = tmp_path / "product_gcs1322taa3.json"
    path.write_text(
        json.dumps(
            {
                "title": "2-Port Dual View HDMI Secure KVM Switch (TAA)",
                "handle": "gcs1322taa3",
                "vendor": "IOGEAR",
                "tags": ["Related Secure KVM"],
                "variants": [{"sku": "GCS1322TAA3"}],
            }
        ),
        encoding="utf-8",
    )

    assert extract_iogear_eol_product_json_rows(path) == []


def test_extract_ezurio_part_eol_rows_imports_exact_part_status_only(tmp_path):
    path = tmp_path / "part_453-00137.html"
    path.write_text(
        """
        <html>
          <head>
            <title>453-00137 | Ezurio</title>
            <link rel="canonical" href="https://www.ezurio.com/part/453-00137">
          </head>
          <body>
            <h1 data-part="453-00137">453-00137</h1>
            <div class="lifecycle">End of Life (EOL)</div>
            <div class="spec-content">
              <div class="specification">Description</div>
              <div class="value">60 Series SOM using 1 Gb LPDDR2 RAM</div>
            </div>
            <div class="spec-content">
              <div class="specification">Product Type</div>
              <div class="value">Embedded Module, SOM</div>
            </div>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_ezurio_part_eol_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "453-00137"
    assert rows[0]["Part Number"] == "453-00137"
    assert rows[0]["Product Name"] == "453-00137"
    assert rows[0]["Description"] == "System-on-Module"
    assert rows[0]["Product Type"] == "Embedded Module, SOM"
    assert rows[0]["Source Description"] == "60 Series SOM using 1 Gb LPDDR2 RAM"
    assert rows[0]["_source_url"] == "https://www.ezurio.com/part/453-00137"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "ezurio_part_page_eol_status_only"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]


def test_extract_ezurio_part_eol_rows_requires_lifecycle_marker(tmp_path):
    path = tmp_path / "part_453-00137.html"
    path.write_text(
        """
        <html>
          <body>
            <h1 data-part="453-00137">453-00137</h1>
            <div class="lifecycle">Active</div>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    assert extract_ezurio_part_eol_rows(path) == []


def test_extract_kontron_product_eol_rows_imports_visible_status_only(tmp_path):
    path = tmp_path / "product_kswitch_d10_mmt_series_p170637.html"
    path.write_text(
        """
        <html>
          <head>
            <title>KSwitch D10 MMT Series</title>
            <meta property="og:url" content="https://www.kontron.com/en/products/kswitch-d10-mmt-series/p170637">
          </head>
          <body>
            <div class="eol-warning">This product is not recommended for new designs. Replacement product : RES2404-PTP More information</div>
            <h1>KSwitch D10 MMT Series</h1>
            <h2 class="h5">8-port industrial Ethernet TSN Switches</h2>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_kontron_product_eol_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "KSwitch D10 MMT Series"
    assert rows[0]["Part Number"] == "KSwitch D10 MMT Series"
    assert rows[0]["Description"] == "Network Switch"
    assert rows[0]["Replacement"] == "RES2404-PTP"
    assert rows[0]["Product ID"] == "170637"
    assert rows[0]["_source_url"] == "https://www.kontron.com/en/products/kswitch-d10-mmt-series/p170637"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "kontron_not_recommended_for_new_designs_status_only"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]


def test_extract_kontron_product_eol_rows_requires_visible_eol_warning(tmp_path):
    path = tmp_path / "product_xtremeclient_tgl_p172040.html"
    path.write_text(
        """
        <html>
          <head><title>XtremeClient-TGL</title></head>
          <body>
            <style>.product-stage:has(.eol-warning) { margin-top: 1rem; }</style>
            <h1>XtremeClient-TGL</h1>
            <p>New product</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    assert extract_kontron_product_eol_rows(path) == []


def test_extract_pepperl_fuchs_archive_rows_imports_part_number_status_only(tmp_path):
    path = tmp_path / "fieldbus_infrastructure_archive_page_1.json"
    path.write_text(
        json.dumps(
            {
                "productResponse": {
                    "response": {
                        "docs": [
                            {
                                "id": "40710",
                                "content_type_s": "product",
                                "state_s": "ARCHIVE",
                                "name_s": "Digi One<sup>&reg;</sup> IA",
                                "shortName_s": "COM Port Converter",
                                "partNumber_s": "911696",
                                "longDescription_s": (
                                    "Selectable serial interface RS 232, RS 422 "
                                    "or RS 485, 10/100 Base-T Ethernet support"
                                ),
                            },
                            {
                                "id": "40710",
                                "content_type_s": "product",
                                "state_s": "ARCHIVE",
                                "name_s": "Digi One<sup>&reg;</sup> IA",
                                "shortName_s": "COM Port Converter",
                                "partNumber_s": "911696",
                            },
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    rows = extract_pepperl_fuchs_archive_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "911696"
    assert rows[0]["Part Number"] == "911696"
    assert rows[0]["Product Name"] == "Pepperl+Fuchs Digi One IA"
    assert rows[0]["Pepperl+Fuchs Product Name"] == "Digi One IA"
    assert rows[0]["Description"] == "Serial-to-Ethernet Converter"
    assert rows[0]["Pepperl+Fuchs Product ID"] == "40710"
    assert rows[0]["_source_url"] == (
        "https://www.pepperl-fuchs.com/usa/en/classid_260.htm?view=productgroupoverview"
    )
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "pepperl_fuchs_archive_state_status_only"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]


def test_extract_pepperl_fuchs_archive_rows_requires_archive_product_identity(tmp_path):
    path = tmp_path / "surge_protection_archive.json"
    path.write_text(
        json.dumps(
            {
                "productResponse": {
                    "response": {
                        "docs": [
                            {
                                "id": "60171",
                                "content_type_s": "product",
                                "state_s": "ACTIVE",
                                "name_s": "W-ACC-SP-NF-NF",
                                "shortName_s": "Surge Protector",
                                "partNumber_s": "261328",
                            },
                            {
                                "id": "page",
                                "content_type_s": "page",
                                "state_s": "ARCHIVE",
                                "name_s": "Surge Protection",
                                "partNumber_s": "not-a-product",
                            },
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    assert extract_pepperl_fuchs_archive_rows(path) == []


def test_extract_pepperl_fuchs_archive_rows_suppresses_known_cross_source_duplicate(
    tmp_path,
):
    path = tmp_path / "surge_protection_archive.json"
    path.write_text(
        json.dumps(
            {
                "productResponse": {
                    "response": {
                        "docs": [
                            {
                                "id": "13206",
                                "content_type_s": "product",
                                "state_s": "ARCHIVE",
                                "name_s": "DP-LBF-I1.34",
                                "shortName_s": "Fieldbus Surge Protector",
                                "partNumber_s": "130018",
                            },
                            {
                                "id": "60171",
                                "content_type_s": "product",
                                "state_s": "ARCHIVE",
                                "name_s": "W-ACC-SP-NF-NF",
                                "shortName_s": "Surge Protector",
                                "partNumber_s": "261328",
                            },
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    rows = extract_pepperl_fuchs_archive_rows(path)

    assert [row["Model"] for row in rows] == ["261328"]


def test_row_to_record_skips_announcement_only_rows(tmp_path):
    class Builder:
        ROOT = tmp_path

        @staticmethod
        def make_record(**kwargs):
            return {"id": "unexpected", "dates": kwargs["dates"]}

    row = {
        "Product": "AT-100-A",
        "End-of-Sale Announcement Date": "2013-07-01",
    }

    record = row_to_record(
        builder=Builder,
        vendor_slug="keysight_ixia",
        display_name="Keysight Ixia",
        raw_file=tmp_path / "source.html",
        row=row,
        source_url="",
        source_hint="announcement-only test",
        as_of=date(2026, 6, 1),
    )

    assert record is None


def test_eos_abbreviation_does_not_override_end_of_support_header():
    row = {
        "End of Support Date (EOS)": "2031-01-13",
    }

    dates = lifecycle_dates(row)

    assert dates["end_of_sale"] is None
    assert dates["end_of_support"] == "2031-01-13"


def test_eots_abbreviation_maps_to_end_of_support():
    row = {
        "EoS": "2025-01-01",
        "EoSD": "2026-01-01",
        "EoTS": "2027-01-01",
    }

    dates = lifecycle_dates(row)

    assert dates["end_of_sale"] == "2025-01-01"
    assert dates["end_of_support"] == "2027-01-01"
    assert "end_of_software_development" not in dates


def test_end_of_life_part_number_is_preferred_over_product_family():
    row = {
        "Product Family": "1B01",
        "End-of-Life Part Number": "010-MV302-1C6",
        "End-of-Life Announcement Date": "46055",
        "End of Sale/ Last Order Date": "46236",
        "End of Service Life": "47332",
    }

    model, part_number, header = choose_model(row)

    assert model == "010-MV302-1C6"
    assert part_number == "010-MV302-1C6"
    assert header == "end of life part number"


def test_product_name_is_preferred_over_product_family():
    row = {
        "Product Family": "Access Point",
        "Product Name": "DNW-AP40",
        "EoS Date": "January 31, 2018",
        "EoL Date": "January 31, 2021",
    }

    model, part_number, header = choose_model(row)

    assert model == "DNW-AP40"
    assert part_number == "DNW-AP40"
    assert header == "product name"


def test_end_of_life_announcement_date_is_not_end_of_life():
    row = {
        "End-of-Life Announcement Date": "46055",
        "End of Sale/ Last Order Date": "46236",
        "End of Service Life": "47332",
    }

    dates = lifecycle_dates(row)

    assert dates["announcement"] == "2026-02-02"
    assert dates["end_of_life"] is None
    assert dates["end_of_sale"] == "2026-08-02"
    assert dates["end_of_service"] == "2029-08-02"


def test_end_of_sale_announcement_date_is_not_end_of_sale():
    row = {
        "End-of-Sale Announcement Date": "26-Mar-09",
        "End-of-Sale (EOS) Date": "1-Jul-09",
        "End-of-Life (EOL) Date": "31-Dec-10",
    }

    dates = lifecycle_dates(row)

    assert dates["announcement"] == "2009-03-26"
    assert dates["end_of_sale"] == "2009-07-01"
    assert dates["end_of_life"] == "2010-12-31"


def test_split_milestone_parser_preserves_rowspanned_affected_products(tmp_path):
    html = """
    <table>
      <tr>
        <th>Affected Product</th><th>Description</th>
        <th>Replacement Products</th><th>Description</th>
      </tr>
      <tr>
        <td rowspan="2">DCS-7050TX-128#<br>DCS-7050TX-128-D#</td>
        <td>Arista 7050X switch, no fans, no psu</td>
        <td rowspan="2">DCS-7050TX2-128#</td>
        <td rowspan="2">Arista 7050X2 switch</td>
      </tr>
      <tr>
        <td>Arista 7050X switch, SSD, no fans, no psu</td>
      </tr>
    </table>
    <table>
      <tr><th>Milestone</th><th>Date</th></tr>
      <tr><td>End-of-Sale Announcement</td><td>January 30th, 2017</td></tr>
      <tr><td>Last day to order the products (End-of-Sale)</td><td>July 30th, 2017</td></tr>
      <tr><td>Last day to receive software bug fixes and support</td><td>July 30th, 2019</td></tr>
      <tr><td>Last day to receive 24x7 TAC support</td><td>July 30th, 2020</td></tr>
      <tr><td>End-of-Life of product</td><td>July 30th, 2020</td></tr>
    </table>
    """
    path = tmp_path / "arista_eos.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_split_milestone_rows(path, "arista")

    assert [row["Affected Product"] for row in rows] == [
        "DCS-7050TX-128#",
        "DCS-7050TX-128-D#",
    ]
    assert all(row["Replacement Products"] == "DCS-7050TX2-128#" for row in rows)
    assert all(row["End of Sale"] == "2017-07-30" for row in rows)
    assert all(row["End of Support"] == "2019-07-30" for row in rows)
    assert all("Arista 7050X switch" not in row["Affected Product"] for row in rows)


def test_split_milestone_parser_does_not_import_rowspanned_replacements(tmp_path):
    html = """
    <table>
      <tr>
        <th>Affected Product</th><th>PID</th><th>Description</th>
        <th>Replacement Products</th><th>Replacement PID</th><th>Description</th>
      </tr>
      <tr>
        <td rowspan="2">9801A6R5</td>
        <td rowspan="2">LS-5570S-30MS-UPWR-EI-GL</td>
        <td rowspan="2">H3C S5570S switch</td>
        <td>9801A7PK</td><td>LS-5130S-24UN8X-EI-G1-V2</td>
        <td>H3C S5130S switch</td>
      </tr>
      <tr>
        <td>0235A3NQ</td><td>LS-6520X-26MC-UPWR-SI-GL</td>
        <td>H3C S6520X switch</td>
      </tr>
    </table>
    <table>
      <tr><th>Milestone</th><th>Date</th></tr>
      <tr><td>Last day to order the products (End-of-Sale)</td><td>2026-06-30</td></tr>
      <tr><td>Last day to receive software bug fixes and support</td><td>2028-06-30</td></tr>
      <tr><td>Last day to receive 24x7 TAC support</td><td>2031-06-30</td></tr>
    </table>
    """
    path = tmp_path / "h3c_eos.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_split_milestone_rows(path, "h3c")

    assert len(rows) == 1
    assert rows[0]["Affected Product"] == "9801A6R5"
    assert rows[0]["Replacement Products"] == "9801A7PK; 0235A3NQ"
    assert rows[0]["End of Sale"] == "2026-06-30"
    assert rows[0]["End of Support"] == "2028-06-30"
    assert rows[0]["End of Service"] == "2031-06-30"


def test_netgate_product_lifecycle_parser_splits_replacement_text(tmp_path):
    html = """
    <table>
      <tr>
        <th>Product Information</th><th>EOS Date</th><th>EOL Date</th>
      </tr>
      <tr>
        <td>Netgate 1537 1U<br>Replaced by: Netgate 8300 BASE</td>
        <td>2024-06-15</td><td>2027-06-15</td>
      </tr>
      <tr>
        <td>MBT-2220<br>There is no replacement product.</td>
        <td>2019-01-17</td><td>2019-09-30</td>
      </tr>
    </table>
    """
    path = tmp_path / "product_lifecycle.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_netgate_product_lifecycle_rows(path)

    assert rows[0]["Model"] == "1537 1U"
    assert rows[0]["Product Name"] == "Netgate 1537 1U"
    assert rows[0]["Replacement Products"] == "Netgate 8300 BASE"
    assert rows[0]["End of Sale"] == "2024-06-15"
    assert rows[0]["End of Life"] == "2027-06-15"
    assert rows[0]["_force_lifecycle_review"] is True
    assert "Netgate 1537 1U" in rows[0]["_aliases"]
    assert "Replaced by" not in rows[0]["Model"]
    assert rows[1]["Model"] == "MBT-2220"
    assert rows[1]["Replacement Products"] == "No replacement"


def test_stormshield_firewall_lifecycle_parser_maps_eol_to_support_end(tmp_path):
    html = """
    <table>
      <tr>
        <th>Product</th><th>Available as of</th><th>End of Sales</th>
        <th>End of Life</th><th>Lowest SNS version</th>
        <th>Highest SNS version</th>
      </tr>
      <tr>
        <td>SN160</td><td>04/01/2017</td><td>06/30/2024</td>
        <td>12/31/2028</td><td>3.1.0</td><td>4.8.x</td>
      </tr>
      <tr>
        <td>SNi40</td><td>06/01/2016</td><td>ND</td>
        <td>ND</td><td>2.3.4</td><td>ND</td>
      </tr>
    </table>
    """
    path = tmp_path / "matrices_firewalls.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_stormshield_firewall_lifecycle_rows(path)

    assert rows == [
        {
            "Model": "SN160",
            "Product Name": "Stormshield SN160",
            "Part Number": "SN160",
            "Description": "Stormshield Network Security physical firewall",
            "End of Sale": "2024-06-30",
            "End of Life": "2028-12-31",
            "End of Support": "2028-12-31",
            "End of Security Updates": "2028-12-31",
            "_source_table": "matrices_firewalls.html table 1",
            "_source_hint": "Stormshield physical firewall lifecycle matrix",
            "_review_policy": "stormshield_eol_stops_maintenance_and_support",
            "_aliases": ["SN160", "Stormshield SN160"],
            "_prefer_model": True,
        }
    ]

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2024-06-30"
    assert dates["end_of_life"] == "2028-12-31"
    assert dates["end_of_support"] == "2028-12-31"
    assert dates["end_of_vulnerability"] == "2028-12-31"


def test_glinet_eol_parser_maps_support_end_to_security_updates(tmp_path):
    html = """
    <html><head>
      <meta property="og:url" content="https://www.gl-inet.com/blog/cirrus-gl-ap1300-product-end-of-life-notice/">
    </head><body>
      <div id="blog-post-content">
        <p>We are officially announcing the End of Life (EOL) for Cirrus.</p>
        <table>
          <tr>
            <th>(EOL) Model Name</th><th>Substitute Model</th>
            <th>(EOL) Effective Datest</th><th>(EOL) Support Ends</th>
          </tr>
          <tr>
            <td>GL-AP1300</td><td>GL-X2000</td>
            <td>June 10, 2025</td><td>June 10, 2027</td>
          </tr>
        </table>
        <p>firmware updates and security patches will continue to be provided</p>
      </div>
    </body></html>
    """
    path = tmp_path / "blog_cirrus-gl-ap1300-product-end-of-life-notice.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_glinet_eol_rows(path)

    assert rows == [
        {
            "Model": "GL-AP1300",
            "Product Name": "GL-AP1300",
            "Part Number": "GL-AP1300",
            "Hardware Version": "",
            "Description": "GL.iNet router product EOL notice",
            "End of Life": "2025-06-10",
            "End of Support": "2027-06-10",
            "End of Security Updates": "2027-06-10",
            "Replacement Products": "GL-X2000",
            "_source_table": "blog_cirrus-gl-ap1300-product-end-of-life-notice.html table 1",
            "_source_hint": "GL.iNet product EOL notice",
            "_review_policy": "glinet_eol_support_end_security_firmware_updates",
            "_aliases": ["GL-AP1300"],
            "_prefer_model": True,
            "_source_url": "https://www.gl-inet.com/blog/cirrus-gl-ap1300-product-end-of-life-notice/",
        }
    ]
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_life"] == "2025-06-10"
    assert dates["end_of_support"] == "2027-06-10"
    assert dates["end_of_vulnerability"] == "2027-06-10"


def test_glinet_eol_parser_splits_grouped_models_and_versions(tmp_path):
    html = """
    <html><head>
      <meta property="article:published_time" content="2021-12-28T09:00:00+08:00">
    </head><body>
      <div id="blog-post-content">
        <p>GL.iNet is announcing an End of Life (EOL) on the following items effective now.</p>
        <p>Model Name: GL-USB150</p>
        <p>Model Names: GL-AR150, GL-AR150-Ext, GL-AR150-PoE</p>
        <p>Substitute Models: GL-AR300M16, GL-MT300N-V2</p>
        <p>The firmware of the abovementioned EOL products will still be maintained
        and supported for 2 years (until December 31st, 2023).</p>
      </div>
    </body></html>
    """
    path = tmp_path / "blog_products-end-of-life-eol-notice-20211228.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_glinet_eol_rows(path)

    assert [row["Model"] for row in rows] == [
        "GL-USB150",
        "GL-AR150",
        "GL-AR150-Ext",
        "GL-AR150-PoE",
    ]
    assert all(row["End of Life"] == "2021-12-28" for row in rows)
    assert all(row["End of Support"] == "2023-12-31" for row in rows)
    assert rows[1]["Replacement Products"] == "GL-AR300M16, GL-MT300N-V2"


def test_glinet_eol_parser_preserves_variant_scope(tmp_path):
    html = """
    <html><body>
      <h1>Granular Software Release EOL Timelines and Support Matrix</h1>
      <div id="blog-post-content">
        <p>End of Life (EOL) for the Mudi (GL-E750V2) with vSIM version only.</p>
        <p>Model Name: Mudi (GL-E750V2) with vSIM Technology</p>
        <p>EOL Effective Date: April 29, 2025</p>
        <p>Support End Date: April 29, 2027 (security updates and firmware upgrades will continue through this period)</p>
      </div>
    </body></html>
    """
    path = tmp_path / "blog_mudi-e750v2-with-vsim-techonology-product-end-of-life-notice.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_glinet_eol_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "GL-E750V2"
    assert rows[0]["Product Name"] == "Mudi (GL-E750V2) with vSIM Technology"
    assert rows[0]["Hardware Version"] == "vSIM Technology"
    assert rows[0]["End of Support"] == "2027-04-29"


def test_inhand_networks_eol_parser_maps_ordering_and_support_dates(tmp_path):
    html = """
    <table>
      <tr>
        <th>EOL Product</th><th>Replacement</th>
        <th>End of Ordering</th><th>End of Production</th>
        <th>End of Support</th>
      </tr>
      <tr>
        <td>IR611-S</td><td>IR302/IR315</td>
        <td>4/1/2021</td><td>12/1/2021</td><td>4/1/2026</td>
      </tr>
    </table>
    """
    path = tmp_path / "inhand_networks_eol_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_inhand_networks_eol_rows(path)

    assert rows == [
        {
            "Model": "IR611-S",
            "Product Name": "IR611-S",
            "Part Number": "IR611-S",
            "Description": "InHand Networks EOL product",
            "End of Sale": "2021-04-01",
            "End of Support": "2026-04-01",
            "End of Security Updates": "2026-04-01",
            "Replacement Products": "IR302/IR315",
            "_source_table": "inhand_networks_eol_products.html table 1",
            "_source_hint": "InHand Networks EOL products table",
            "_source_url": "https://www.inhand.com/en/support/eol-products/",
            "_review_policy": "inhand_end_of_support_marks_support_end",
            "_aliases": ["IR611-S"],
            "_prefer_model": True,
        }
    ]
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2021-04-01"
    assert dates["end_of_life"] is None
    assert dates["end_of_support"] == "2026-04-01"
    assert dates["end_of_vulnerability"] == "2026-04-01"


def test_netmodule_eol_parser_skips_broad_rows_and_maps_support_repair(tmp_path):
    html = """
    <table>
      <tr>
        <th>Product</th><th>Product Discontinuation Notice</th>
        <th>End of Support and repair</th>
      </tr>
      <tr>
        <td>NB2700</td><td>pdn_nb2700_20220401.pdf</td>
        <td>March 1, 2025</td>
      </tr>
      <tr>
        <td>UMTS/3G only products</td><td>pdn-umts.pdf</td>
        <td>August 31, 2017</td>
      </tr>
    </table>
    """
    path = tmp_path / "netmodule_end_of_life.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_netmodule_eol_rows(path)

    assert rows == [
        {
            "Model": "NB2700",
            "Product Name": "NB2700",
            "Part Number": "NB2700",
            "Description": "NetModule end-of-life product",
            "End of Support": "2025-03-01",
            "End of Security Updates": "2025-03-01",
            "_source_table": "netmodule_end_of_life.html table 1",
            "_source_hint": "NetModule End of Life products table",
            "_source_url": "https://wiki.netmodule.com/documentation/end-of-life",
            "_review_policy": "netmodule_end_of_support_and_repair_marks_support_end",
            "_aliases": ["NB2700"],
            "_prefer_model": True,
            "Product Discontinuation Notice": "pdn_nb2700_20220401.pdf",
        }
    ]
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_support"] == "2025-03-01"
    assert dates["end_of_vulnerability"] == "2025-03-01"


def test_zte_lifecycle_parser_maps_eom_and_eos_terms(tmp_path):
    html = """
    <table>
      <tr><td>outer shell</td></tr>
      <tr><td>
        <table>
          <tr>
            <td>Product</td><td>EOM</td><td>LTBSP</td><td>EOS</td><td>Substitutes</td>
          </tr>
          <tr>
            <td>ZX R10 29 10E-PS</td><td>Jul . 1 0,202 4</td>
            <td>Oct . 30,202 4</td><td>Dec. 30,202 6</td>
            <td>ZX R 10 5260-S Series</td>
          </tr>
        </table>
      </td></tr>
    </table>
    """
    path = tmp_path / "eom_eol_notice_1035984.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_zte_lifecycle_rows(path)

    assert rows == [
        {
            "Model": "ZXR10 2910E-PS",
            "Product Name": "ZXR10 2910E-PS",
            "Part Number": "ZXR10 2910E-PS",
            "Description": "ZTE product lifecycle notice",
            "End of Sale": "2024-07-10",
            "Last Time Buy of Spare Parts": "2024-10-30",
            "End of Service": "2026-12-30",
            "End of Security Updates": "2026-12-30",
            "Replacement Products": "ZXR10 5260-S Series",
            "_source_table": "eom_eol_notice_1035984.html table 2",
            "_source_hint": "ZTE product lifecycle notice table",
            "_review_policy": "zte_eom_market_eos_service_support",
            "_aliases": ["ZXR10 2910E-PS", "ZTE ZXR10 2910E-PS"],
            "_prefer_model": True,
            "_source_url": "https://support.zte.com.cn/support/news/NewsDetail.aspx?newsId=1035984",
        }
    ]
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2024-07-10"
    assert dates["end_of_service"] == "2026-12-30"
    assert dates["end_of_vulnerability"] == "2026-12-30"
    assert dates["end_of_support"] is None


def test_zte_lifecycle_parser_splits_grouped_models_and_keeps_eofs_separate(tmp_path):
    html = """
    <p>Notice:EOM Announcement for ZTE ZXR10 5916E\u30015928E</p>
    <table>
      <tr><td>Product</td><td>EOM</td><td>EOFS</td><td>EOS</td></tr>
      <tr>
        <td>5916E\u30015928E</td><td>2021.9.2</td>
        <td>Mar . 15 , 202 3</td><td>Aug. 1 5 , 202 3</td>
      </tr>
    </table>
    """
    path = tmp_path / "eom_eol_notice_1018624.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_zte_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == ["5916E", "5928E"]
    assert all(row["End of Sale"] == "2021-09-02" for row in rows)
    assert all(row["End of Security Updates"] == "2023-03-15" for row in rows)
    assert all(row["End of Service"] == "2023-08-15" for row in rows)
    assert rows[0]["_aliases"] == ["5916E", "ZTE 5916E", "ZXR10 5916E"]


def test_zte_lifecycle_parser_treats_planned_eos_as_review_only(tmp_path):
    html = """
    <table>
      <tr><td>Product</td><td>EOM</td><td>LTBSP</td><td>EOS\uff08Plan\uff09</td></tr>
      <tr><td>ZXUN DSC V4</td><td>Sep.30, 202 2</td><td>Jun. 30, 202 4</td><td>Jun. 30, 202 6</td></tr>
    </table>
    """
    path = tmp_path / "eom_eol_notice_1024984.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_zte_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["End of Sale"] == "2022-09-30"
    assert rows[0]["Last Time Buy of Spare Parts"] == "2024-06-30"
    assert rows[0]["Planned EOS"] == "2026-06-30"
    assert rows[0]["_force_lifecycle_review"] is True
    assert "End of Service" not in rows[0]
    assert "End of Security Updates" not in rows[0]


def test_multitech_eol_date_maps_to_sales_end_only(tmp_path):
    html = """
    <table>
      <tr>
        <th>Tradename</th><th>Ordering Part #</th><th>MultiTech P/N</th>
        <th>NRND</th><th>NEOL</th><th>EOL DATE</th>
        <th>Replacement Model Number</th><th>Replacement 9-level</th>
      </tr>
      <tr>
        <td>MultiConnect OCG-E</td><td>MT100EOCG-H4-GP-P1</td>
        <td>94456359LF</td><td>X</td><td>08/03/2012</td>
        <td>02/27/2013</td><td>Contact MultiTech</td><td></td>
      </tr>
    </table>
    """
    path = tmp_path / "multitech_eol_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_multitech_eol_product_rows(path)

    assert rows == [
        {
            "Tradename": "MultiConnect OCG-E",
            "Ordering Part #": "MT100EOCG-H4-GP-P1",
            "MultiTech P/N": "94456359LF",
            "Announcement": "08/03/2012",
            "End of Sale": "02/27/2013",
            "Replacement Model Number": "Contact MultiTech",
            "Replacement 9-level": "",
            "_source_table": "multitech_eol_products.html table 1",
            "_source_hint": "MultiTech lifecycle products table",
            "_review_policy": "multitech_eol_date_is_sales_end_not_security_eol",
        }
    ]

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2012-08-03"
    assert dates["end_of_sale"] == "2013-02-27"
    assert dates["end_of_life"] is None
    assert dates["end_of_support"] is None


def test_sangoma_support_end_maps_to_end_of_support(tmp_path):
    html = """
    <table>
      <tr>
        <th>Product Name</th><th>SKU</th><th>Category</th>
        <th>Effective Date</th><th>Support End</th>
        <th>Replacement Product</th><th>Replacement SKU</th>
        <th>Added to EOL</th><th>Detailed Information</th>
      </tr>
      <tr>
        <td>SmartOffice Gateway Kit</td><td>1SMR001LF</td>
        <td>Access Control</td><td>3/30/2023</td>
        <td>3/30/2024</td><td>N/A</td><td>N/A</td>
        <td>3/17/2023</td><td></td>
      </tr>
    </table>
    """
    path = tmp_path / "end_of_life_eol.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_sangoma_eol_rows(path)

    assert rows == [
        {
            "Product Name": "SmartOffice Gateway Kit",
            "SKU": "1SMR001LF",
            "Category": "Access Control",
            "End of Life": "3/30/2023",
            "End of Support": "3/30/2024",
            "Announcement": "3/17/2023",
            "Replacement Product": "N/A",
            "Replacement SKU": "N/A",
            "Detailed Information": "",
            "_source_table": "end_of_life_eol.html table 1",
            "_source_hint": "Sangoma End-Of-Life table",
            "_review_policy": "sangoma_eol_effective_date_with_support_end",
        }
    ]

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2023-03-17"
    assert dates["end_of_life"] == "2023-03-30"
    assert dates["end_of_support"] == "2024-03-30"


def test_clavister_end_of_sales_parser_splits_replacement_text(tmp_path):
    html = """
    <table>
      <tr>
        <th>Hardware Products</th><th>End of sales date</th>
        <th>End of life date</th>
      </tr>
      <tr>
        <td>Clavister NetWall W30 Series
        The designated replacement product is Clavister NetWall 500 or 6000 Series.</td>
        <td>2022-06-30</td><td>2025-06-30</td>
      </tr>
    </table>
    <table>
      <tr>
        <th>Software and services</th><th>End of sales date</th>
        <th>End of life date</th>
      </tr>
      <tr>
        <td>Clavister EasyAccess</td><td>2022-07-06</td>
        <td>2025-07-06 or until license expiration</td>
      </tr>
    </table>
    """
    path = tmp_path / "end_of_sales.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_clavister_end_of_sales_rows(path)

    assert rows == [
        {
            "Product Name": "Clavister NetWall W30 Series",
            "End of Sale": "2022-06-30",
            "End of Life": "2025-06-30",
            "Replacement Product": "Clavister NetWall 500 or 6000 Series",
            "Description": "Hardware product",
            "_source_table": "end_of_sales.html table 1",
            "_source_hint": "Clavister End-of-Sales table",
            "_review_policy": "clavister_eos_supported_until_eol",
        },
        {
            "Product Name": "Clavister EasyAccess",
            "End of Sale": "2022-07-06",
            "End of Life": "2025-07-06",
            "Replacement Product": "",
            "Description": "Software or service",
            "_source_table": "end_of_sales.html table 2",
            "_source_hint": "Clavister End-of-Sales table",
            "_review_policy": "clavister_eos_supported_until_eol",
        },
    ]


def test_2n_final_order_and_support_parser(tmp_path):
    html = """
    <table>
      <tr>
        <th>Discontinued Product</th><th>Order Number</th>
        <th>Replacement Product</th><th>Replacement Order Number</th>
        <th>Final Order Date</th><th>Final Support Date</th>
      </tr>
      <tr>
        <td>2N EasyGate Pro</td><td>501332E</td>
        <td>2N EasyGate IP</td><td>5023011E</td>
        <td>30.05.2025</td><td>30.05.2031</td>
      </tr>
    </table>
    """
    path = tmp_path / "news_easygate_pro_gsm_discontinued_en_us.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_2n_discontinued_rows(path)

    assert rows == [
        {
            "Product Name": "2N EasyGate Pro",
            "Part Number": "501332E",
            "End of Sale": "2025-05-30",
            "End of Support": "2031-05-30",
            "Replacement Products": "2N EasyGate IP (5023011E)",
            "Product Status": "discontinued product",
            "_source_table": "news_easygate_pro_gsm_discontinued_en_us.html table 1",
            "_source_hint": "2N discontinued product table",
            "_review_policy": "2n_final_order_is_sales_end_final_support_is_support_end",
            "_prefer_model": True,
        }
    ]

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2025-05-30"
    assert dates["end_of_support"] == "2031-05-30"


def test_2n_discontinuation_date_is_sales_end_not_support_end(tmp_path):
    html = """
    <p>Discontinuation date in the AMER and APAC regions: March 31, 2025</p>
    <p>The discontinuation date is the planned final date that the product/s can be ordered.</p>
    <table>
      <tr><th>Discontinued Product</th><th>Replacement Product</th></tr>
      <tr>
        <td>2N Indoor Touch 2.0 Black [01668-001]</td>
        <td>2N Indoor View Black [02087-001]</td>
      </tr>
    </table>
    """
    path = tmp_path / "news_indoor_touch_2_0_discontinued_en_us.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_2n_discontinued_rows(path)

    assert rows[0]["Product Name"] == "2N Indoor Touch 2.0 Black"
    assert rows[0]["Part Number"] == "01668-001"
    assert rows[0]["End of Sale"] == "2025-03-31"
    assert rows[0]["End of Support"] == ""
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2025-03-31"
    assert dates["end_of_support"] is None


def test_2n_discontinued_without_dates_requires_lifecycle_review(tmp_path):
    html = """
    <table>
      <tr>
        <th>End of Life Order Number</th><th>Discontinued Product</th>
        <th>Replacement Order Number</th><th>Replacement Product</th>
      </tr>
      <tr>
        <td>9151101CW</td><td>2N IP Force - 1 Button, Camera</td>
        <td>9151101CHW</td><td>2N IP Force - 1 Button, HD Camera</td>
      </tr>
    </table>
    """
    path = tmp_path / "news_ip_force_sd_camera_versions_discontinued_en_gb.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_2n_discontinued_rows(path)

    assert rows[0]["Part Number"] == "9151101CW"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "2n_discontinued_no_exact_support_date"


def test_threeonedata_discontinued_list_imports_exact_models_as_review(tmp_path):
    html = """
    <html>
      <body>
        <table>
          <tr><th>SERIES / PRODUCT</th><th>NOTES / COMMENTS</th><th>DATE</th></tr>
          <tr>
            <td><a download="EOL announcement for SW485GI V1.0.0 series.pdf">
              EOL announcement for SW485GI V1.0.0 series.pdf</a></td>
            <td>NO LONGER MANUFACTURED</td>
            <td>06/30/2025</td>
          </tr>
          <tr>
            <td><a download="EOL announcement for USB converters">
              EOL announcement for USB converters</a></td>
            <td>NO LONGER MANUFACTURED</td>
            <td>01/03/2024</td>
          </tr>
          <tr>
            <td><a download="Product End-of-Life Notice during June,2023">
              Product End-of-Life Notice during June,2023</a></td>
            <td>NO LONGER MANUFACTURED</td>
            <td>06/28/2023</td>
          </tr>
          <tr>
            <td><a download="IES618 Series V1.0.pdf">IES618 Series V1.0.pdf</a></td>
            <td>NO LONGER MANUFACTURED</td>
            <td>06/28/2023</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "discontinued_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_threeonedata_discontinued_rows(path)

    assert [row["Model"] for row in rows] == [
        "SW485GI V1.0.0 series",
        "IES618 Series V1.0",
    ]
    assert rows[0]["Announcement Date"] == "2025-06-30"
    assert rows[0]["Product Status"] == "No longer manufactured"
    assert rows[0]["_status_only_review"] is True
    assert (
        rows[0]["_review_policy"]
        == "threeonedata_no_longer_manufactured_not_security_eol"
    )

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2025-06-30"
    assert dates["end_of_sale"] is None
    assert dates["end_of_support"] is None


def test_kramer_product_page_imports_model_eol_as_review(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical" href="https://www1.kramerav.com/product/sl-280" />
      </head>
      <body>
        <h1>SL-280</h1>
        <p class="subTitle">32-Port Master / Room Controller</p>
        <nav id="product_quick_facts_section">
          <span>Supported by Kramer Control</span>
          <span>The SL-280 has reached end-of-life status. This product should ONLY be used as a control gateway in existing installations. For all new deployments, please transition to KC-Virtual Brain1 or KC-Virtual Brain5</span>
        </nav>
        <div class="price-block">
          <span class="note">
            Supply is limited. This item will be discontinued when global inventory is depleted. Replaced by:
            <a href="/product/kc-virtual-brain1">KC-Virtual Brain1</a>
          </span>
        </div>
      </body>
    </html>
    """
    path = tmp_path / "product_sl-280.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_kramer_product_eol_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "SL-280"
    assert rows[0]["Part Number"] == "SL-280"
    assert rows[0]["Description"] == "32-Port Master / Room Controller"
    assert rows[0]["Replacement Products"] == "KC-Virtual Brain1"
    assert rows[0]["_source_url"] == "https://www1.kramerav.com/product/sl-280"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "kramer_product_eol_not_security_eol"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]


def test_iei_networking_eol_cards_import_as_review_only(tmp_path):
    html = """
    <html>
      <head>
        <meta property="og:url" content="https://www.ieiworld.com/en/product/eol_list.php?CA=2" />
      </head>
      <body>
        <h1>Networking and Servers | End of Life</h1>
        <div class="card__content">
          <h2>PUZZLE-M901</h2>
          <div class="eol__tag">End of Life</div>
          <p class="card__description">OpenWrt Network Appliance with Marvell processor</p>
          <a href="./model.php?II=747" class="btn__product btn__base">View Product</a>
        </div>
        <div class="card__content">
          <h2>PULM-10G4SF-MLX</h2>
          <div class="eol__tag">End of Life</div>
          <img class="card__img" alt="Mellanox based Network Interface Card">
        </div>
      </body>
    </html>
    """
    path = tmp_path / "eol_list_ca_2_networking_and_servers.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_iei_networking_eol_rows(path)

    assert [row["Model"] for row in rows] == ["PUZZLE-M901", "PULM-10G4SF-MLX"]
    assert rows[0]["Description"] == "OpenWrt Network Appliance with Marvell processor"
    assert rows[1]["Description"] == "Mellanox based Network Interface Card"
    assert rows[0]["Product Status"] == "End of Life"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "iei_eol_list_not_security_eol"
    assert rows[0]["_source_url"] == "https://www.ieiworld.com/en/product/eol_list.php?CA=2"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]


def test_lantronix_discontinued_products_table_maps_eol_date_to_sales_end(tmp_path):
    html = """
    <html>
      <body>
        <table>
          <tr><th>Product</th></tr>
          <tr><td>Navigation shell</td></tr>
        </table>
        <table>
          <tr>
            <th>Date of EOL</th><th>Name</th><th>SKU</th>
            <th>Replacement Part</th><th>Current Alternatives</th>
            <th>Resources</th><th>EOL Notice</th>
          </tr>
          <tr>
            <td>Jun 30, 2026</td><td>SGX5150000ES</td><td>SGX5150000ES</td>
            <td>SGX 5150</td><td>--</td><td>View Files</td>
            <td>
              <a href="https://cdn.lantronix.com/wp-content/uploads/pdf/PCN-887.pdf">
                PCN-887 SGX5150 product discontinuation notice
              </a>
            </td>
          </tr>
          <tr>
            <td>Nov 22, 2025</td><td>TN-CWDM-SFP-1310</td>
            <td>TN-CWDM-SFP-1310</td><td>Not Available</td>
            <td>Network Switches</td><td>View Files</td>
            <td>PCN-958 Product Discontinuation Notice</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "nhedb__raw__discontinued-products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_lantronix_discontinued_product_rows(path)

    assert [row["Model"] for row in rows] == ["SGX5150000ES", "TN-CWDM-SFP-1310"]
    assert rows[0]["End of Sale"] == "2026-06-30"
    assert rows[0]["Lantronix Lifecycle Phase"] == "End of Sale"
    assert rows[0]["Replacement Products"] == "SGX 5150"
    assert rows[0]["_source_url"] == "https://cdn.lantronix.com/wp-content/uploads/pdf/PCN-887.pdf"
    assert rows[0]["_source_hint"] == "Lantronix product lifecycle date table import"
    assert rows[0]["_replace_existing_raw_record"] is True
    assert rows[0]["_review_policy"] == (
        "lantronix_eol_date_is_end_of_sale_not_security_eol"
    )
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]
    assert lifecycle_dates(rows[0])["end_of_sale"] == "2026-06-30"
    assert rows[1]["Replacement Products"] == "Network Switches"
    assert "network SFP transceiver" in rows[1]["Description"]


def test_arbor_eol_template_imports_last_shipment_as_sale_only(tmp_path):
    html = """
    <html>
      <body>
        <p>The products listed below have reached End-of-Life (EOL) status.</p>
        <p>The EOL date corresponds to the last shipping date. For timely
        orders, please contact customer service at least three months in
        advance.</p>
        <template class="b-product-list__group-data">
          <tr>
            <td><span class="b-eol__data-title-txt">LYNC-715-1900G4</span></td>
            <td><span class="b-eol__data-alternativeProducts-txt">LYNC-715-7433G8</span></td>
            <td><span class="b-eol__data-date-txt">2025-11-11</span></td>
          </tr>
          <tr>
            <td><span class="b-eol__data-title-txt">PBC-900J</span></td>
            <td><span class="b-eol__data-alternativeProducts-txt"></span></td>
            <td><span class="b-eol__data-date-txt">2025-05-08</span></td>
          </tr>
        </template>
      </body>
    </html>
    """
    path = tmp_path / "end_of_life_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_arbor_eol_product_rows(path)

    assert [row["Model"] for row in rows] == ["LYNC-715-1900G4", "PBC-900J"]
    assert rows[0]["End of Sale"] == "2025-11-11"
    assert rows[0]["Last Sale"] == "2025-11-11"
    assert rows[0]["Replacement Products"] == "LYNC-715-7433G8"
    assert rows[0]["Description"] == "Industrial panel PC"
    assert rows[0]["Product Status"] == "Last shipping date published by ARBOR"
    assert rows[0]["_review_policy"] == (
        "arbor_eol_date_is_last_shipping_date_not_security_eol"
    )
    assert "_force_lifecycle_review" not in rows[0]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]
    assert lifecycle_dates(rows[0])["end_of_sale"] == "2025-11-11"
    assert lifecycle_dates(rows[0])["last_sale"] == "2025-11-11"
    assert "Replacement Products" not in rows[1]
    assert rows[1]["Description"] == "Industrial embedded board computer"
    assert extract_rows(path, "arbor_technology") == rows


def test_arbor_eol_template_requires_last_shipping_definition(tmp_path):
    html = """
    <html>
      <body>
        <template class="b-product-list__group-data">
          <tr>
            <td><span class="b-eol__data-title-txt">LYNC-715-1900G4</span></td>
            <td><span class="b-eol__data-date-txt">2025-11-11</span></td>
          </tr>
        </template>
      </body>
    </html>
    """
    path = tmp_path / "end_of_life_products.html"
    path.write_text(html, encoding="utf-8")

    assert extract_arbor_eol_product_rows(path) == []


def test_epiphan_pearl_eol_notice_imports_as_lifecycle_review(tmp_path):
    html = """
    <html><body>
      <h1>Pearl-2 support</h1>
      <p>How does Pearl-2 differ from Pearl?</p>
      <p>Notice: Pearl has officially reached its end of life and is
      discontinued. However, firmware updates continue to be made available for
      the Pearl models.</p>
      <p>Free firmware updates are accessible for any device paired to an
      Epiphan Edge team, or through the local admin UI on your device.</p>
    </body></html>
    """
    path = tmp_path / "epiphan_pearl_2_support_page.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_epiphan_pearl_status_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "Pearl"
    assert rows[0]["Product Name"] == "Epiphan Pearl"
    assert rows[0]["Description"] == "Network video encoder"
    assert rows[0]["Product Status"] == (
        "End of life and discontinued; firmware updates continue"
    )
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == (
        "epiphan_pearl_eol_firmware_updates_continue"
    )
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]
    assert extract_rows(path, "epiphan_video") == rows


def test_epiphan_pearl_eol_notice_requires_firmware_update_context(tmp_path):
    html = """
    <html><body>
      <p>Notice: Pearl has officially reached its end of life and is
      discontinued.</p>
    </body></html>
    """
    path = tmp_path / "epiphan_pearl_2_support_page.html"
    path.write_text(html, encoding="utf-8")

    assert extract_epiphan_pearl_status_rows(path) == []


def test_idirectgov_pdf_parser_imports_exact_eol_eos_rows():
    text = """
End of Life Reference Guide
Purpose
This purpose of this document is to inform iDirect Government's customers of the
end of life (EOL) and end of support (EOS: End of Life + 3 years) dates for
iDirect hardware products.
For a period of three years following the End of Life Date, iDirect Government
shall continue to offer Technical Support.

Hub Equipment
          Hub Chassis and Private
                                             EOL Date           EOS Date
                  Hubs
        Concentrator                           September 1,     September 1, 2015
                                                        2012
        Series 12100 Universal 4-Slot          May 31, 2017         May 31, 2020
        Hub; Model 12101

Miscellaneous
               Description                EOL Date            EOS Date
        Web Services Toolkit/iToolkit   November 1, 2010     Not supported after
                                                                 release iDX 2.1
        iDS Software                    December 31, 2015   December 31,
                                                               2018
"""

    rows = parse_idirectgov_pdf_rows_from_text(
        text,
        "idirectgov_eol_reference_guide_2025_07_15.pdf",
    )

    by_model = {row["Model"]: row for row in rows}
    assert by_model["Concentrator"]["End of Life"] == "2012-09-01"
    assert by_model["Concentrator"]["End of Support"] == "2015-09-01"
    assert by_model["Concentrator"]["_review_policy"] == (
        "idirectgov_eos_is_end_of_support"
    )
    assert by_model["Series 12100 Universal 4-Slot Hub; Model 12101"][
        "Description"
    ] == "Satellite hub"
    assert by_model["iDS Software"]["End of Support"] == "2018-12-31"
    assert by_model["iDS Software"]["Description"] == "Software"
    assert "Web Services Toolkit/iToolkit" not in by_model
    assert "End of Sale" not in by_model["Concentrator"]


def test_idirectgov_pdf_parser_requires_policy_context():
    text = """
End of Life Reference Guide
Hub Equipment
        Concentrator                           September 1,     September 1, 2015
                                                        2012
"""

    assert parse_idirectgov_pdf_rows_from_text(text, "idirectgov.pdf") == []


def test_netapp_software_version_support_json_imports_update_and_support_dates(tmp_path):
    html = """
    <html><body>
      <p>Full Support includes Service Updates (P-releases) and security
      vulnerability evaluation.</p>
      <p>Limited Support continues technical support. Service Updates
      (including any form of software update) are not provided for versions
      under limited support.</p>
      <p>End of Engineering Support marks the end of Full Support. End of
      Version Support marks the end of Limited Support.</p>
      <table>
        <tr>
          <th>Product</th>
          <th>Version</th>
          <th>End of Full Support</th>
          <th>End of Limited Support</th>
          <th>End of Self-Service Support</th>
        </tr>
        <tr>
          <td>ONTAP</td>
          <td>9.13.1</td>
          <td>30-Jun-2026</td>
          <td>30-Jun-2028</td>
          <td>30-Jun-2031</td>
        </tr>
        <tr>
          <td>9.12.1</td>
          <td>28-Feb-2026</td>
          <td>28-Feb-2028</td>
          <td>28-Feb-2031</td>
        </tr>
        <tr>
          <td>9.99.1</td>
          <td>TBD</td>
          <td>TBD</td>
          <td>TBD</td>
        </tr>
      </table>
      <table>
        <tr>
          <th>Product</th>
          <th>Packs</th>
          <th>Version</th>
          <th>End of Engineering Support</th>
          <th>End of Version Support</th>
        </tr>
        <tr>
          <td>Automation Store Packs</td>
          <td>WFA pack for managing vCenter</td>
          <td>1.0.1</td>
          <td>21-Jan-22</td>
          <td>8-Feb-22</td>
        </tr>
      </table>
    </body></html>
    """
    path = tmp_path / "software_version_support.json"
    path.write_text(json.dumps({"localizedContent": html}), encoding="utf-8")

    rows = extract_netapp_software_version_support_rows(path)

    assert [row["Part Number"] for row in rows] == [
        "ONTAP 9.13.1",
        "ONTAP 9.12.1",
        "WFA pack for managing vCenter 1.0.1",
    ]
    assert rows[0]["Model"] == "ONTAP"
    assert rows[0]["Version"] == "9.13.1"
    assert rows[0]["End of Security Updates"] == "2026-06-30"
    assert rows[0]["End of Support"] == "2028-06-30"
    assert rows[0]["End of Service"] == "2031-06-30"
    assert rows[0]["_end_of_security_updates_override"] == "2026-06-30"
    assert rows[0]["_review_policy"] == (
        "netapp_full_support_end_is_service_update_end"
    )
    assert lifecycle_dates(rows[0])["end_of_vulnerability"] == "2026-06-30"
    assert lifecycle_dates(rows[0])["end_of_support"] == "2028-06-30"
    assert rows[1]["Model"] == "ONTAP"
    assert rows[1]["Version"] == "9.12.1"
    assert rows[2]["Model"] == "WFA pack for managing vCenter"
    assert rows[2]["End of Security Updates"] == "2022-01-21"
    assert rows[2]["End of Support"] == "2022-02-08"
    assert extract_rows(path, "netapp") == rows


def test_netapp_software_version_support_requires_definitions(tmp_path):
    path = tmp_path / "software_version_support.json"
    path.write_text(
        json.dumps(
            {
                "localizedContent": """
                <table>
                  <tr>
                    <th>Product</th><th>Version</th>
                    <th>End of Full Support</th>
                    <th>End of Version Support</th>
                  </tr>
                  <tr>
                    <td>ONTAP</td><td>9.13.1</td>
                    <td>30-Jun-2026</td><td>30-Jun-2028</td>
                  </tr>
                </table>
                """
            }
        ),
        encoding="utf-8",
    )

    assert extract_netapp_software_version_support_rows(path) == []


def test_row_to_record_preserves_netapp_security_update_end_before_support_end(tmp_path):
    class FakeBuilder:
        ROOT = tmp_path

        @staticmethod
        def normalize_lookup_key(value):
            return str(value or "").lower().replace(" ", "-")

        @staticmethod
        def make_record(**kwargs):
            dates = dict(kwargs["dates"])
            dates["end_of_security_updates"] = (
                dates.get("end_of_support")
                or dates.get("end_of_vulnerability")
                or dates.get("end_of_service")
            )
            return {
                "id": "hw_netapp_ontap",
                "vendor": "NetApp",
                "vendor_slug": kwargs["vendor_slug"],
                "model": kwargs["model"],
                "model_key": kwargs["model"].lower(),
                "part_number": kwargs["part_number"],
                "device_class": "software",
                "dates": dates,
                "lifecycle": {
                    "status": "supported",
                    "receives_security_updates": True,
                },
                "source": {
                    "source_hint": kwargs["source_hint"],
                    "raw_file": str(kwargs["raw_file"].relative_to(tmp_path)),
                },
                "netwatch": {
                    "match_priority": 1,
                    "finding_title": "old title",
                },
            }

        @staticmethod
        def classify_lifecycle(**kwargs):
            security_date = kwargs["dates"]["end_of_security_updates"]
            return {
                "status": "unsupported" if security_date == "2026-01-31" else "supported",
                "receives_security_updates": security_date != "2026-01-31",
            }

        @staticmethod
        def match_priority(device_class, lifecycle_status):
            return 77 if lifecycle_status == "unsupported" else 10

        @staticmethod
        def build_finding_title(vendor, model, lifecycle):
            return f"{vendor} {model} {lifecycle['status']}"

    raw_file = tmp_path / "software_version_support.json"
    raw_file.write_text("{}", encoding="utf-8")
    row = {
        "Model": "ONTAP",
        "Part Number": "ONTAP 9.10.1",
        "Product Name": "ONTAP 9.10.1",
        "Description": "Storage operating system software",
        "Product Status": "software/service updates end 2026-01-31",
        "Version": "9.10.1",
        "End of Security Updates": "2026-01-31",
        "End of Support": "2031-01-31",
        "_end_of_security_updates_override": "2026-01-31",
        "_review_policy": "netapp_full_support_end_is_service_update_end",
        "_prefer_model": True,
    }

    record = row_to_record(
        builder=FakeBuilder(),
        vendor_slug="netapp",
        display_name="NetApp",
        raw_file=raw_file,
        row=row,
        source_url="https://mysupport.netapp.com/site/info/version-support",
        source_hint="NetApp software version support table import",
        as_of=date(2026, 6, 2),
    )

    assert record["dates"]["end_of_security_updates"] == "2026-01-31"
    assert record["dates"]["end_of_support"] == "2031-01-31"
    assert record["lifecycle"]["status"] == "unsupported"
    assert record["lifecycle"]["receives_security_updates"] is False
    assert record["sunsetscan"]["match_priority"] == 77
    assert record["sunsetscan"]["finding_title"] == "NetApp ONTAP unsupported"
    assert record["quality"]["interpretation_policy"] == (
        "netapp_full_support_end_is_service_update_end"
    )
    assert record["quality"]["previous_lifecycle"]["status"] == "supported"
    assert record["quality"]["review_required"] is True


def test_sierra_airlink_rv50x_pdf_maps_software_maintenance_to_security_end():
    layout_text = """
AirLink® End of Sale Announcement: AirLink RV50X

OVERVIEW
DATE ISSUED:           24-Jul-2025
PRODUCTS AFFECTED:     AirLink® RV50X Routers

PRODUCTION MILESTONES
AFFECTED MODELS:        All AirLink® RV50X Routers.
LAST TIME BUY:          31-Dec-2025: The last date that purchase orders will be accepted by Semtech.
LAST TIME SHIP:         30-Jun-2026: The last ship date that can be requested from Semtech.

PRODUCT SUPPORT AND MAINTENANCE
ACTIVE SOFTWARE         From 30-Jun-2026 TO 30-Jun-2027: During this phase router software will
MAINTENANCE PHASE:      be actively maintained. Software releases will contain bug fixes and
                        security patches only; no new features will be deployed.
END OF SOFTWARE         30-Jun-2029: No new router software will be released after this date.
MAINTENANCE:

AFFECTED PART NUMBERS
 Part No.              RV50X Router Description                                                     Suggested Replacements
 1103045               RV50X, 4G LTE-A Router, APAC, includes 1-year AirLink Complete
                       RV50X, 4G LTE-A Router, North America & EMEA, includes 1-year                See Suggested Router
 1103052
                       AirLink Complete                                                             Replacements below
 1103973               RV50X, 4G LTE-A Router, China, includes 1-year AirLink Complete

SUGGESTED ROUTER REPLACEMENTS
"""
    raw_text = """
AirLink®
End of Sale Announcement: AirLink RV50X
PRODUCTION MILESTONES
AFFECTED MODELS: All AirLink® RV50X Routers.
LAST TIME BUY: 31-Dec-2025: The last date that purchase orders will be accepted by
PRODUCT SUPPORT AND MAINTENANCE
END OF SOFTWARE
MAINTENANCE:
30-Jun-2029: No new router software will be released after this date.
AFFECTED PART NUMBERS
Part No. RV50X Router Description Suggested Replacements
1103045 RV50X, 4G LTE-A Router, APAC, includes 1-year AirLink Complete
See Suggested Router
Replacements below
1103052
RV50X, 4G LTE-A Router, North America & EMEA, includes 1-year
AirLink Complete
1103973 RV50X, 4G LTE-A Router, China, includes 1-year AirLink Complete
SUGGESTED ROUTER REPLACEMENTS
"""

    rows = parse_sierra_airlink_pdf_rows_from_text(
        layout_text,
        "airlink_rv50x_eos__rv50x-end-of-sale-notice-v4.ashx.pdf",
        raw_text=raw_text,
    )

    assert [row["Part Number"] for row in rows] == ["1103045", "1103973", "1103052"]
    assert all(row["End of Sale"] == "2025-12-31" for row in rows)
    assert all(row["End of Support"] == "2029-06-30" for row in rows)
    assert all(row["End of Security Updates"] == "2029-06-30" for row in rows)
    assert rows[0]["Announcement Date"] == "2025-07-24"
    assert rows[0]["_source_url"] == (
        "https://source.sierrawireless.com/resources/airlink/"
        "hardware_reference_docs/airlink_rv50x_eos/"
    )
    assert rows[0]["_review_policy"] == (
        "sierra_airlink_end_of_software_maintenance_security_updates"
    )


def test_sierra_airlink_gx400_pdf_preserves_variant_sale_dates():
    text = """
END-OF-SALE ANNOUCEMENT

OVERVIEW
DATE ISSUED:            Mar 2, 2017
PRODUCTS AFFECTED:      GX400 Series Gateways

PRODUCTION MILESTONES
AFFECTED MODELS:        GX400 (AT&T, ROW/CANADA and AU/NZ variants)
END OF SALE DATE:       30-APR-2017 The product cannot be ordered from Sierra Wireless after this date.

AFFECTED MODELS:        GX400 (VERIZON and SPRINT variants)
END OF SALE DATE:       30-SEP-2017 The product cannot be ordered from Sierra Wireless after this date.

PRODUCT SUPPORT AND MAINTENANCE
ACTIVE SOFTWARE         FROM 30-APR-2017 TO 31-DEC-2017 During this phase, device software will be actively
MAINTENANCE PHASE:      maintained. Software releases will contain bug fixes and security patches only.
END OF SOFTWARE         31-DEC-2019 No new device software will be released after this date.
MAINTENANCE:

AFFECTED PART NUMBERS
  PART No.      MODEL DESCRIPTION                            SUGGESTED REPLACEMENT                                 PART No.
   1101207      GX400 (HSPA+, AT&T, AC)                       GX450 (LTE/HSPA+, AT&T, DC)                           1102363
                                                              GX450 (LTE/HSPA+, INTL, DC)                           1102375
   1101209      GX400 (EVDO, VERIZON, AC)                     GX450 (LTE/EVDO, VERIZON, DC)                         1102326

CONTACT
"""

    rows = parse_sierra_airlink_pdf_rows_from_text(
        text,
        "airlink_gx400_eos__gx400_end_of_sale_notice_r2.ashx.pdf",
    )

    assert [(row["Part Number"], row["End of Sale"]) for row in rows] == [
        ("1101207", "2017-04-30"),
        ("1101209", "2017-09-30"),
    ]
    assert all(row["End of Support"] == "2019-12-31" for row in rows)
    assert all(row["End of Security Updates"] == "2019-12-31" for row in rows)


def test_sierra_airlink_non_hardware_eol_pdf_is_skipped():
    text = """
End of Life Announcement: Dynamic DNS eairlink.com
DATE ISSUED:       07-Jun-2023
PRODUCT SUPPORT AND MAINTENANCE
END OF SOFTWARE
SUPPORT:
1-JUL-2023 The eairlink.com DDNS will be taken offline.
"""

    assert (
        parse_sierra_airlink_pdf_rows_from_text(
            text,
            "sierra-wireless-technical-bulletin---aleos-ddns-eol__notice.ashx.pdf",
        )
        == []
    )


def test_zpe_nscp_pdf_imports_sale_eol_as_review():
    text = """
End of Sale Notice
ZPE-NSCP-T96R-STND-xxx-5G

ZPE Systems Announces the End-of-Sale (EOS) for the following product(s):
Nodegrid Serial Console Plus - 96 Port with 5G cellular module

Key Dates:
End-of-Sale Announcement Date: February 28, 2025
End-of-Sale Date: May 30, 2025
End of Life: May 30, 2028

EOL Product Overview
EOL SKU
ZPE-NSCP-T96R-
STND-SAC-5G
ZPE-NSCP-T96R-STND-SAC-4G
ZPE-NSCP-T96R-STND-DAC-5G
ZPE-NSCP-T96R-STND-DAC-4G
ZPE-NSCP-T96R-STND-DDC-5G
ZPE-NSCP-T96R-STND-DDC-4G

Can I extend my warranty for an impacted device beyond the End-of-Life date?
Customers can purchase extended support. The end date for gold contract can go beyond
the End-of-Life date.
"""

    rows = parse_zpe_systems_pdf_rows_from_text(
        text,
        "zpe_2025_02_06_20_20end_20of_20sale_20notice_20_20"
        "zpe_nscp_t96r_stnd_xxx_5g.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "ZPE-NSCP-T96R-STND-SAC-5G",
        "ZPE-NSCP-T96R-STND-DAC-5G",
        "ZPE-NSCP-T96R-STND-DDC-5G",
    ]
    assert all(row["End of Sale"] == "2025-05-30" for row in rows)
    assert all(row["Last Sale"] == "2025-05-30" for row in rows)
    assert all(row["End of Life"] == "2028-05-30" for row in rows)
    assert all(row["_force_lifecycle_review"] is True for row in rows)
    assert all(row["_review_policy"] == "zpe_nscp_end_of_life_not_support_or_security_end" for row in rows)
    assert "End of Support" not in rows[0]
    assert rows[0]["_source_url"].endswith("ZPE-NSCP-T96R-STND-xxx-5G.pdf")


def test_zpe_gate_sr_pdf_imports_end_of_support_rows_and_wrapped_skus():
    text = """
End of Life Announcement
Select Nodegrid Gate SR Configurations

ZPE Systems is announcing the End-of-Life (EOL) and discontinuation of the part numbers
outlined in Table 1.

Announcement Milestones
September 1, 2025
End-of-Life Announcement (EOL) is the public notification date.
February 28, 2026
Last Order/Sale Date (LOD) refers to the final date on which purchase orders can be placed.
February 28, 2026
Last Ship Date (LSD) is the last possible ship date.
February 28, 2028
End of Support Date (EOS) is considered the final Milestone.

Part Number(s) Affected by this Announcement
GSR-T8-BASE ZPE-GSR-48-BASE-F
ZPE-GSR-48-BASE ZPE-GSR-48-BASE-F
ZPE-GSR-48-W5 ZPE-GSR-48-W5-F
ZPE-GSR-48-4G ZPE-GSR-48-4G-F
ZPE-GSR-48-4G-W5 ZPE-GSR-48-4G-W5-F
ZPE-GSR-48-4G-W5-D1
28G ZPE-GSR-48-4G-W5-D1
28G-F
ZPE-GSR-48-D128G ZPE-GSR-48-D128G-F
ZPE-GSR-48-BASE-GW ZPE-GSR-48-BASE-F-G
W
ZPE-GSR-48-W5-GW ZPE-GSR-48-W5-F-GW
ZPE-GSR-48-4G-GW ZPE-GSR-48-4G-F-GW
"""

    rows = parse_zpe_systems_pdf_rows_from_text(
        text,
        "zpe_end_20of_20life_20announcement_20_20selected_20nodegrid_20"
        "gate_20sr_20configurations.pdf",
    )

    assert len(rows) == 10
    assert rows[0]["Model"] == "GSR-T8-BASE"
    assert rows[0]["Announcement Date"] == "2025-09-01"
    assert rows[0]["End of Sale"] == "2026-02-28"
    assert rows[0]["Last Ship Date"] == "2026-02-28"
    assert rows[0]["End of Support"] == "2028-02-28"
    assert "End of Security Updates" not in rows[0]
    wrapped = {row["Model"]: row for row in rows}
    assert wrapped["ZPE-GSR-48-4G-W5-D128G"]["Replacement Products"] == (
        "ZPE-GSR-48-4G-W5-D128G-F"
    )
    assert wrapped["ZPE-GSR-48-BASE-GW"]["Replacement Products"] == (
        "ZPE-GSR-48-BASE-F-GW"
    )
    assert rows[0]["_review_policy"] == "zpe_end_of_support_date_is_technical_support_end"
    assert rows[0]["_source_url"].endswith("Gate%20SR%20Configurations.pdf")


def test_zpe_link_sr_pdf_imports_planned_replacements():
    text = """
End of Life Announcement
Select Nodegrid Link SR Configurations

ZPE Systems is announcing the End-of-Life (EOL) and discontinuation of the part numbers
outlined in Table 1.

Announcement Milestones
September 1, 2025 End-of-Life Announcement (EOL) is the public notification date.
December 31, 2025 Last Order/Sale Date (LOD) refers to the final date.
December 31, 2025 Last Ship Date (LSD) is the last possible ship date.
December 31, 2027 End of Support Date (EOS) is considered the final Milestone.

Part Number(s) Affected by this Announcement
LSR-T1-UPG2 Planned for 2026
ZPE-LSR-48-BASE Planned for 2026
ZPE-LSR-48-W5 Planned for 2026
ZPE-LSR-48-4G Planned for 2026
ZPE-LSR-48-4G-W5 Planned for 2026
"""

    rows = parse_zpe_systems_pdf_rows_from_text(
        text,
        "zpe_end_20of_20life_20announcement_20_20selected_20nodegrid_20"
        "link_20sr_20configurations.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "LSR-T1-UPG2",
        "ZPE-LSR-48-BASE",
        "ZPE-LSR-48-W5",
        "ZPE-LSR-48-4G",
        "ZPE-LSR-48-4G-W5",
    ]
    assert all(row["Replacement Products"] == "Planned for 2026" for row in rows)
    assert all(row["End of Sale"] == "2025-12-31" for row in rows)
    assert all(row["End of Support"] == "2027-12-31" for row in rows)
    assert rows[0]["Description"] == "Nodegrid Link SR serial console"
    assert rows[0]["_source_url"].endswith("Link%20SR%20Configurations.pdf")


def test_telrad_cpe8100_pdf_imports_manufacturing_discontinued_as_sale_only():
    text = """
August 10, 2020
Manufacturing Discontinued Notice

Due to the Covid-19 component shortage Telrad is forced to announce earlier than
expected end-of-life of our CPE 8100 model as of August 31, 2020.

Telrad strives to provide the highest levels of service and support to all of our
customers. Therefore our intent is to continue to support the CPE8100 for our
customers holding an active Service Level Agreement.

Discontinued Product Family PN Product Description Proposed Alternatives
CPE8100 735081xx CPE8100-PRO-1D-3.x Single Mode LTE Outdoor CPE CPE9000 CPE9000HG CPE12000
"""

    rows = parse_telrad_cpe8100_pdf_rows_from_text(
        text,
        "telrad_manufacturing_discontinued_notice_cpe8100.pdf",
    )

    assert len(rows) == 1
    assert rows[0]["Model"] == "CPE8100"
    assert rows[0]["Part Number"] == "735081xx"
    assert rows[0]["Announcement Date"] == "2020-08-10"
    assert rows[0]["End of Sale"] == "2020-08-31"
    assert rows[0]["Last Sale"] == "2020-08-31"
    assert rows[0]["Replacement Products"] == "CPE9000; CPE9000HG; CPE12000"
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == (
        "telrad_cpe8100_manufacturing_discontinued_support_continues"
    )


def test_telrad_breezeview_html_imports_centos7_security_update_end(tmp_path):
    html = """
    <html><body>
    <h1>Important update - BreezeVIEW OS Update Required - CentOS 7 End of Life</h1>
    <p>Our current operating system, CentOS Linux 7, has officially reached End of Life
    as of June 30, 2024. As CentOS 7 no longer receives security updates, continuing
    to use it may expose your system to vulnerabilities.</p>
    <p>All new BreezeVIEW releases will be available exclusively for Rocky Linux.
    No further versions will be released for CentOS.</p>
    </body></html>
    """
    path = tmp_path / "telrad_breezeview_centos7_end_of_life.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_telrad_breezeview_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "BreezeVIEW CentOS 7"
    assert rows[0]["End of Support"] == "2024-06-30"
    assert rows[0]["End of Security Updates"] == "2024-06-30"
    assert rows[0]["Description"] == "Network management software"
    assert rows[0]["_review_policy"] == (
        "telrad_breezeview_centos7_security_updates_ended"
    )
    assert extract_rows(path, "telrad_networks") == rows


def test_rockwell_stratix_lifecycle_json_imports_sales_end_only(tmp_path):
    data = {
        "docs": [
            {
                "type": "HARDWARE",
                "brand": "Allen-Bradley",
                "catalogNumber": "1783-BMS06TGA",
                "productLifeCycleStatus": "DISCONTINUED",
                "description": "Stratix 5700 6 Port Managed Switch",
                "title": "Stratix 5700 6 Port Managed Switch",
                "discontinuedDate": "2024-09-01T00:00:00Z",
                "replacementText": "1783-CMS6P",
                "replacementUrl": "https://www.rockwellautomation.com/en-us/products/details.1783-CMS6P.html",
                "url": "https://www.rockwellautomation.com/en-us/products/details.1783-BMS06TGA.html",
            },
            {
                "type": "HARDWARE",
                "brand": "Allen-Bradley",
                "catalogNumber": "LA2-16-1783",
                "productLifeCycleStatus": "DISCONTINUED",
                "description": "Cam Switch",
                "title": "Cam Switch",
                "discontinuedDate": "2024-09-01T00:00:00Z",
            },
            {
                "type": "HARDWARE",
                "brand": "Allen-Bradley",
                "catalogNumber": "1783-SFP100LX",
                "productLifeCycleStatus": "ACTIVE",
                "description": "100LX SFP Fiber Transceiver",
                "title": "100LX SFP Fiber Transceiver",
            },
        ]
    }
    path = tmp_path / "api_lifecycle_1783_page_01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    rows = extract_rockwell_stratix_lifecycle_rows(path)

    assert rows == [
        {
            "Model": "1783-BMS06TGA",
            "Part Number": "1783-BMS06TGA",
            "Product Name": "Stratix 5700 6 Port Managed Switch",
            "Description": "Stratix 5700 6 Port Managed Switch",
            "Rockwell Lifecycle": "Discontinued",
            "End of Sale": "2024-09-01",
            "_source_table": "api_lifecycle_1783_page_01.json docs",
            "_source_hint": "Rockwell Automation Stratix lifecycle API import",
            "_source_url": "https://www.rockwellautomation.com/en-us/products/details.1783-BMS06TGA.html",
            "_review_policy": "rockwell_lifecycle_status_sales_end_not_security_eol",
            "_review_reason": (
                "Rockwell lifecycle status defines End of Life as discontinued-date "
                "announcement and last-time-buy planning, and Discontinued as no "
                "longer manufactured or procured with possible repair/exchange "
                "services; the source does not publish a support or security-update "
                "end date."
            ),
            "_aliases": [
                "1783-BMS06TGA",
                "Stratix 5700 6 Port Managed Switch",
            ],
            "_prefer_model": True,
            "Lifecycle Status Source": (
                "https://www.rockwellautomation.com/en-us/support/product/"
                "product-compatibility-migration/product-lifecycle-status.html"
            ),
            "Replacement Products": "1783-CMS6P",
            "Replacement URL": "https://www.rockwellautomation.com/en-us/products/details.1783-CMS6P.html",
        }
    ]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]


def test_siemens_ruggedcom_pm410_imports_product_cancellation_as_sale_only(tmp_path):
    data = {
        "products": [
            {
                "productInformation": {
                    "productIdentifiers": {
                        "articleNumber": "6GK6090-0AS21-0BA0-Z A06+B00",
                        "mlfb": "6GK6090-0AS21-0BA0-Z",
                    },
                    "description": (
                        "RUGGEDCOM RS900 is a 9-port industrially hardened "
                        "managed Ethernet switch."
                    ),
                    "isSoftware": False,
                    "lifeCycle": {
                        "currentMilestone": {
                            "code": "P.M410",
                            "date": "2022-10-01T00:00:00",
                        },
                        "mileStones": [
                            {"code": "P.M400", "date": "2021-10-01T00:00:00"},
                            {"code": "P.M410", "date": "2022-10-01T00:00:00"},
                        ],
                        "phasedOut": True,
                        "phasedOutSinceDate": "2022-10-01T00:00:00",
                    },
                    "materialShortText": "RUGGEDCOM RS900",
                },
                "mlfb": "6GK6090-0AS21-0BA0-Z",
                "originalArticleNumber": "6GK60900AS210BA0-Z A06B00",
            }
        ]
    }
    path = tmp_path / "ruggedcom_rs900_pm410_6gk60900as210ba0_products_and_prices.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    rows = extract_siemens_ruggedcom_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "RUGGEDCOM RS900"
    assert rows[0]["Part Number"] == "6GK6090-0AS21-0BA0-Z A06+B00"
    assert rows[0]["Announcement Date"] == "2021-10-01"
    assert rows[0]["End of Sale"] == "2022-10-01"
    assert rows[0]["Last Sale"] == "2022-10-01"
    assert rows[0]["Description"] == "Industrial Ethernet switch"
    assert rows[0]["_review_policy"] == "siemens_ruggedcom_plm_milestone_mapping"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]
    assert rows[0]["_source_url"].endswith("6GK6090-0AS21-0BA0-Z")
    assert extract_rows(path, "siemens_ruggedcom") == rows


def test_siemens_ruggedcom_pm500_uses_pm490_support_discontinued_date(tmp_path):
    data = {
        "products": [
            {
                "productInformation": {
                    "productIdentifiers": {
                        "articleNumber": "6GK60100AX210DB0-Z A00+B00",
                        "mlfb": "6GK60100AX210DB0-Z",
                    },
                    "description": (
                        "RUGGEDCOM RX1000 cyber security appliance with router, "
                        "firewall and VPN functionality."
                    ),
                    "isSoftware": False,
                    "lifeCycle": {
                        "currentMilestone": {
                            "code": "P.M500",
                            "date": "2024-10-01T00:00:00Z",
                        },
                        "mileStones": [
                            {"code": "P.M400", "date": "2015-04-15T00:00:00Z"},
                            {"code": "P.M410", "date": "2018-10-01T00:00:00Z"},
                            {"code": "P.M490", "date": "2024-10-01T00:00:00Z"},
                            {"code": "P.M500", "date": "2024-12-31T00:00:00Z"},
                        ],
                        "successor": {
                            "articleNumber": "6GK6015-0DM2.-....",
                            "description": "RUGGEDCOM RX1536 successor",
                        },
                    },
                    "materialShortText": "RUGGEDCOM RX1000",
                },
                "mlfb": "6GK60100AX210DB0-Z",
            }
        ]
    }
    path = tmp_path / "ruggedcom_rx1000_pm500_6gk60100ax210db0_products_and_prices.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    rows = extract_siemens_ruggedcom_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "RUGGEDCOM RX1000"
    assert rows[0]["Announcement Date"] == "2015-04-15"
    assert rows[0]["End of Life"] == "2024-10-01"
    assert rows[0]["End of Support"] == "2024-10-01"
    assert rows[0]["Description"] == "Industrial security appliance"
    assert rows[0]["Replacement Products"].startswith("6GK6015-0DM2.-....")
    assert "End of Sale" not in rows[0]


def test_siemens_ruggedcom_switch_router_text_wins_over_sfp_module_text(tmp_path):
    data = {
        "products": [
            {
                "productInformation": {
                    "productIdentifiers": {
                        "articleNumber": "6GK6015-0BM2.-....",
                        "mlfb": "6GK6015-0BM2.-....",
                    },
                    "description": (
                        "The RUGGEDCOM RX1501 series is a layer 2 switch and "
                        "layer 3 router with field replaceable line modules, "
                        "SFP ports and serial interface modules."
                    ),
                    "lifeCycle": {
                        "currentMilestone": {
                            "code": "P.M410",
                            "date": "2024-10-01T00:00:00Z",
                        },
                        "mileStones": [
                            {"code": "P.M400", "date": "2023-10-01T00:00:00Z"},
                            {"code": "P.M410", "date": "2024-10-01T00:00:00Z"},
                        ],
                        "phasedOut": True,
                    },
                    "materialShortText": "RUGGEDCOM RX1501",
                }
            }
        ]
    }
    path = tmp_path / "ruggedcom_rx1501_pm410_6gk6015_0bm2_products_and_prices.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    rows = extract_siemens_ruggedcom_lifecycle_rows(path)

    assert rows[0]["Description"] == "Industrial switch/router"
    assert rows[0]["End of Sale"] == "2024-10-01"


def test_antaira_phaseout_parser_keeps_phaseout_in_lifecycle_review(tmp_path):
    html = """
    <table>
      <tr>
        <th>EOL Model</th><th>Phase Out Start Date</th>
        <th>Alternative Model</th><th>Notification Date</th><th>Details</th>
      </tr>
      <tr>
        <td>LMP-1002C-SFP-24 series</td><td>2019-06-18</td>
        <td>LMP-1202M-SFP-24 series</td><td>2019-06-18</td><td></td>
      </tr>
    </table>
    """
    path = tmp_path / "phaseout_ethernet_switch.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_antaira_phaseout_rows(path)

    assert rows == [
        {
            "Model": "LMP-1002C-SFP-24 series",
            "Product Name": "LMP-1002C-SFP-24 series",
            "Description": "ethernet switch",
            "Product Status": "phase out",
            "Announcement Date": "2019-06-18",
            "Phase Out Start Date": "2019-06-18",
            "Replacement Products": "LMP-1202M-SFP-24 series",
            "_source_table": "phaseout_ethernet_switch.html table 1",
            "_source_hint": "Antaira phase-out product notice table",
            "_status_only_review": True,
            "_review_policy": "antaira_phaseout_not_security_eol",
            "_review_reason": (
                "Antaira lists this model in a phase-out/EOL notice, but "
                "the table does not provide an exact support or "
                "security-update end date."
            ),
            "_prefer_model": True,
        }
    ]

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2019-06-18"
    assert dates["end_of_sale"] is None
    assert dates["end_of_support"] is None


def test_aten_japan_discontinued_products_imports_status_only_rows(tmp_path):
    html = """
    <html>
      <head><title>生産終了製品 | ATEN Japan</title></head>
      <body>
        <table>
          <tr><th>型番</th><th>製品概要</th><th>終了案内</th><th>修理可否</th><th>後継／代替</th></tr>
          <tr><td>KE6912</td><td>デュアルリンクDVI-D IP-KVMエクステンダー</td><td>2026/4/16</td><td>▲</td><td>-</td></tr>
          <tr><td>2L-4102-GR</td><td>Cat6 UTPケーブル(RJ45コネクタ付き)</td><td>2025/10/9</td><td>-</td><td>2L-BU5E002</td></tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "japan_discontinued_products.html"
    path.write_text(html, encoding="utf-8")
    global_path = tmp_path / "global_discontinued_products.html"
    global_path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "aten") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["KE6912", "2L-4102-GR"]
    assert rows[0]["Description"] == "KVM Device"
    assert rows[0]["Announcement Date"] == "2026-04-16"
    assert "Replacement Products" not in rows[0]
    assert "repair consultation required" in rows[0]["Product Status"]
    assert rows[1]["Description"] == "KVM/AV Accessory"
    assert rows[1]["Replacement Products"] == "2L-BU5E002"
    assert rows[1]["Region"] == "Japan"
    assert rows[1]["_status_only_review"] is True
    assert rows[1]["_source_url"] == "https://www.aten.com/jp/ja/supportcenter/discontinued-products/"
    assert rows[1]["_review_policy"] == "aten_japan_discontinued_products_status_only"
    assert extract_rows(global_path, "aten") == []


def test_avm_fritzbox_status_api_imports_network_hardware_review_rows(tmp_path):
    payload = {
        "data": {
            "products": {
                "fritzbox": {
                    "FRITZ-Box-7590": {
                        "id": 1,
                        "name": "FRITZ!Box 7590",
                        "slug": "FRITZ-Box-7590",
                        "data": {
                            "fields": {
                                "im-web-anzeigen": {"data": "true"},
                                "eod": {"data": "ja"},
                                "eos": {"data": "nein"},
                                "f-os-version": {"data": "8.25"},
                                "update-typ": {"data": "fos"},
                                "update-link": {"data": "https://fritz.com/update/7590"},
                                "skb-link": {"data": "https://fritz.com/kb/7590"},
                                "garantiezeit": {"data": "5"},
                            }
                        },
                    },
                    "FRITZ-Box-7690": {
                        "id": 2,
                        "name": "FRITZ!Box 7690",
                        "slug": "FRITZ-Box-7690",
                        "data": {
                            "fields": {
                                "im-web-anzeigen": {"data": "true"},
                                "eod": {"data": "nein"},
                                "eos": {"data": "nein"},
                            }
                        },
                    },
                },
                "fritzwlan": {
                    "FRITZ-Repeater-1750E": {
                        "id": 3,
                        "name": "FRITZ!Repeater 1750E",
                        "slug": "FRITZ-Repeater-1750E",
                        "data": {
                            "fields": {
                                "im-web-anzeigen": {"data": "true"},
                                "eod": {"data": "ja"},
                                "eos": {"data": "ja"},
                                "f-os-version": {"data": "7.32"},
                                "update-typ": {"data": "fos"},
                            }
                        },
                    }
                },
                "fritzapps": {
                    "FRITZ-App": {
                        "id": 4,
                        "name": "FRITZ!App",
                        "slug": "FRITZ-App",
                        "data": {
                            "fields": {
                                "im-web-anzeigen": {"data": "true"},
                                "eod": {"data": "ja"},
                                "eos": {"data": "ja"},
                            }
                        },
                    }
                },
            }
        }
    }
    path = tmp_path / "status_products_api.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    html_path = tmp_path / "product_support_status_page.html"
    html_path.write_text(
        "<table><tr><th>Model</th><th>EOS</th></tr><tr><td>bad</td><td>ja</td></tr></table>",
        encoding="utf-8",
    )

    rows = [row for row in extract_rows(path, "avm_fritzbox") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == [
        "FRITZ!Box 7590",
        "FRITZ!Repeater 1750E",
    ]
    assert rows[0]["Description"] == "FRITZ!Box Router"
    assert rows[0]["Current Version"] == "FRITZ!OS 8.25"
    assert rows[0]["Manufacturer Warranty"] == "5 years"
    assert "personal support available" in rows[0]["Product Status"]
    assert rows[1]["Description"] == "FRITZ! Wi-Fi Repeater/Adapter"
    assert "personal support unavailable" in rows[1]["Product Status"]
    assert rows[1]["_status_only_review"] is True
    assert rows[1]["_source_url"] == "https://fritz.com/en/pages/status-produktunterstuetzung"
    assert rows[1]["_review_policy"] == "avm_fritz_support_status_without_exact_dates"
    assert extract_rows(html_path, "avm_fritzbox") == []


def test_yealink_eol_detail_maps_eol_to_support_and_security_end(tmp_path):
    path = tmp_path / "product_detail_eol_ip-phone-t41p.html"
    path.write_text(
        """
<html>
<head>
<meta property="og:url" content="https://www.yealink.com/en/product-detail/ip-phone-t41p" />
<script type="application/ld+json">
{"@context":"https://schema.org/","@type":"WebPage","name":"SIP-T41P","url":"https://www.yealink.com/en/product-detail/ip-phone-t41p","mainEntity":[{"@type":"Product","name":"SIP-T41P","description":"End of Life Announcement for SIP-T41P IP Phone"}]}
</script>
</head>
<body>
<h2>End of Life Announcement &#8211; SIP-T41P</h2>
<p>End-of-Life (EOL) Date:<span>Apr 01 2025</span></p>
<p>End-of-Sale (EOS) Date: <span>Apr 01 2020</span></p>
<p>We will continue to provide support and services for this product under the applicable terms until the EOL date. Effective from the EOL date, all support and services for this product will be terminated.</p>
<input type="hidden" name="pageTitle" value="SIP-T41P">
</body>
</html>
""",
        encoding="utf-8",
    )

    rows = extract_yealink_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "SIP-T41P"
    assert rows[0]["Description"] == "IP Phone"
    assert rows[0]["End of Sale"] == "2020-04-01"
    assert rows[0]["Last Sale"] == "2020-04-01"
    assert rows[0]["End of Life"] == "2025-04-01"
    assert rows[0]["End of Support"] == "2025-04-01"
    assert rows[0]["End of Security Updates"] == "2025-04-01"
    assert rows[0]["Lifecycle Status Source"] == "https://www.yealink.com/en/onepage/end-of-life-policy"
    assert rows[0]["_source_url"] == "https://www.yealink.com/en/product-detail/ip-phone-t41p"
    assert rows[0]["_review_policy"] == "yealink_eol_date_support_and_security_updates_end"
    assert "T41P" in rows[0]["_aliases"]
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2020-04-01"
    assert dates["end_of_life"] == "2025-04-01"
    assert dates["end_of_support"] == "2025-04-01"
    assert dates["end_of_vulnerability"] == "2025-04-01"
    assert extract_rows(path, "yealink") == rows


def test_yealink_eos_detail_maps_only_end_of_sale(tmp_path):
    path = tmp_path / "product_detail_eos_microsoft-teams-rooms-mvc900ii.html"
    path.write_text(
        """
<html>
<head>
<meta property="og:url" content="https://www.yealink.com/en/product-detail/microsoft-teams-rooms-mvc900II" />
<script type="application/ld+json">
{"@context":"https://schema.org/","@type":"WebPage","mainEntity":[{"@type":"Product","name":"MVC900 II Microsoft Teams Room System","description":"Microsoft Teams Rooms video conferencing system"}]}
</script>
</head>
<body>
<h1>End-of-Sale Announcement for MVC900 II</h1>
<p>Yealink hereby informs you that the <span>MVC900 II</span> has been discontinued since <span>Jul 12 2021</span>. After the date, new orders for the product would not be accepted.</p>
<p>After the End-of-Sale date, Yealink will continue to offer support and after-sale service.</p>
<p>The recommended replacement solution to the MVC900 II is MVC940, which offers richer technology.</p>
<input type="hidden" name="pageTitle" value="MVC900 II Microsoft Teams Room System">
</body>
</html>
""",
        encoding="utf-8",
    )

    rows = extract_yealink_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "MVC900 II"
    assert rows[0]["Product Name"] == "MVC900 II Microsoft Teams Room System"
    assert rows[0]["Description"] == "Video Conferencing Endpoint/Room System"
    assert rows[0]["End of Sale"] == "2021-07-12"
    assert rows[0]["Last Sale"] == "2021-07-12"
    assert rows[0]["Replacement Products"] == "MVC940"
    assert "End of Life" not in rows[0]
    assert "End of Support" not in rows[0]
    assert "End of Security Updates" not in rows[0]
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "yealink_eos_is_sales_end_not_support_end"
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2021-07-12"
    assert dates["end_of_support"] is None
    assert dates["end_of_vulnerability"] is None


def test_yealink_us_market_eos_effective_date_splits_grouped_models(tmp_path):
    path = tmp_path / "product_detail_eos_wireless-presentation-wpp30-eol.html"
    path.write_text(
        """
<html>
<head>
<meta property="og:url" content="https://www.yealink.com/en/product-detail/wireless-presentation-wpp30-eol" />
<script type="application/ld+json">
{"@context":"https://schema.org/","@type":"WebPage","mainEntity":[{"@type":"Product","name":"WPP20/WPP30","description":"End-of-Sale in US Market"}]}
</script>
</head>
<body>
<h2>Yealink End-of-Sale Announcement of WPP20/WPP30 in the United States Market</h2>
<p>Yealink will no longer sell WPP20/WPP30 products as standalone devices or in combination with corresponding video conferencing systems into the United States market.</p>
<p>Notification Date: April 25, 2024</p>
<p>Effective Date: April 25, 2024</p>
<input type="hidden" name="pageTitle" value="WPP20/WPP30">
</body>
</html>
""",
        encoding="utf-8",
    )
    list_path = tmp_path / "eos_products.html"
    list_path.write_text(
        "<table><tr><th>Model</th><th>EOS</th></tr><tr><td>Bad</td><td>2024</td></tr></table>",
        encoding="utf-8",
    )

    rows = extract_yealink_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == ["WPP20", "WPP30"]
    assert {row["Region"] for row in rows} == {"United States"}
    assert {row["Description"] for row in rows} == {"Wireless Presentation Device"}
    assert {row["Announcement Date"] for row in rows} == {"2024-04-25"}
    assert {row["End of Sale"] for row in rows} == {"2024-04-25"}
    assert "WPP20/WPP30" in rows[0]["_aliases"]
    assert extract_rows(list_path, "yealink") == []


def test_tippingpoint_eol_dates_parser_maps_hardware_support_end(tmp_path):
    html = """
    <table>
      <tr>
        <th>"J" SKU</th><th>Device</th><th>Bulletin Number</th>
        <th>Announcement Date</th><th>End of Sale</th><th>End of Life</th>
      </tr>
      <tr>
        <td>TPNN0321</td><td>1100TX</td><td>1108</td>
        <td>AUG/28/2025</td><td>DEC/31/2025</td><td>DEC/31/2030</td>
      </tr>
    </table>
    """
    path = tmp_path / "tippingpoint_eol_dates.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_tippingpoint_eol_dates_rows(path)

    assert rows == [
        {
            "Model": "1100TX",
            "Part Number": "TPNN0321",
            "Product Name": "TippingPoint 1100TX",
            "Description": "TippingPoint hardware appliance or module",
            "Announcement Date": "2025-08-28",
            "End of Sale": "2025-12-31",
            "End of Life": "2030-12-31",
            "End of Support": "2030-12-31",
            "End of Security Updates": "2030-12-31",
            "Bulletin Number": "1108",
            "_source_table": "tippingpoint_eol_dates.html table 1",
            "_source_hint": "TippingPoint official EOL dates table",
            "_review_policy": "tippingpoint_eol_is_maintenance_end",
            "_aliases": ["TPNN0321"],
            "_prefer_model": True,
        }
    ]

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2025-12-31"
    assert dates["end_of_life"] == "2030-12-31"
    assert dates["end_of_support"] == "2030-12-31"
    assert dates["end_of_vulnerability"] == "2030-12-31"


def test_tippingpoint_eol_dates_parser_maps_software_version(tmp_path):
    html = """
    <table>
      <tr>
        <th>Version</th><th>Product</th><th>Bulletin</th>
        <th>Announcement</th><th>EOL</th>
      </tr>
      <tr><td>6.1.0</td><td>SMS</td><td>1103</td><td>DEC/19/2024</td><td>DEC/31/2025</td></tr>
    </table>
    """
    path = tmp_path / "tippingpoint_eol_dates.html"
    path.write_text(html, encoding="utf-8")

    # The captured Trend page has repeated End-of-Life headers after table
    # normalization; this synthetic row mirrors that shape.
    rows = extract_tippingpoint_eol_dates_rows(path)
    assert rows == []

    html = """
    <table>
      <tr>
        <th>End-of-Life</th><th>End-of-Life</th><th>End-of-Life</th>
        <th>End-of-Life</th><th>End-of-Life</th>
      </tr>
      <tr><td>6.1.0</td><td>SMS</td><td>1103</td><td>DEC/19/2024</td><td>DEC/31/2025</td></tr>
    </table>
    """
    path.write_text(html, encoding="utf-8")

    rows = extract_tippingpoint_eol_dates_rows(path)

    assert rows[0]["Model"] == "SMS"
    assert rows[0]["Part Number"] == "SMS 6.1.0"
    assert rows[0]["Version"] == "6.1.0"
    assert rows[0]["End of Support"] == "2025-12-31"
    assert rows[0]["End of Security Updates"] == "2025-12-31"


def test_patton_sunset_catalog_imports_review_only_rows(tmp_path):
    html = """
    <table>
      <tr>
        <th>Product</th><th>End of Life Notice (PDF)</th>
      </tr>
      <tr>
        <td>Model 1005 &amp; 1006</td>
        <td>This legacy product is EOL. For product replacement alternative,
        please see Pattons Model 1080A.</td>
      </tr>
    </table>
    """
    path = tmp_path / "sunset_eol_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_patton_sunset_rows(path)

    assert rows == [
        {
            "Model": "1005 & 1006",
            "Product Name": "Model 1005 & 1006",
            "Part Number": "1005 & 1006",
            "Description": (
                "This legacy product is EOL. For product replacement "
                "alternative, please see Pattons Model 1080A."
            ),
            "Product Status": "sunset or end-of-life product",
            "Replacement Products": "1080A",
            "_source_table": "sunset_eol_products.html table 1",
            "_source_hint": "Patton Sunset & EOL Products catalog",
            "_status_only_review": True,
            "_review_policy": "patton_legacy_eol_or_sunset_no_exact_support_date",
            "_review_reason": (
                "Patton lists this product in its Sunset & EOL Products "
                "catalog, but this catalog row does not provide an exact "
                "support or security-update end date."
            ),
            "_aliases": [
                "Model 1005 & 1006",
                "1005 & 1006",
                "Patton Model 1005 & 1006",
                "1005",
                "Model 1005",
                "Patton Model 1005",
                "1006",
                "Model 1006",
                "Patton Model 1006",
            ],
            "_prefer_model": True,
        }
    ]


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


def test_winmate_pcn_pdf_imports_last_time_buy_as_sale_only():
    text = """
    Product Change Notification
    Document No.                        PCN-A-20260416-1
    PCN TOPIC: Product Strategy Adjustment - Product Discontinuation Notice
    PCN Type: Product Discontinuation / Recommended Replacement Models
    Winmate products will be officially discontinued.
    Impacted Product List:
                                                 Discontinue Product                 Alternative Product
                    Product line
                                                    Model Name                          Model Name
                                                         IH70                              IAD70
             SBC
                                                         IK32                               IT32
                                                    IV7W-RK2U-
             2U Rack PC                              IV7T-RK2U                          IAD7T-RK2U
                                                     IH7T-RK2U-
    BIOS change: Yes
    Change Effective Date: From Aril 16th 2026
    Last Time Buy Date: Aril 16th 2026
    PCN Release Date: Aril 16th 2026
    """

    rows = parse_winmate_pcn_pdf_rows_from_text(text, "winmate.pdf")

    assert [row["Model"] for row in rows] == ["IH70", "IK32", "IV7T-RK2U"]
    assert rows[0]["End of Sale"] == "2026-04-16"
    assert rows[0]["Announcement Date"] == "2026-04-16"
    assert rows[0]["Replacement Products"] == "IAD70"
    assert all("End of Support" not in row for row in rows)
    assert rows[0]["_source_url"] == "https://www.winmate.com/en/NewsAndEvents/PCNNews"


def test_winmate_pcn_pdf_skips_alternative_only_lines_and_patterns():
    text = """
    Winmate Product Change Notification
    PCN Type: Product Discontinuation / Recommended Replacement Models
    Impacted Product List:
                           Discontinue Product
        Product line                                                    Alternative Product
                              Model Name
                                  IB32                    IE32                 IAN3
                                 IB32S                    IE32S                                     IP32S
                              W07IB3S-POT1         W07IE3S-POT1       W07IAN3S-POT1
                                                W12IE3S-PPB1
                              W22IB7T-IPA3         R19IP7T-PMA1
                                  XXXIK7T-XXXXX
                                     (X=A~z,o~g)
    BIOS change: Yes
    Last Time Buy Date: Jun 15th 2026
    PCN Release Date: Aril 15th 2026
    """

    rows = parse_winmate_pcn_pdf_rows_from_text(text, "ib.pdf")

    assert [row["Model"] for row in rows] == [
        "IB32",
        "IB32S",
        "W07IB3S-POT1",
        "W22IB7T-IPA3",
    ]
    assert all(row["End of Sale"] == "2026-06-15" for row in rows)
    assert "W12IE3S-PPB1" not in {row["Model"] for row in rows}
    assert "XXXIK7T-XXXXX" not in {row["Model"] for row in rows}


def test_winmate_pcn_pdf_imports_intel_component_order_date_without_wildcard():
    text = """
    Winmate
    Product Change Notification
    PCN Type: Product Discontinued
    Last Product Discontinuance Order Date:                                September 05,2025
    last Product Discontinuance Shipment Date:                             September 04,2026
    IMPACT PRODUCT LIST:
                            Model Name
     Single Board Computer                  IK70
     BOX PC                              IK70SB7-111
     2U Rack PC                          IK7T-RK2U
                                      XXXIK7T-XXXXX
     Panel PC
                                         (X=A~z,o~g)
    Original                                                    New
    IK7T                                                        IAD7T
    Change Effective Date: From March , 17th 2025
    Last Time Buy Date: June 30th··2025
    PCN Release Date: March . 11th 2025
    """

    rows = parse_winmate_pcn_pdf_rows_from_text(text, "ik7t.pdf")

    assert [row["Model"] for row in rows] == ["IK70", "IK70SB7-111", "IK7T-RK2U"]
    assert {row["End of Sale"] for row in rows} == {"2025-06-30"}
    assert {row["Announcement Date"] for row in rows} == {"2025-03-11"}


def test_winmate_pcn_pdf_ignores_non_winmate_component_pcn():
    text = """
    Product Change Notification
    Change Title: Intel Atom Processor D2700 Product Discontinuance
    Last Product Discontinuance Order Date: June 29, 2012
    Products Affected / Intel Ordering Codes:
    Intel Atom Processor D2700 DF8064101055647 SR0D9
    """

    assert parse_winmate_pcn_pdf_rows_from_text(text, "intel.pdf") == []


def test_mimosa_eol_pdf_imports_software_maintenance_and_sale_dates():
    text = """
    Mimosa A5c Access Point | End-of-Life Announcement
    Date Issued: May 1, 2025
    Product: Mimosa A5c Access Point
    Model Number(s): A5c | 100-00037, A5c-EF | 100-00037-01
    As we continue to evolve our product portfolio, Mimosa Networks is
    announcing the End-of-Life (EOL) process for the A5c Access Point Radio.

    Product Key Milestones:
    Milestone
    Definition
    Date

    End-of-Life Announcement
    End-of-Life/Product Discontinuance Announcement
    May 1, 2025

    End of Software Maintenance
    The last date Mimosa will release any software maintenance or bug fixes
    for the Product.
    May 1, 2025

    End-of-Sale Date
    The last date to order the Product from Mimosa and is no longer available
    for sale after this date.
    June 30, 2025

    End-of-Support Date
    The last date to receive support for the Product.
    Based on Warranty Terms

    Recommended Replacement:
    Part Number
    Product
    PN: 100-00113
    A6 Access Point

    Support Commitments:
    Mimosa will continue to provide technical support for the Products for
    the duration of each unit's applicable warranty period.
    """

    rows = parse_mimosa_eol_pdf_rows_from_text(text, "2025_A5c_EOL.pdf")

    assert [row["Model"] for row in rows] == ["A5c", "A5c-EF"]
    assert rows[0]["Part Number"] == "100-00037"
    assert rows[1]["Part Number"] == "100-00037-01"
    assert rows[0]["Announcement Date"] == "2025-05-01"
    assert "End of Life" not in rows[0]
    assert rows[0]["Security Updates End"] == "2025-05-01"
    assert rows[0]["End of Sale"] == "2025-06-30"
    assert rows[0]["Replacement Products"] == "100-00113 / A6 Access Point"
    assert "End of Support" not in rows[0]
    assert rows[0]["_source_url"] == "https://www2.mimosa.co/a5c-eol"

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2025-05-01"
    assert dates["end_of_life"] is None
    assert dates["end_of_sale"] == "2025-06-30"
    assert dates["end_of_vulnerability"] == "2025-05-01"
    assert dates["end_of_support"] is None


def test_ligowave_eol_pdf_maps_last_support_date(tmp_path):
    text = """
    LigoDLB 2-14
    Product End of Life Announcement

    LigoWave hereby announces that it is initiating the end of life of the
    following product and provides relevant end of life dates:

    Product Description
    LigoDLB 2-14 2.4GHz CPE with an integrated 14dBi antenna

    End of Life Timeline
    Announcement1 End of Sale2 End of Software Maintenance3 Last Date of Support4
    September 5, 2018 February 5, 2019 September 5, 2020 September 5, 2021

    3 after this date, the LigoWave team will no longer develop, repair,
    maintain or test the product software
    4 after this date, all support services for the product will no longer be
    available
    """

    rows = parse_ligowave_pdf_rows_from_text(text, "EOL_LigoDLB_2-14.pdf")

    assert len(rows) == 1
    assert rows[0]["Model"] == "LigoDLB 2-14"
    assert rows[0]["Description"] == "Wireless CPE"
    assert rows[0]["Announcement Date"] == "2018-09-05"
    assert rows[0]["End of Sale"] == "2019-02-05"
    assert rows[0]["Vendor Software Maintenance End"] == "2020-09-05"
    assert rows[0]["End of Support"] == "2021-09-05"
    assert rows[0]["_source_url"] == "https://www.ligowave.com/end-of-life-policy"
    assert "End of Software Maintenance" not in rows[0]

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2018-09-05"
    assert dates["end_of_sale"] == "2019-02-05"
    assert dates["end_of_support"] == "2021-09-05"
    assert dates["end_of_vulnerability"] is None


def test_ligowave_product_change_pdf_is_skipped():
    text = """
    NFT 2
    Product Change Announcement
    LigoWave hereby announces that it is applying changes to the following
    product and provides relevant product change information.
    Altered Product NFT 2ac
    """

    assert parse_ligowave_pdf_rows_from_text(
        text,
        "NFT_2ac_Product_Change_Announcement_.pdf",
    ) == []


def test_eaton_dit_eol_table_imports_current_catalog_numbers_as_review_only():
    text = """
    Eaton Corporation
    End-of-Life Notification: 5P Rack Tower UPS
    Eaton is announcing intention to end-of-life the 5P1500RT, 5P2200RT, and 5P3000RT at the end of
    calendar year 2026. Orders placed against these part numbers prior to September 1, 2026, will be
    fulfilled.

    End-of-Life Effective Date
    **December 31, 2026** The 5P Rack Tower UPS portfolio will reach its official End-of-Life on this
    date.

    EOL Catalog Number                   Description                   Replacement Catalog Number
    5P1500RT                        1500 VA UPS                           5P1500RTG2
    5P2200RT                        2200 VA UPS                           5P2200RTG2
    RK4PC                           Rack Kit for 5P2200RT, 5P3000RT       NA

    Next Steps:
    """

    rows = parse_eaton_pdf_rows_from_text(text, "dit_eol_notice_001_26.pdf")

    assert [row["Model"] for row in rows] == ["5P1500RT", "5P2200RT", "RK4PC"]
    assert rows[0]["End of Sale"] == "2026-09-01"
    assert rows[0]["End of Life"] == "2026-12-31"
    assert rows[0]["Replacement Products"] == "5P1500RTG2"
    assert rows[0]["_force_lifecycle_review"] is True
    assert "End of Support" not in rows[0]


def test_eaton_power_alert_local_maps_explicit_no_updates_support_date():
    text = """
    Eaton Corporation
    Power Alert Local - End-of-Life Notice
    Eaton is formally announcing the End-of-Life (EOL) of Power Alert Local, our local
    monitoring and management software for Eaton Tripp Lite Series UPS systems.

    End-of-Life Effective Date
    **December 31, 2025** - Power Alert Local will reach its official End-of-Life on this date.
    After this date, Power Alert Local will no longer receive updates, patches, or technical support.
    """

    rows = parse_eaton_pdf_rows_from_text(text, "dit_eol_notice_032_26.pdf")

    assert [row["Model"] for row in rows] == ["Power Alert Local"]
    assert rows[0]["End of Life"] == "2025-12-31"
    assert rows[0]["End of Support"] == "2025-12-31"
    assert rows[0]["Security Updates End"] == "2025-12-31"
    assert rows[0]["_end_of_security_updates_override"] == "2025-12-31"
    assert "_force_lifecycle_review" not in rows[0]


def test_eaton_network_m2_notice_is_review_only_without_exact_update_end():
    text = """
    Eaton sets timeline for transition to NETWORK-M3 for Gigabit network management cards
    Eaton announces its intention to end of life the NETWORK-M2 by the end of 2023. The NETWORK-M2 will be fully
    replaced by the new NETWORK-M3 which will have the same form, fit, and function. Cybersecurity certifications and
    updates for the NETWORK-M2 will be supported for the warranty period of the host device or applicable service contract.
    February 14, 2023
    """

    rows = parse_eaton_pdf_rows_from_text(text, "dit_eol_notice_034_23.pdf")

    assert [row["Model"] for row in rows] == ["NETWORK-M2"]
    assert rows[0]["End of Life"] == "2023-12-31"
    assert rows[0]["Replacement Products"] == "NETWORK-M3"
    assert rows[0]["_status_only_review"] is True
    assert "End of Support" not in rows[0]


def test_silicom_eol_table_imports_exact_sku_with_support_date():
    text = """
    March 3, 2021

    End of Life Notification PCIe Servers Adapters based on Intel 82580DB:
    Silicom
    Dear valued Customer,
    We want to notify you that we decided to discontinue the production of Dual 82580 based adapters.
    PNs as in table below.
    Last Time Buy (LTB) purchase orders for the EOL products will be accepted until
    December 15, 2021 (LTB). Last Time Ship (LTS) will be until December 15, 2023

    End of Life product             Description                      Replacement
    PE2G2BPI80-SD-LP-R              Dual port Copper bypass          i350 based adapters
                                    1GBE PCI-E G2 adapter
    PE2G2I80-Q-R                    Dual Port Copper 1G Ethe.
                                    PCI-E Server Adapter

    Full Warranty and Support
    As with all our products, these EOL products include a one-year warranty, and we will provide
    support till December 15, 2024.
    """

    rows = parse_silicom_pdf_rows_from_text(
        text,
        "LCC001321-EOL-letter-Dual-82580-based-adapters.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "PE2G2BPI80-SD-LP-R",
        "PE2G2I80-Q-R",
    ]
    assert rows[0]["End of Sale"] == "2021-12-15"
    assert rows[0]["End of Support"] == "2024-12-15"
    assert rows[0]["Last Ship Date"] == "2023-12-15"
    assert rows[0]["_review_policy"] == "silicom_eol_notice_explicit_or_derived_support_end"
    assert "_force_lifecycle_review" not in rows[0]


def test_silicom_eol_notice_derives_three_year_support_from_ltb():
    text = """
    May 18, 2014
    End of Life Notification
    Silicom
    We want to notify you that we are discontinuing the production of the PEG1T, PEG1TF Series.
    Due to that purchase orders for this product will be accepted until July 1st, 2015.
    Last ship date is: December 31th, 2015.

    Product              Replacement
    PEG1T                PE2G2I35
    PEG1TF               PE2G2I35

    Full Warranty and Support
    As with all our products, these EOL PEG1T, PEG1TF products include a one-year
    warranty, and we will provide support for a full three (3) years after the last time buy
    opportunity on July 1st, 2015.
    """

    rows = parse_silicom_pdf_rows_from_text(text, "peg1tx_eol_letter.pdf")

    assert [row["Model"] for row in rows] == ["PEG1T", "PEG1TF"]
    assert rows[0]["End of Sale"] == "2015-07-01"
    assert rows[0]["End of Support"] == "2018-07-01"
    assert rows[0]["Last Ship Date"] == "2015-12-31"


def test_silicom_status_only_exact_eol_row_is_review_only():
    text = """
    November 28, 2022
    End of Life Notification for:
    Security Protocol Processor PCI Express Adapter
    We want to notify you that we decided to immediately discontinue the production of BDS#PEG4RS416.

    End of Life product              Description                          Replacement
                                                                           Contact Silicom sales
    BDS#PEG4RS416
    """

    rows = parse_silicom_pdf_rows_from_text(
        text,
        "EOL-Notification-Letter-BDSPEG4RS416.pdf",
    )

    assert [row["Model"] for row in rows] == ["BDS#PEG4RS416"]
    assert "End of Sale" not in rows[0]
    assert "End of Support" not in rows[0]
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_force_lifecycle_review"] is True


def test_silicom_wildcard_and_compressed_rows_are_skipped():
    text = """
    November 28, 2022
    End of Life Notification for:
    Security Protocol Processor PCI Express Adapter
    We want to notify you that we decided to immediately discontinue the production of PESC61, PESC62
    and PESC63 products. PNs as in table below.

    End of Life product              Description                          Replacement
    PESC61-*                         Security Protocol Processor PCI      Contact Silicom sales
    PESC62-*                         Security Protocol Processor PCI
    PESC63-*                         Security Protocol Processor PCI

    - all configurations.

    Product Series that will be discontinued:
      - PEG4T/TE/TS/TES
      - PEG2DBI6-SD
    Purchase orders for these products will be accepted until October 10, 2014.
    """

    rows = parse_silicom_pdf_rows_from_text(
        text,
        "EOL-Notification-Letter-PESC61-PESC62-PESC63.pdf",
    )

    assert [row["Model"] for row in rows] == ["PEG2DBI6-SD"]


def test_audiocodes_cpn_table_maps_explicit_software_support_date():
    text = """
    Product Notice #0280
    End-of-Life for MP-201B

    Notice Effective Date:
    April 2016

    Affected Part Numbers (CPN)
    MP201B/1S/SIP

    Note: AudioCodes EoL policy terms:
    The deadline for Last-Time Buy (LTB) orders for the MP201B/1S/SIP is July 2016.
    Software Support services for the discontinued product is available until April 2018.
    """

    rows = parse_audiocodes_pdf_rows_from_text(
        text,
        "0280-product-notice-end-of-life-eol-for-mp-201b.pdf",
    )

    assert [row["Model"] for row in rows] == ["MP201B/1S/SIP"]
    assert rows[0]["End of Sale"] == "2016-07-31"
    assert rows[0]["End of Support"] == "2018-04-30"
    assert rows[0]["_review_policy"] == "audiocodes_explicit_end_of_support_notice"
    assert "_force_lifecycle_review" not in rows[0]


def test_audiocodes_end_of_sale_rows_are_review_only_without_support_date():
    text = """
    Product Notice #0489
    End-of-Sale for Specific AudioCodes IP Phone and Meeting Space Models

    Effective Date
    January 1, 2023.

    Last Time Buy
    The Last Time Buy (LTB) is January 1, 2023.

    Affected Products
    IP-RX50, RX50-B40, AC-SAT-MIC
    TEAMS-C450HD, TEAMS-C450HDPS
    """

    rows = parse_audiocodes_pdf_rows_from_text(
        text,
        "0489-product-notice-end-of-sale-for-specific-ip-phone-and-meeting-space-models.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "IP-RX50",
        "RX50-B40",
        "AC-SAT-MIC",
        "TEAMS-C450HD",
        "TEAMS-C450HDPS",
    ]
    assert all(row["End of Sale"] == "2023-01-01" for row in rows)
    assert all(row["_force_lifecycle_review"] is True for row in rows)
    assert all("End of Support" not in row for row in rows)


def test_audiocodes_end_of_service_notice_maps_service_date():
    text = """
    End-of-Service for
    AudioCodes Auto-Attendant IVR Solution
    Product Notice #0548

    This Product Notice is a formal announcement by AudioCodes that its Auto-
    Attendant interactive voice response (IVR) solution will reach End-of-Service (EoS)
    on December 31, 2024.

    Affected Products
    AudioCodes Auto-Attendant IVR CPNs:
    SW/APP/AA/SRV
    SW/APP/AA/2
    """

    rows = parse_audiocodes_pdf_rows_from_text(
        text,
        "0548-product-notice-end-of-service-for-audiocodes-auto-attendant-ivr-solution.pdf",
    )

    assert [row["Model"] for row in rows] == ["SW/APP/AA/SRV", "SW/APP/AA/2"]
    assert rows[0]["End of Service"] == "2024-12-31"
    assert rows[0]["_review_policy"] == "audiocodes_explicit_end_of_service_notice"
    assert "_force_lifecycle_review" not in rows[0]


def test_ribbon_product_code_table_maps_support_and_not_replacement():
    text = """
    PRODUCT AND SERVICES BULLETIN
    External Announcement

    ISSUED: March 7, 2025

    End of Product Sale Notice for the Session
    Border Controller 2000 - SBC 2000

    SUGGESTED REPLACEMENT PRODUCTS/SKUs
                  EOPS PLATFORM                      REPLACEMENT
    Session Border Controller 2000                   Edge 8100/8300/8500

    PRODUCT LIFE CYCLE DATES
    Milestone                                                  Date
    End of Product Sale (EoPS) Announcement: Date on which Ribbon has
                                                              7 March 2025
    Last Quote Date: Date on which the affected product codes are no longer
                                                              30 June 2025
    End of Product Availability: Date on which the affected product codes
    are no longer orderable.
                                                              30 September 2025
    End of Product Delivery: Date on which the affected product codes can
    no longer be shipped.
                                                              15 November 2025
    End of RMA Support: Date on which all levels of RibbonCare HW support
    are no longer available for purchase for the affected product.
                                                              28 February 2030

    PRODUCT CODES NO LONGER AVAILABLE AFTER LAST QUOTE DATE
    Product Code                    Description of EOL SKU
    SBC-2K-R-1                      REVISED SBC 2000 W/ 1 DSP
    SBC-2K-PSU-AC                   SBC2000 AC POWER SUPPLY
    BLANK-USB                       GENERAL PURPOSE USB DRIVE FOR RIBBON PRODUCTS

    RIBBON CONFIDENTIAL AND PROPRIETARY
    """

    rows = parse_ribbon_pdf_rows_from_text(
        text,
        "SBC_2000_End_of_Product_Sale_Notice_EoPS.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "BLANK-USB",
        "SBC-2K-PSU-AC",
        "SBC-2K-R-1",
    ]
    assert all(row["End of Sale"] == "2025-09-30" for row in rows)
    assert all(row["End of Support"] == "2030-02-28" for row in rows)
    assert all("Edge 8100" not in row["Model"] for row in rows)
    assert all("_force_lifecycle_review" not in row for row in rows)


def test_ribbon_software_release_maps_explicit_rnd_support_end():
    text = """
    PRODUCT AND SERVICES BULLETIN
    External Announcement

    ISSUED: January 8, 2024

    SBC Core Release 10.1.x (non-JITC) End of Product Sale
    Notification
    Ribbon is announcing the End of Product Sale (EoPS) and End of Support (EoS)
    dates for Release 10.1.x software running on the Ribbon SBC 5400, SBC 7000 and
    SBC SWe products. Customers are recommended to upgrade to SBC Core 12.1.x
    release software for continued software fixes and security updates.

    PRODUCT LIFE CYCLE DATES
    Milestone                                                  Date
    End of Product Sale Announcement: Date on which Ribbon has announced EoPS.
                                                              January 8, 2024
    End of R&D Support: Date on which the product will no longer receive
    software fixes. RibbonCare RTS best effort technical support without
    software patches remains available for purchase.
                                                              December 31, 2024
    """

    rows = parse_ribbon_pdf_rows_from_text(
        text,
        "Ribbon_External_EoPS_Bulletin_SBC_Core_10.1_non_JITC_SW-3_Jan_2024.pdf",
    )

    assert [row["Model"] for row in rows] == ["SBC Core Release 10.1.x (non-JITC)"]
    assert rows[0]["End of Support"] == "2024-12-31"
    assert rows[0]["Security Updates End"] == "2024-12-31"
    assert rows[0]["_end_of_security_updates_override"] == "2024-12-31"


def test_ribbon_policy_pdf_is_not_imported():
    text = """
    Sonus End of Product Sale (EOPS) Policy
    General Product Lifecycle Timelines
    End of Product Sale means the period that the Product is still supported but
    is no longer available for purchase. EoSL means standard support is no longer
    provided by Sonus.
    """

    assert parse_ribbon_pdf_rows_from_text(
        text,
        "Sonus-end-of-product-sale-policy-050717.pdf",
    ) == []


def test_ribbon_two_column_eol_codes_do_not_become_descriptions():
    text = """
    SONUS PRODUCT BULLETIN
    Subject: dotHill RAID EOL & StorageTek Drive/Price Change
    Date: November 19, 2008

    Last year dotHill announced the end of life of their SANNet II RAID systems.
    Information was communicated in a 12/15/08 product bulletin. The dotHill
    product codes listed below are no longer orderable. These systems will be
    supported by dotHill until June 30, 2012 and Sonus will support them until
    December 15, 2014.

    dotHill EOL product codes no longer orderable

    RAID-HA                   CORDSET-RAID-AC
    RAID-HA-AC                CORDSET-RAID-DC

    The StorageTek replacement products have been available since Q1-09.

    Product Code              List Price US
    ST2540-HD-300             $1,400
    """

    rows = parse_ribbon_pdf_rows_from_text(
        text,
        "2009-11-19_dothill_raid_eol-storagetek_drive-price_change_1.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "CORDSET-RAID-AC",
        "CORDSET-RAID-DC",
        "RAID-HA",
        "RAID-HA-AC",
    ]
    assert all(row["End of Support"] == "2014-12-15" for row in rows)
    assert all("End of Life" not in row for row in rows)
    assert all("CORDSET" not in row["Description"] for row in rows if row["Model"].startswith("RAID-"))
    assert all(row["Model"] != "ST2540-HD-300" for row in rows)


def test_ribbon_title_fallback_imports_exact_edgeview_release():
    text = """
    PRODUCT AND SERVICES BULLETIN
    External Announcement

    ISSUED: June 30, 2025

    EdgeView Release 15.x End of Product Sale and End of R&D
    Support Notification
    Ribbon is announcing the End of Product Sale and End of Support dates for
    EdgeView Release 15.x software. Customers should upgrade for continued
    software fixes and security updates.

    PRODUCT LIFE CYCLE DATES
    End of Product Sale Announcement: Announces the date when a Product
    is no longer Generally Available for sale.
    June 30, 2025
    End of R&D Support: Date on which the product will no longer receive
    software updates. Best effort support remains available without software patches.
    July 31, 2025
    """

    rows = parse_ribbon_pdf_rows_from_text(
        text,
        "EdgeView_Release_15.x_EoPS-_EoS_Bulletin_30_June_2025-1.pdf",
    )

    assert [row["Model"] for row in rows] == ["EdgeView Release 15.x"]
    assert rows[0]["End of Support"] == "2025-07-31"
    assert rows[0]["Security Updates End"] == "2025-07-31"


def test_ivanti_release_matrix_imports_product_scoped_releases(tmp_path):
    html = """
    <html><body>
      <p>Granular Software Release EOL Timelines and Support Matrix</p>
      <h1>Ivanti Connect Secure:</h1>
      <h2>Modern Stack Releases (22.x) for Ivanti Connect Secure</h2>
      <table>
        <tr>
          <td>Gateway Release</td><td>Launch Date</td>
          <td>End of Engineering</td><td>End of Support</td>
        </tr>
        <tr><td>22.7</td><td>05/21/2024</td><td>1/31/2026</td><td>01/31/2027</td></tr>
      </table>
      <h2>Desktop Ivanti Secure Access Client</h2>
      <table>
        <tr><td>Release</td><td>Launch Date</td><td>End of Support</td></tr>
      </table>
      <table>
        <tr><td>22.8</td><td>02/11/2025</td><td>01/31/2027</td></tr>
      </table>
    </body></html>
    """
    path = tmp_path / "granular_software_release_eol_matrix.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_ivanti_pulse_release_matrix_rows(path)

    assert [row["Model"] for row in rows] == [
        "Ivanti Connect Secure 22.7",
        "Ivanti Secure Access Client Desktop 22.8",
    ]
    assert rows[0]["Launch Date"] == "2024-05-21"
    assert rows[0]["Vendor End of Engineering"] == "2026-01-31"
    assert rows[0]["End of Support"] == "2027-01-31"
    assert rows[1]["Description"] == "Endpoint VPN client software"


def test_vertiv_avocent_acs6000_parser_skips_duplicate_source():
    text = """
    PRODUCT END-OF-LIFE (EOL)
    Avocent ACS6000 Advanced Console Servers
    EOL SKU
    ACS6004DAC-G2 ACS 6000 4-PORTS DUAL AC
    """

    assert parse_vertiv_avocent_pdf_rows_from_text(
        text,
        "eol_notice_042_avocent_acs_6000_product_eol.pdf",
    ) == []


def test_vertiv_avocent_acs6000_parser_imports_exact_skus_review_only():
    text = """
    PRODUCT END-OF-LIFE (EOL)
    Avocent ACS6000 Advanced Console Servers
    EOL Announcement: March 30, 2018
    End-of-Sale: July 31, 2018
    End of Life: July 31, 2023

    EOL SKU DESCRIPTION REPLACEMENT SKU(s)
    ACS6004DAC-G2 ACS 6000 4-PORTS DUAL AC ACS804EAC-001
    ACS6016DAC-G2-G01 ACS 6000 16-PORTS DUAL AC ACS8016DAC-400
    """

    rows = parse_vertiv_avocent_pdf_rows_from_text(
        text,
        "eol_notice_047_avocent_acs6000_console_servers_eol.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "ACS6004DAC-G2",
        "ACS6016DAC-G2-G01",
    ]
    assert rows[0]["End of Sale"] == "2018-07-31"
    assert rows[0]["End of Life"] == "2023-07-31"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "vertiv_avocent_product_eol_extended_warranty_review"


def test_vertiv_avocent_dsview_parser_preserves_security_update_end():
    text = """
    Product End-of-Sale (EOS)
    Vertiv Avocent DSView 4.5 Management Software
    End-of-Sale: February 1, 2025
    Final Software Release: December 2026
    Last committed Service Pack release to address Sev1 issues and end of
    security updates
    End-of-Life: February 1, 2030

    Current SKU Description Replacement
    DSV4.5-1000DEV DSView 4.5 1000 Device Add-On Licenses
    DSV4.5-BASE DSView 4.5 Master License Key Request
    """

    rows = parse_vertiv_avocent_pdf_rows_from_text(
        text,
        "eol_notice_045_avocent_dsview_45_product_end_of_sale_av_49568.pdf",
    )

    assert [row["Model"] for row in rows] == ["DSV4.5-1000DEV", "DSV4.5-BASE"]
    assert rows[0]["End of Sale"] == "2025-02-01"
    assert rows[0]["Security Updates End"] == "2026-12-31"
    assert rows[0]["_end_of_security_updates_override"] == "2026-12-31"
    assert rows[0]["End of Life"] == "2030-02-01"


def test_vertiv_geist_part_model_table_imports_exact_pairs_with_service_date():
    text = """
    Product End of Life
    Vertiv PowerIT Basic and Metered Upgradeable Rack PDU Models

    Key dates:
    End of Sale (and EOL): July 1, 2025
    End of Production: August 1, 2025
    End of Service: July 1, 2030

    Part No.        Model No.                         Part No.      Model No.
    GI10001L        MG01X4B1-12L193-3PS56B2A10-S      GI10021L      MG01D2R1-12L193-3PS56B2H10-S
    I10004L         MN01X4W1-36PT68-3PS6B0A10-S      VP3G9100      MG01D1R1-12CF13-3PS6B2H10-S

    Vertiv.com
    """

    rows = parse_vertiv_pdf_rows_from_text(
        text,
        "eol_notice_001_product_end_of_life_announcement-_vertiv_powerit_basic_and_metered_upgradeable_rack_pdu_models.pdf",
    )

    assert [row["Part Number"] for row in rows] == [
        "GI10001L",
        "GI10021L",
        "I10004L",
        "VP3G9100",
    ]
    assert rows[0]["Model"] == "MG01X4B1-12L193-3PS56B2A10-S"
    assert rows[0]["End of Sale"] == "2025-07-01"
    assert rows[0]["End of Life"] == "2025-07-01"
    assert rows[0]["End of Service"] == "2030-07-01"
    assert "_force_lifecycle_review" not in rows[0]


def test_vertiv_geist_replacement_table_imports_only_affected_pair():
    text = """
    Product End-of-Life
    Vertiv Geist MJ Series rPDUs

    Effective November 1, 2022, The Vertiv Geist MJ Series rPDUs will enter End of Life.
    Effective April 1, 2023, all standard and ETO Geist MJ Series models will no longer be
    available for sale. The standard Geist MJ Series models and their replacement models
    are listed below.

    MJ Series Item #       MJ Series Model #       Replacement Item #       Replacement Model #
    11156                  MJCN122-101S15ST5       11757VH                  NSVC140-101S15
    11158                  MJCN122-102S20ST5       28087                    NSVC140-102S20
    """

    rows = parse_vertiv_pdf_rows_from_text(
        text,
        "eol_notice_003_product_end_of_life_announcement_-_vertiv_geist_mj_series_rpdus.pdf",
    )

    assert [row["Part Number"] for row in rows] == ["11156", "11158"]
    assert [row["Model"] for row in rows] == [
        "MJCN122-101S15ST5",
        "MJCN122-102S20ST5",
    ]
    assert all("NSVC140" not in row["Model"] for row in rows)
    assert rows[0]["End of Sale"] == "2023-04-01"
    assert rows[0]["End of Life"] == "2022-11-01"
    assert rows[0]["_force_lifecycle_review"] is True


def test_vertiv_family_support_notice_without_exact_sku_rows_is_skipped():
    text = """
    End of Support Notice
    Models:
    Geist R-Series rPDUs and Watchdog 1000 Series Environmental Monitors
    Announcement: Dec 19, 2018

    PRODUCT                                      END OF SUPPORT       REPLACEMENT PRODUCT
    R-Series rPDU with v2 Firmware RSM, RSP     12/31/2018           Vertiv Geist Upgradable rPDU family
    R-Series Watchdog Climate Monitors          12/31/2018           Watchdog15 or Watchdog 100
    """

    assert parse_vertiv_pdf_rows_from_text(
        text,
        "eol_notice_009_product_end_of_support_announcement_r-series_and_watchdog_1000.pdf",
    ) == []


def test_etherwan_eol_notice_maps_last_buy_to_sale_only(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical"
          href="https://www.etherwan.com/us/support/eol-notice/etherwan-switches-and-media-converters-series">
      </head>
      <body>
        <article>
          <h1>EtherWAN Switches and Media Converters Series</h1>
          <div class="field--name-body">
            <p><strong>ECN Number:</strong> PM20200226<br>
            <strong>Issue Date:</strong> 2020/02/26<br>
            <strong>Effective Date:</strong> 2020/03/01</p>
            <p>EtherWAN has decided to strategically announce the end-of-life
            for the following series of products.</p>
            <table>
              <tr>
                <td>Product Name</td>
                <td>Last Buy Date</td>
                <td>Last Shipment Date</td>
                <td>Replacement</td>
              </tr>
              <tr>
                <td>EM1020</td>
                <td>28th Aug 2020</td>
                <td>28th Nov 2020</td>
                <td>EL2315</td>
              </tr>
            </table>
          </div>
        </article>
      </body>
    </html>
    """
    path = tmp_path / "notice.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_etherwan_eol_notice_rows(path)

    assert rows[0]["Model"] == "EM1020"
    assert rows[0]["End of Sale"] == "2020-08-28"
    assert rows[0]["Announcement Date"] == "2020-03-01"
    assert rows[0]["Replacement Products"] == "EL2315"
    assert "End of Support" not in rows[0]
    assert rows[0]["_source_url"].endswith(
        "/us/support/eol-notice/etherwan-switches-and-media-converters-series"
    )


def test_etherwan_immediate_last_order_uses_notice_date(tmp_path):
    html = """
    <article>
      <h1>Product EOL - EX63000 and EX77964</h1>
      <div class="field--name-body">
        <p>Date: 6/26/2025</p>
        <p>EtherWAN is phasing out the following products.</p>
        <table>
          <tr>
            <td>Product Name</td>
            <td>Last Order Date</td>
            <td>Alternative Product</td>
          </tr>
          <tr>
            <td>EX63000</td>
            <td>Immediate</td>
            <td>EX73900E series</td>
          </tr>
          <tr>
            <td>EX77964</td>
            <td>December 23, 2025</td>
            <td>EX73900E series</td>
          </tr>
        </table>
      </div>
    </article>
    """
    path = tmp_path / "notice.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_etherwan_eol_notice_rows(path)

    assert [row["Model"] for row in rows] == ["EX63000", "EX77964"]
    assert rows[0]["End of Sale"] == "2025-06-26"
    assert rows[1]["End of Sale"] == "2025-12-23"
    assert rows[0]["Replacement Products"] == "EX73900E series"


def test_etherwan_engineering_change_notice_is_not_lifecycle_eol(tmp_path):
    html = """
    <article>
      <h1>Product ECN - EasyLink Series Engineering Change Notice</h1>
      <div class="field--name-body">
        <p>Notification Date: 9/16/2024</p>
        <table>
          <tr>
            <td>Product Name</td>
            <td>Notification Date of Version Change</td>
            <td>Last Time Buy Date of old Version</td>
            <td>Last Shipment Date of old Version</td>
          </tr>
          <tr>
            <td>EasyLink</td>
            <td>9/16/2024</td>
            <td>6/30/24</td>
            <td>8/1/24</td>
          </tr>
        </table>
      </div>
    </article>
    """
    path = tmp_path / "notice.html"
    path.write_text(html, encoding="utf-8")

    assert extract_etherwan_eol_notice_rows(path) == []


def test_robustel_eol_policy_maps_services_and_software_support(tmp_path):
    html = """
    <table>
      <tr>
        <td>Product Name</td>
        <td>EoL Effective Date</td>
        <td>End of Sale Date</td>
        <td>End of Services Date</td>
        <td>End of Software Support Date</td>
        <td>Replacement Product</td>
      </tr>
      <tr>
        <td>R3010</td>
        <td>2024/12/23</td>
        <td>2025/06/23</td>
        <td>2027/06/23</td>
        <td>2027/06/23</td>
        <td>EV8100 NOTE: Replacement product functions vary</td>
      </tr>
    </table>
    """
    path = tmp_path / "robustel_eol_and_pcn_policy.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_robustel_eol_policy_rows(path)

    assert rows == [
        {
            "Model": "R3010",
            "Part Number": "R3010",
            "Product Name": "R3010",
            "Description": "Robustel product lifecycle policy row",
            "Product Status": "Lifecycle policy schedule",
            "_source_table": "robustel_eol_and_pcn_policy.html table 1",
            "_source_hint": "Robustel EOL policy table import",
            "_source_url": "https://robustel.com/eol-and-pcn/",
            "_review_policy": "robustel_services_and_software_support_end",
            "_aliases": ["R3010", "Robustel R3010"],
            "_prefer_model": True,
            "Announcement Date": "2024-12-23",
            "End of Sale": "2025-06-23",
            "End of Service": "2027-06-23",
            "End of Support": "2027-06-23",
            "End of Software Support": "2027-06-23",
            "End of Security Updates": "2027-06-23",
            "Replacement Products": "EV8100",
        }
    ]
    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2025-06-23"
    assert dates["end_of_support"] == "2027-06-23"
    assert dates["end_of_service"] == "2027-06-23"
    assert dates["end_of_vulnerability"] == "2027-06-23"


def test_hillstone_eol_policy_splits_models_and_maps_terms(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical"
          href="https://www.hillstonenet.com/more/services/end-of-life-policy-and-announcement/" />
      </head>
      <body>
        <table>
          <tr>
            <td>Models</td>
            <td>End of Sales Date</td>
            <td>End of Software Support Date</td>
            <td>End of Hardware Support Date</td>
          </tr>
          <tr>
            <td>Hillstone I1850, S1060, S1560, IOC-S-4SFP-L</td>
            <td>Sep. 30th 2025</td>
            <td>Sep. 30th 2030</td>
            <td>Sep. 30th 2030</td>
          </tr>
          <tr>
            <td>Hillstone X9180 Data Center Firewall</td>
            <td>Dec. 31st 2024</td>
            <td>Dec. 31st 2029</td>
            <td>Dec. 31st 2029</td>
          </tr>
          <tr>
            <td>IOC-2XFP-Lite-M</td>
            <td>Dec. 31st 2018</td>
            <td>NA</td>
            <td>Dec. 31st 2023</td>
          </tr>
          <tr>
            <td>Hillstone M/G Series NGFW*</td>
            <td>Dec. 1st 2015</td>
            <td>Dec. 1st 2018</td>
            <td>Dec. 1st 2020</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "end_of_life_policy_and_announcement.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_hillstone_eol_policy_rows(path)

    assert [row["Model"] for row in rows[:4]] == [
        "I1850",
        "S1060",
        "S1560",
        "IOC-S-4SFP-L",
    ]
    assert rows[0]["End of Sale"] == "2025-09-30"
    assert rows[0]["End of Software Support"] == "2030-09-30"
    assert rows[0]["End of Security Updates"] == "2030-09-30"
    assert rows[0]["End of Hardware Support Date"] == "2030-09-30"
    assert rows[4]["Model"] == "X9180"
    assert rows[4]["Product Name"] == "Hillstone X9180 Data Center Firewall"
    assert rows[5]["End of Support"] == "2023-12-31"
    assert "End of Software Support" not in rows[5]
    assert rows[6]["Model"] == "M/G Series NGFW"
    assert rows[6]["_source_url"] == (
        "https://www.hillstonenet.com/more/services/end-of-life-policy-and-announcement/"
    )

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2025-09-30"
    assert dates["end_of_support"] == "2030-09-30"
    assert dates["end_of_vulnerability"] == "2030-09-30"


def test_neousys_eol_products_parser_keeps_eol_as_review_only(tmp_path):
    html = """
    <html>
      <head>
        <meta property="og:url"
          content="https://www.neousys-tech.com/en/product/end-of-life-products/eol-products-and-suggested-replacements" />
      </head>
      <body>
        <table>
          <tr>
            <td>Model</td>
            <td>Downloads</td>
            <td>Suggested Replacement</td>
            <td>EOL date</td>
          </tr>
          <tr>
            <td>Nuvo-6108GC</td>
            <td>Link</td>
            <td>Nuvo-10108GC</td>
            <td>2025/12/31</td>
          </tr>
          <tr>
            <td>POC-200/ 120 Series</td>
            <td>POC-200 / 120</td>
            <td>POC-400 / POC-40</td>
            <td>2022/02/28</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "end_of_life_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_neousys_eol_product_rows(path)

    assert len(rows) == 2
    assert rows[0]["Model"] == "Nuvo-6108GC"
    assert rows[0]["End of Life"] == "2025-12-31"
    assert rows[0]["Replacement Products"] == "Nuvo-10108GC"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "neousys_eol_date_not_security_eol"
    assert rows[0]["_source_url"] == (
        "https://www.neousys-tech.com/en/product/end-of-life-products/"
        "eol-products-and-suggested-replacements"
    )
    assert rows[1]["Model"] == "POC-200/ 120 Series"
    assert rows[1]["Replacement Products"] == "POC-400 / POC-40"

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_life"] == "2025-12-31"
    assert dates["end_of_support"] is None
    assert dates["end_of_vulnerability"] is None


def test_axiomtek_product_eol_parser_imports_only_notice_table(tmp_path):
    html = """
    <html>
      <body>
        <a href="/ePaperView.aspx?ItemId=4865&t=278">here</a>
        <table>
          <tr><td>FEATURED PRODUCTS</td></tr>
          <tr><td>CAPA322</td><td>IPC970</td><td>AX92325</td></tr>
        </table>
        <table>
          <tr>
            <td>Model Name</td><td>Last-Order Date</td>
            <td>EOL Date</td><td>Replacement</td>
          </tr>
          <tr>
            <td>PICO880</td><td>2022/10/31</td>
            <td>2024/03/01</td><td>PICO500</td>
          </tr>
          <tr>
            <td>eBOX638-842-FL</td><td>2022/10/31</td>
            <td>2023/01/31</td><td>eBOX710-521-FL , eBOX700-891-FL</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "product_eol_notice_2022_07.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_axiomtek_product_eol_rows(path)

    assert [row["Model"] for row in rows] == ["PICO880", "eBOX638-842-FL"]
    assert rows[0]["End of Sale"] == "2022-10-31"
    assert rows[0]["End of Life"] == "2024-03-01"
    assert rows[0]["Replacement Products"] == "PICO500"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "axiomtek_eol_not_final_security_support_end"
    assert rows[0]["_source_url"] == "https://www.axiomtek.com/ePaperView.aspx?ItemId=4865&t=278"
    assert rows[1]["Replacement Products"] == "eBOX710-521-FL , eBOX700-891-FL"

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2022-10-31"
    assert dates["end_of_life"] == "2024-03-01"
    assert dates["end_of_support"] is None
    assert dates["end_of_vulnerability"] is None


def test_bcm_advanced_research_eol_notice_parser_splits_models_and_last_buy(tmp_path):
    html = """
    <html>
      <body>
        <table>
          <tr>
            <td>04/06/2020</td>
            <td>
              End of Life notification for multiple BCM products.
              EOL Product List: MX87QD BI260-87QD ESM-QM87 Series
              BOX-81H-3DCM (310547-03/ 31-1603).
            </td>
            <td></td>
          </tr>
          <tr>
            <td>11/04/2016</td>
            <td>
              End of Life notification for the BCM RX77Q Micro ATX motherboard.
              Last time buy orders will be accepted through April 28, 2017.
            </td>
          </tr>
          <tr>
            <td>02/20/2026</td>
            <td>End of Life notification (EOL) for the ESM-CFH COMe module.</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "bcm_eol_notices.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_bcm_advanced_research_eol_notice_rows(path)

    assert [row["Model"] for row in rows] == [
        "MX87QD",
        "BI260-87QD",
        "ESM-QM87 Series",
        "BOX-81H-3DCM",
        "RX77Q",
        "ESM-CFH",
    ]
    assert rows[0]["Announcement Date"] == "2020-04-06"
    assert "End of Sale" not in rows[0]
    assert rows[4]["Announcement Date"] == "2016-11-04"
    assert rows[4]["End of Sale"] == "2017-04-28"
    assert rows[5]["_status_only_review"] is True
    assert rows[5]["_review_policy"] == "bcm_eol_notice_not_security_eol"

    dates = lifecycle_dates(rows[4])
    assert dates["announcement"] == "2016-11-04"
    assert dates["end_of_sale"] == "2017-04-28"
    assert dates["end_of_support"] is None
    assert dates["end_of_vulnerability"] is None


def test_milesight_eol_announcement_parser_preserves_rowspanned_models(tmp_path):
    html = """
    <html>
      <head>
        <meta property="og:url"
          content="https://www.milesight.com/iot/news/product-end-of-life-announcement-in-july" />
      </head>
      <body>
        <p>Xiamen, China, July 31, 2025 - Milesight hereby announces the
        discontinuation of selected product models. The affected products will
        no longer be available for sale with future updates.</p>
        <p>End-of-Life Date: June 15 th, 2025</p>
        <table>
          <tr><td>Type</td><td>EOL Model</td><td>Recommended Replacement</td></tr>
          <tr><td>Sensor</td><td>EM300-CL-868M</td><td>No recommended replacement</td></tr>
          <tr><td>EM300-CL-915M</td></tr>
        </table>
        <p>End-of-Life Date: July 1 st, 2025</p>
        <table>
          <tr><td>Type</td><td>EOL Model</td><td>Recommended Replacement</td></tr>
          <tr><td>LoRaWAN ® Gateway</td><td>UG65-L04EU-868M-EA</td><td>UG65-L08GL-868M/915M-EA</td></tr>
          <tr><td>UG65-L04EU-915M-EA</td></tr>
          <tr><td>UG67-L04EU-868M</td><td>UG67-L08GL-868M/915M</td></tr>
          <tr><td>UG67-L04EU-915M</td></tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "product_end_of_life_announcement_in_july.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_milesight_eol_announcement_rows(path)

    assert [row["Model"] for row in rows] == [
        "EM300-CL-868M",
        "EM300-CL-915M",
        "UG65-L04EU-868M-EA",
        "UG65-L04EU-915M-EA",
        "UG67-L04EU-868M",
        "UG67-L04EU-915M",
    ]
    assert rows[0]["Announcement Date"] == "2025-07-31"
    assert rows[0]["End of Life"] == "2025-06-15"
    assert rows[0]["End of Sale"] == "2025-06-15"
    assert "Replacement Products" not in rows[0]
    assert rows[2]["Replacement Products"] == "UG65-L08GL-868M/915M-EA"
    assert rows[3]["Replacement Products"] == "UG65-L08GL-868M/915M-EA"
    assert rows[4]["Replacement Products"] == "UG67-L08GL-868M/915M"
    assert rows[5]["Replacement Products"] == "UG67-L08GL-868M/915M"
    assert all(row["_force_lifecycle_review"] is True for row in rows)
    assert rows[0]["_source_url"] == (
        "https://www.milesight.com/iot/news/product-end-of-life-announcement-in-july"
    )

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2025-07-31"
    assert dates["end_of_life"] == "2025-06-15"
    assert dates["end_of_sale"] == "2025-06-15"
    assert dates["end_of_support"] is None
    assert dates["end_of_vulnerability"] is None


def test_digital_loggers_discontinued_parser_splits_grouped_product_cells(tmp_path):
    products_html = """
    <html>
      <body>
        <h2>Energy Control and Switching</h2>
        <table>
          <tr><td>Current Products</td></tr>
          <tr><td><a>Ethernet Power Controller 7</a> (EPCR7)</td></tr>
          <tr><td colspan="3">Superseded and Discontinued Products</td></tr>
          <tr>
            <td><a>Vertical PDU (special order)</a> (VPDU)</td>
            <td><a>Automatic Transfer Switch (special order)</a><br>(ATS)</td>
            <td><a>Web Power Switch 7</a> (LPC 7)</td>
          </tr>
        </table>
      </body>
    </html>
    """
    support_html = """
    <html>
      <body>
        <h2>AC Energy Control and Switching</h2>
        <table>
          <tr><td><strong>Current Products</strong></td></tr>
          <tr><td><strong>Superseded and Discontinued Products</strong></td></tr>
          <tr>
            <td>Ethernet Power Controller 6<a href="/EPCR6faqs.html">FAQs</a>
              <a href="/epcr6.html">Overview</a> <a href="/update_epcr6.html">Firmware</a></td>
            <td>Web Power Switch (LPC - LPC7)<a href="/lpc7faqs.html">FAQs</a></td>
            <td><a>Vertical PDU (special order)</a> (VPDU)</td>
          </tr>
        </table>
      </body>
    </html>
    """
    products_path = tmp_path / "digital_loggers_products_superseded_discontinued.html"
    support_path = tmp_path / "digital_loggers_support_superseded_discontinued.html"
    products_path.write_text(products_html, encoding="utf-8")
    support_path.write_text(support_html, encoding="utf-8")

    product_rows = extract_digital_loggers_discontinued_rows(products_path)
    support_rows = extract_digital_loggers_discontinued_rows(support_path)

    assert [row["Model"] for row in product_rows] == ["VPDU", "ATS", "LPC 7"]
    assert support_rows == []
    assert product_rows[0]["Product Name"] == "Vertical PDU (special order)"
    assert product_rows[0]["Product Status"] == "Superseded and Discontinued Products"
    assert all(row["_status_only_review"] is True for row in product_rows)
    assert all(
        row["_review_policy"] == "digital_loggers_discontinued_not_security_eol"
        for row in product_rows
    )
    assert product_rows[0]["_source_url"] == "https://www.digital-loggers.com/dli.products.html"

    dates = lifecycle_dates(product_rows[0])
    assert dates["end_of_sale"] is None
    assert dates["end_of_life"] is None
    assert dates["end_of_support"] is None


def test_netskope_sdwan_lifecycle_parser_maps_support_month_year(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical" href="https://www.netskope.com/sd-wan-lifecycle-announcements" />
      </head>
      <body>
        <h2>Product Lifecycle Milestones</h2>
        <p><strong>End-of-Sale Date:</strong> This is the final date on which
        Netskope will sell the product through authorized point-of-sale channels.</p>
        <p><strong>End-of-Life/ End-of-Support Date:</strong> Final date to
        receive applicable services, hardware and software support.</p>
        <table>
          <tr>
            <th>Product</th>
            <th>Announcement Date</th>
            <th>End-of-Sale Date</th>
            <th>End-of-Support/<br>End-of-Life Report</th>
            <th></th>
          </tr>
          <tr>
            <td>NSG-100</td>
            <td>Jan 25, 2024</td>
            <td>Jun 24, 2025</td>
            <td>Jun, 2030</td>
            <td>Download announcement</td>
          </tr>
          <tr>
            <td>NSG-1000</td>
            <td>Apr 15, 2023</td>
            <td>Sept 15, 2023</td>
            <td>Apr, 2028</td>
            <td>Download announcement</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "netskope_sdwan_lifecycle_announcements.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_netskope_sdwan_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == ["NSG-100", "NSG-1000"]
    assert rows[0]["Announcement Date"] == "2024-01-25"
    assert rows[0]["End of Sale"] == "2025-06-24"
    assert rows[0]["End of Support"] == "2030-06-30"
    assert rows[0]["End of Life"] == "2030-06-30"
    assert rows[1]["End of Sale"] == "2023-09-15"
    assert rows[1]["End of Support"] == "2028-04-30"
    assert rows[0]["_source_url"] == "https://www.netskope.com/sd-wan-lifecycle-announcements"

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2024-01-25"
    assert dates["end_of_sale"] == "2025-06-24"
    assert dates["end_of_life"] == "2030-06-30"
    assert dates["end_of_support"] == "2030-06-30"
    assert dates["end_of_vulnerability"] is None


def test_pica8_product_bulletin_merges_milestones_and_affected_parts(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical" href="https://www.pica8.com/support/warranty-and-agreements/" />
      </head>
      <body>
        <h1>Pica8 Product Bulletins</h1>
        <p>Pica8 Software Inc. announces the end-of-sale and end-of-life dates
        for the PICA8 P-3780, P-3920 and P-3290.</p>
        <h3>Table 1. End-of-Life Milestones and Dates</h3>
        <table>
          <tr><th>Milestone</th><th>Definition</th><th>Date</th></tr>
          <tr>
            <td>Last Day of Order</td>
            <td>The last date to order the product.</td>
            <td>September 30, 2015</td>
          </tr>
          <tr>
            <td>End Of Support</td>
            <td>After this date, PICA8 will not provide any support service.</td>
            <td>March 31, 2018</td>
          </tr>
        </table>
        <h3>Table 2. Product Part Numbers Affected by This Announcement</h3>
        <table>
          <tr>
            <th>End-of-Sale Product Part Number</th>
            <th>Product Description</th>
          </tr>
          <tr>
            <td>Last Day of Order</td>
            <td>The last date to order the product.</td>
          </tr>
          <tr>
            <td>P-3780</td>
            <td>Non-blocking 48x10GE SFP+ switch.</td>
          </tr>
          <tr>
            <td>P-3920</td>
            <td>Non-blocking 48x10GE SFP+ with 4X40GE ports.</td>
          </tr>
          <tr>
            <td>P-3290</td>
            <td>Non-blocking 48xGE switch with 4x10GE SFP+ uplinks.</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "pica8_warranty_and_agreements_product_bulletin.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_pica8_product_bulletin_rows(path)

    assert [row["Model"] for row in rows] == ["P-3780", "P-3920", "P-3290"]
    assert rows[0]["End of Sale"] == "2015-09-30"
    assert rows[0]["End of Support"] == "2018-03-31"
    assert "End of Life" not in rows[0]
    assert rows[0]["Description"] == "Non-blocking 48x10GE SFP+ switch."
    assert rows[0]["_source_url"] == "https://www.pica8.com/support/warranty-and-agreements/"
    assert "Last Day of Order" not in [row["Model"] for row in rows]

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2015-09-30"
    assert dates["end_of_support"] == "2018-03-31"
    assert dates["end_of_life"] is None


def test_ruijie_eol_page_maps_product_service_end_to_support(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical" href="https://www.ruijie.com/en-global/support/xw/75554" />
        <title>End of Life Announcement for M8610-CM II - Ruijie Networks</title>
      </head>
      <body>
        <h2 id="h_Title">End of Life Announcement for M8610-CM II</h2>
        <div id="d_content">
          <p><strong>No.: EOL-2019-0004</strong></p>
          <p><strong>Date: 06/10/2019</strong></p>
          <p>Table 1 describes the end of life milestones.</p>
          <table>
            <tr><td>Milestone</td><td>Definition</td><td>Date</td></tr>
            <tr>
              <td>End of Life(EOL) Date</td>
              <td>The last date of product service period. Product service includes:
              bug fixes, enquiry and product maintenance.</td>
              <td>June 10, 2019</td>
            </tr>
          </table>
          <table>
            <tr><td>EOL product</td><td>Replacement product</td></tr>
            <tr><td>M8610-CM II</td><td>NONE</td></tr>
          </table>
        </div>
      </body>
    </html>
    """
    path = tmp_path / "eol_switch_75554.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_ruijie_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "M8610-CM II"
    assert rows[0]["End of Life"] == "2019-06-10"
    assert rows[0]["End of Support"] == "2019-06-10"
    assert "Announcement Date" not in rows[0]
    assert "Replacement" not in rows[0]
    assert rows[0]["_source_url"] == "https://www.ruijie.com/en-global/support/xw/75554"

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_life"] == "2019-06-10"
    assert dates["end_of_support"] == "2019-06-10"


def test_ruijie_old_eos_page_keeps_contract_dates_out_of_eol(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical" href="https://www.ruijie.com/en-global/support/xw/61734" />
      </head>
      <body>
        <h2 id="h_Title">End of Sale Announcement for RG-ACE1000 V3.0</h2>
        <div id="d_content">
          <p><strong>Date: 5/2/2013</strong></p>
          <table>
            <tr><td>Milestone</td><td>Definition</td><td>Date</td></tr>
            <tr><td>End of Sale Date</td><td>Last order date</td><td>February 5, 2013</td></tr>
            <tr><td>End of Software Maintenance Date</td><td>Last firmware or bug fixes</td><td>February 5, 2015</td></tr>
            <tr><td>End of New Life Attachment Date</td><td>New service contracts</td><td>February 5, 2014</td></tr>
            <tr><td>End Of Life Contract Renewal Date</td><td>Renew service contract</td><td>February 5, 2017</td></tr>
            <tr><td>End of Life Date</td><td>All support services unavailable</td><td>February 5, 2018</td></tr>
          </table>
          <table>
            <tr><td>EOS product</td><td>Replacement product</td></tr>
            <tr><td>RG-ACE1000 V3.0</td><td>None</td></tr>
          </table>
        </div>
      </body>
    </html>
    """
    path = tmp_path / "eos_gateway_61734.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_ruijie_lifecycle_rows(path)

    assert len(rows) == 1
    assert rows[0]["End of Sale"] == "2013-02-05"
    assert rows[0]["End of Support"] == "2015-02-05"
    assert rows[0]["End of Life"] == "2018-02-05"
    assert "2017-02-05" not in rows[0].values()

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2013-02-05"
    assert dates["end_of_support"] == "2015-02-05"
    assert dates["end_of_life"] == "2018-02-05"


def test_ruijie_eos_rowspan_service_plan_maps_software_and_support_dates(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical" href="https://www.ruijie.com/en-global/support/xw/eos-rg-inc-pro" />
      </head>
      <body>
        <h2 id="h_Title">End-of-Sale Announcement in International Market for Ruijie RG-INC-PRO Series</h2>
        <div id="d_content">
          <p><strong>Date:</strong> 2025-08-31</p>
          <table>
            <tr>
              <td>Country or Region</td>
              <td>End-of-Sale Model</td>
              <td>End-of-Sale Product Description</td>
              <td>Replacement Model</td>
              <td>Replacement Description</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-INC-PRO-BASE</td>
              <td>RG-INC-PRO Software, excluding nodes</td>
              <td rowspan="2">RG-UNC-AS</td>
              <td rowspan="2">RG-UNC AS software license</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-INC-PRO-SW-NMC</td>
              <td>RG-INC-PRO Switching Device Management Component License</td>
            </tr>
          </table>
          <table>
            <tr>
              <td>Country or Region</td>
              <td>End-of-Sale Model</td>
              <td>End-of-Sale Date</td>
              <td>End of Official Software Releases Date</td>
              <td>End of Software Maintenance Releases Date</td>
              <td>End of New Service Attachment Date</td>
              <td>End of (Hardware) Service Contract Renewal Date</td>
              <td>Last Date of Support</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-INC-PRO-BASE</td>
              <td rowspan="2">August 20, 2025</td>
              <td rowspan="2">October 31, 2025</td>
              <td rowspan="2">August 31, 2027</td>
              <td rowspan="2">August 31, 2026</td>
              <td rowspan="2">August 31, 2027</td>
              <td rowspan="2">August 31, 2027</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-INC-PRO-SW-NMC</td>
            </tr>
          </table>
        </div>
      </body>
    </html>
    """
    path = tmp_path / "eos_application_eos_rg_inc_pro.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_ruijie_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == [
        "RG-INC-PRO-BASE",
        "RG-INC-PRO-SW-NMC",
    ]
    assert rows[0]["End of Sale"] == "2025-08-20"
    assert rows[0]["End of Support"] == "2027-08-31"
    assert rows[0]["End of Service"] == "2027-08-31"
    assert rows[0]["Replacement"] == "RG-UNC-AS"
    assert rows[1]["End of Sale"] == "2025-08-20"
    assert rows[1]["Replacement"] == "RG-UNC-AS"

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] == "2025-08-20"
    assert dates["end_of_support"] == "2027-08-31"
    assert dates["end_of_service"] == "2027-08-31"


def test_ruijie_highlighted_model_text_is_rejoined(tmp_path):
    html = """
    <html>
      <head><link rel="canonical" href="https://www.ruijie.com/en-global/support/xw/eg210g" /></head>
      <body>
        <h2 id="h_Title">End of Sale Announcement for RG-EG210G-E and RG-EG210G-P</h2>
        <div id="d_content">
          <p><strong>Date:</strong> 2024-08-30</p>
          <table>
            <tr>
              <td>Country or Region</td>
              <td>End-of-Sale Model</td>
              <td>End-of-Sale Product Description</td>
              <td>Replacement Model</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-EG210G-E</td>
              <td>10-Port Gigabit Cloud Managed Gateway</td>
              <td>RG-EG310GH-E</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-<span>EG210</span>G-P</td>
              <td>10 Gigabit Ports, 8 PoE+ ports</td>
              <td>RG-<span>EG210</span>G-P-V3</td>
            </tr>
          </table>
          <table>
            <tr>
              <td>Country or Region</td>
              <td>End-of-Sale Model</td>
              <td>End-of-Sale Date</td>
              <td>End of Software Maintenance Releases Date</td>
              <td>Last Date of Support</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td><p>RG-EG210G-E</p><p>RG-EG210G-P</p></td>
              <td>Aug 30, 2024</td>
              <td>Aug 30, 2026</td>
              <td>Aug 30, 2029</td>
            </tr>
          </table>
        </div>
      </body>
    </html>
    """
    path = tmp_path / "eos_router_eg210g_e_eg210g_p_eos.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_ruijie_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == ["RG-EG210G-E", "RG-EG210G-P"]
    assert all(row["End of Sale"] == "2024-08-30" for row in rows)
    assert all(row["End of Support"] == "2026-08-30" for row in rows)
    assert all(row["End of Service"] == "2029-08-30" for row in rows)


def test_ruijie_eos_transposed_service_plan_maps_each_model(tmp_path):
    html = """
    <html>
      <head>
        <link rel="canonical" href="https://www.ruijie.com/en-global/support/xw/eos-rg-sap885-sp-w-rg-sap150-sp-w" />
      </head>
      <body>
        <h2 id="h_Title">End-of-Sale Announcement in International Market for Ruijie RG-SAP885-SP and RG-SAP150-SP-W</h2>
        <div id="d_content">
          <p><strong>Date:</strong> 2025-07-10</p>
          <table>
            <tr>
              <td>Country or Region</td>
              <td>End-of-Sale Model</td>
              <td>End-of-Sale Product Description</td>
              <td>Replacement Model</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-SAP885-SP</td>
              <td>Wi-Fi 6E indoor high-density wireless access point</td>
              <td>NA</td>
            </tr>
            <tr>
              <td>International Market</td>
              <td>RG-SAP150-SP-W</td>
              <td>Wi-Fi 5 dual-radio wireless access point</td>
              <td>NA</td>
            </tr>
          </table>
          <table>
            <tr><td>End-of-Sale Product Service Plan</td><td>RG-SAP885-SP</td><td>RG-SAP150-SP-W</td></tr>
            <tr><td>Country or Region</td><td>International Market</td><td>International Market</td></tr>
            <tr><td>End-of-Sale Date</td><td>July 10, 2025</td><td>July 10, 2025</td></tr>
            <tr><td>End of Software Maintenance Release Date</td><td>July 10, 2027</td><td>July 10, 2027</td></tr>
            <tr><td>Last Date of Support</td><td>July 10, 2030</td><td>July 10, 2030</td></tr>
          </table>
        </div>
      </body>
    </html>
    """
    path = tmp_path / "eos_wireless_eos_rg_sap885_sp_w_rg_sap150_sp_w.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_ruijie_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == ["RG-SAP885-SP", "RG-SAP150-SP-W"]
    assert all(row["End of Sale"] == "2025-07-10" for row in rows)
    assert all(row["End of Support"] == "2027-07-10" for row in rows)
    assert all(row["End of Service"] == "2030-07-10" for row in rows)


def test_volktek_eos_eol_parser_imports_status_only_rows(tmp_path):
    html = """
    <html>
      <head><link rel="canonical" href="https://www.volktek.com/support_en_3.php" /></head>
      <body>
        <p>The following products are no longer being sold or supported.</p>
        <h2>EOS (End-of-Sale)</h2>
        <table>
          <tr><td>Model Name</td><td>Substituted Product</td></tr>
          <tr><td>HMC-672 series</td><td>HMC-672E series</td></tr>
          <tr><td>IEN-8328P</td><td>N/A</td></tr>
        </table>
        <h2>EOL (End-of-Life)</h2>
        <table>
          <tr><td>Model Name</td><td>Substituted Product</td></tr>
          <tr><td>MEN-5428</td><td>5100-24GT2GS</td></tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "support_eos_eol.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_volktek_eos_eol_rows(path)

    assert [row["Model"] for row in rows] == [
        "HMC-672 series",
        "IEN-8328P",
        "MEN-5428",
    ]
    assert rows[0]["Replacement Products"] == "HMC-672E series"
    assert "Replacement Products" not in rows[1]
    assert rows[2]["Replacement Products"] == "5100-24GT2GS"
    assert all(row["_status_only_review"] is True for row in rows)
    assert all(row["_review_policy"] == "volktek_eos_eol_status_without_dates" for row in rows)
    assert rows[0]["_source_url"] == "https://www.volktek.com/support_en_3.php"

    dates = lifecycle_dates(rows[0])
    assert dates["end_of_sale"] is None
    assert dates["end_of_life"] is None
    assert dates["end_of_support"] is None
    assert dates["end_of_vulnerability"] is None


def test_nvt_phybridge_eol_parser_ignores_milestone_definition_rows(tmp_path):
    html = """
    <html>
      <head><link rel="canonical" href="https://www.nvtphybridge.com/eol/" /></head>
      <body>
        <table>
          <tr><td>Milestone</td><td>Definition</td><td>Date</td></tr>
          <tr>
            <td>End of life announcement</td>
            <td>Date of website announcement and issuing email notification.</td>
            <td>1/20/2022 EOL Notice</td>
          </tr>
          <tr>
            <td>End of sale date</td>
            <td>The final date to order the product.</td>
            <td>1/20/2022</td>
          </tr>
          <tr>
            <td>End of Software/Hardware Maintenance Date*</td>
            <td>Final release date of software maintenance releases or bug fixes.</td>
            <td>1/20/2030</td>
          </tr>
          <tr>
            <td>Last Date of Support*</td>
            <td>Final date service and support will be provided.</td>
            <td>1/20/2031</td>
          </tr>
        </table>
        <table>
          <tr><td>End of Sale Product Part Numbers</td><td>Product Description</td></tr>
          <tr><td>NV-CLR-024</td><td>CLEER 24-Port Managed Switch</td></tr>
        </table>
        <table>
          <tr>
            <td>End of Life Part Number</td>
            <td>Recommended Replacement Part Number</td>
            <td>Replacement Product Description</td>
          </tr>
          <tr><td>NV-CLR-024</td><td>NV-CLR-024-10G</td><td>Layer 3 switch</td></tr>
        </table>
        <table>
          <tr>
            <td>Product Code</td><td>Product Description</td>
            <td>CHARIOT REPLACEMENT PRODUCT(S)</td><td>Notes</td>
            <td>DATE OF EOL</td><td>Final Support Date</td>
          </tr>
          <tr>
            <td>NV-1613A</td><td>16-Channel Passive Hub</td>
            <td>PoLRE Family OR FLEX Family</td><td>Upgrade guidance</td>
            <td>2014-03-31</td><td>2019-03-30</td>
          </tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "end_of_life_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_nvt_phybridge_eol_rows(path)

    assert [row["Model"] for row in rows] == ["NV-CLR-024", "NV-1613A"]
    assert rows[0]["Announcement Date"] == "2022-01-20"
    assert rows[0]["End of Sale"] == "2022-01-20"
    assert rows[0]["End of Support"] == "2030-01-20"
    assert rows[0]["End of Security Updates"] == "2030-01-20"
    assert rows[0]["End of Service"] == "2031-01-20"
    assert rows[0]["Replacement Products"] == "NV-CLR-024-10G"
    assert rows[0]["Description"] == "CLEER 24-Port Managed Switch"
    assert rows[1]["End of Life"] == "2014-03-31"
    assert rows[1]["End of Support"] == "2019-03-30"
    assert rows[1]["End of Security Updates"] == "2019-03-30"
    assert rows[1]["Replacement Products"] == "PoLRE Family OR FLEX Family"

    dates = lifecycle_dates(rows[0])
    assert dates["announcement"] == "2022-01-20"
    assert dates["end_of_sale"] == "2022-01-20"
    assert dates["end_of_support"] == "2030-01-20"
    assert dates["end_of_service"] == "2031-01-20"
    assert dates["end_of_vulnerability"] == "2030-01-20"


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


def test_acti_eol_json_imports_service_schedule_as_review_rows(tmp_path):
    data = [
        {
            "Model": "Z97",
            "Stage": "C6.2",
            "ProductType": "Fixed Dome",
            "ClearanceStart": "2026-03-30",
            "ClearanceEnd": "2026-03-30",
            "EngineeringPhase": "2026-09-26",
            "StandardWarranty": "2028-03-29",
            "TechnicalSupport": "2029-03-29",
            "ReplacementModelList": [
                {"Model": "Z714", "Stage": "C6.2"},
            ],
        }
    ]
    path = tmp_path / "eol_search_results.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    rows = extract_rows(path, "acti")

    assert len(rows) == 1
    assert rows[0]["Model"] == "Z97"
    assert rows[0]["Description"] == "Fixed Dome discontinued product"
    assert rows[0]["Announcement Date"] == "2026-03-30"
    assert rows[0]["End of Sale"] == "2026-03-30"
    assert rows[0]["End of Support"] == "2029-03-29"
    assert rows[0]["Replacement Product"] == "Z714 (C6.2)"
    assert rows[0]["_aliases"] == ["Z97 C6.2"]
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "acti_technical_support_not_security_update_eol"


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
            "End of Security Updates": "2022-10-31",
            "End of OS Updates": "2017-12-31",
            "Replacement Products": "TS-264",
            "_source_table": "product-support-status-filtered-nas.html support status table 1",
            "_source_hint": "QNAP product support status table import",
        }
    ]


def test_qnap_product_status_api_imports_hardware_lifecycle_rows(tmp_path):
    payload = {
        "success": True,
        "results": {
            "productLineList": {"1": "NAS / Expansion"},
            "modelList": [
                {
                    "display_name": "TS-259 Pro+",
                    "name": "TS-259 Pro+",
                    "product_line_id": 1,
                    "is_eol": True,
                    "is_eos": True,
                    "eol_detail": {
                        "hardware_repair_of_replacement": "Discontinued",
                        "os_and_application_updates_and_maintenance": "2017-12 (QTS 4.2)",
                        "technical_support_and_security_updates": "2022-10",
                        "recommended_replacement": "TS-264",
                    },
                },
                {
                    "display_name": "TS-431P",
                    "name": "TS-431P",
                    "product_line_id": 1,
                    "is_eol": False,
                    "is_eos": True,
                    "eol_detail": {
                        "hardware_repair_of_replacement": "Limited",
                        "os_and_application_updates_and_maintenance": "Full",
                        "technical_support_and_security_updates": "Active",
                        "recommended_replacement": "TS-433",
                    },
                },
                {
                    "display_name": "EOL-no-date",
                    "name": "EOL-no-date",
                    "product_line_id": 1,
                    "is_eol": True,
                    "is_eos": True,
                    "eol_detail": {
                        "hardware_repair_of_replacement": "Discontinued",
                        "os_and_application_updates_and_maintenance": "None",
                        "technical_support_and_security_updates": "None",
                        "recommended_replacement": "-",
                    },
                },
                {
                    "display_name": "QXP-830S-3808",
                    "name": "QXP-830S-3808",
                    "product_line_id": 9,
                    "is_eol": False,
                    "is_eos": False,
                    "eol_detail": [],
                },
            ],
        },
    }
    path = tmp_path / "product_status_api.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    rows = extract_qnap_product_status_api_rows(path)

    assert rows == [
        {
            "Model": "TS-259 Pro+",
            "Product Name": "TS-259 Pro+",
            "Description": "NAS / Expansion",
            "Product Status": "End-of-life (EOL)",
            "Replacement Products": "TS-264",
            "End of Support": "2022-10-31",
            "End of Security Updates": "2022-10-31",
            "End of OS Updates": "2017-12-31",
            "_source_table": "product_status_api.json modelList",
            "_source_hint": "QNAP product support status API import",
        },
    ]


def test_qnap_os_lifecycle_imports_eol_dates_from_status_page(tmp_path):
    html = """
    <script>
    var osLocaleData = {
      "chapters": [
        {
          "title": "End-of-Life (EOL) Dates",
          "contents": [
            {
              "title": "QTS",
              "table": {
                "tbody": [
                  {
                    "version": "4.3 (LTS)",
                    "availability": "2017-05",
                    "production": "2018-05",
                    "maintenance": "2019-05",
                    "lts": "2024-02"
                  },
                  {
                    "version": "5.0",
                    "availability": "2021-10",
                    "production": "2022-09",
                    "maintenance": "2023-09",
                    "lts": "--"
                  }
                ]
              }
            }
          ]
        }
      ]
    };
    </script>
    """
    path = tmp_path / "product_status.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_qnap_os_lifecycle_rows(path)

    assert rows == [
        {
            "Model": "QTS 4.3",
            "Part Number": "QTS 4.3",
            "Product Name": "QTS 4.3 (LTS)",
            "Description": "Software",
            "Product Status": "Operating system EOL date",
            "Announcement": "2017-05-31",
            "End of Support": "2024-02-29",
            "End of Security Updates": "2024-02-29",
            "Aliases": "QTS 4.3; QTS 4.3.x",
            "_source_table": "product_status.html QTS operating system lifecycle table",
            "_source_hint": "QNAP operating system lifecycle import",
        },
        {
            "Model": "QTS 5.0",
            "Part Number": "QTS 5.0",
            "Product Name": "QTS 5.0",
            "Description": "Software",
            "Product Status": "Operating system EOL date",
            "Announcement": "2021-10-31",
            "End of Support": "2023-09-30",
            "End of Security Updates": "2023-09-30",
            "Aliases": "QTS 5.0; QTS 5.0.x",
            "_source_table": "product_status.html QTS operating system lifecycle table",
            "_source_hint": "QNAP operating system lifecycle import",
        },
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


def test_hms_ewon_product_page_imports_new_raw_filename_variant(tmp_path):
    html = """
    <h1>Ewon Flexy 103 (End of Life)</h1>
    <p>Item number FLEXY10300_00MA</p>
    <p>The Ewon Flexy 103 has been designed for simple and cost effective
    remote data collection application.</p>
    """
    path = tmp_path / "ewon_flexy_103_end_of_life.html"
    path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(path, "hms_ewon") if row.get("_source_hint")]

    assert len(rows) == 1
    assert rows[0]["Model"] == "Ewon Flexy 103"
    assert rows[0]["Part Number"] == "FLEXY10300_00MA"
    assert rows[0]["_source_table"] == (
        "ewon_flexy_103_end_of_life.html product page"
    )
    assert rows[0]["_review_policy"] == "status_only_not_security_eol"


def test_hms_ewon_firmware_replacement_guide_imports_obsolete_supported_review_rows(tmp_path):
    html = """
    <h1>Ewon Product List: Firmware Versions and Replacement Guide</h1>
    <p>Although these devices remain supported on the Talk2M platform for now,
    they have been in the exit phase for several years.</p>
    <table>
      <tr>
        <th>Product family</th>
        <th>Models</th>
        <th>Serial Numbers</th>
        <th>Latest FW version*</th>
        <th>Upgrade process*</th>
      </tr>
      <tr>
        <td>Ewon Cosy+</td>
        <td>Cosy+ Ethernet</td>
        <td>####-####-25</td>
        <td>23.0s4</td>
        <td>Cosy+_update</td>
      </tr>
      <tr>
        <td>Ewon Cosy141</td>
        <td>Cosy 141 MPI port (Vipa)</td>
        <td>####-####-38</td>
        <td>11.3s0</td>
        <td>Cosy141_replacement</td>
      </tr>
      <tr>
        <td>Cosy 141 serial port</td>
        <td>####-####-39</td>
        <td>11.3s0</td>
      </tr>
      <tr>
        <td>Ewon legacy devices</td>
        <td>Ewon 4101CD</td>
        <td>####-####-43</td>
        <td>11.3s0</td>
        <td>EwonCD_replacement</td>
      </tr>
      <tr>
        <td>Ewon 2101CD MPI</td>
        <td>####-####-44</td>
        <td>11.3s0</td>
      </tr>
    </table>
    """
    path = tmp_path / "ewon_product_list_firmware_versions_replacement_guide.html"
    path.write_text(html, encoding="utf-8")

    rows = [
        row
        for row in extract_rows(path, "hms_ewon")
        if row.get("_source_hint")
        == "HMS Ewon obsolete device replacement guide import"
    ]

    assert [row["Model"] for row in rows] == [
        "Ewon Cosy 141 MPI port (Vipa)",
        "Ewon Cosy 141 serial port",
        "Ewon 4101CD",
        "Ewon 2101CD MPI",
    ]
    assert "Ewon Cosy+ Ethernet" not in [row["Model"] for row in rows]
    for row in rows:
        assert row["_force_lifecycle_review"] is True
        assert row["_review_policy"] == "hms_ewon_obsolete_but_talk2m_supported"
        assert row["Latest Firmware"] == "11.3s0"
        assert "End of Support" not in row
        assert "Security Updates End" not in row


def test_mitel_aastra_discontinued_rows_are_status_only_review(tmp_path):
    html = """
    <article>
      <p>The Aastra 390 phone has been discontinued.</p>
      <p>The Aastra 6725ip phone became the Mitel MiVoice 6725 Lync phone
      but it has now been discontinued.</p>
      <p>The Aastra 6731i phone became the Mitel 6731 SIP phone but it has
      now been discontinued .</p>
      <p>The Aastra 700 (pre-Version 3) became the Mitel 700 but it has now
      been discontinued. However, a related product, the Mitel MiVoice MX-ONE,
      is available.</p>
    </article>
    """
    path = tmp_path / "what_happened_aastra_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_mitel_lifecycle_rows(path)

    assert [row["Model"] for row in rows] == [
        "Aastra 390 phone",
        "Aastra 6725ip phone",
        "Aastra 6731i phone",
        "Aastra 700 (pre-Version 3)",
    ]
    for row in rows:
        assert row["_force_lifecycle_review"] is True
        assert row["_review_policy"] == "mitel_status_only_not_security_eol"
        assert "End of Support" not in row
        assert "End of Security Updates" not in row
    assert rows[1]["_aliases"] == [
        "Aastra 6725ip phone",
        "Mitel MiVoice 6725 Lync phone",
    ]


def test_mitel_exact_lifecycle_dates_use_policy_without_overstating_sales_rows(tmp_path):
    html = """
    <article>
      <p>MiCloud Connect reached end of sale in June 2022.</p>
      <p>Retail and Partner Delivered versions of MiCloud Flex reached end of
      sale on June 30, 2022. Wholesale versions of MiCloud Flex reached End
      of Sale on December 31, 2023. Existing customers on MiCloud Flex
      Wholesale will continue to be supported by Mitel, through Mitel partners,
      after this date.</p>
      <p>MiCloud Business reached end of sale in December 2019 and will be
      End of Life June 2024.</p>
      <p>ShoreTel 14.2 was renamed Mitel 14.2 when Mitel acquired ShoreTel
      in 2017. ShoreTel 14.2 / Mitel 14.2 reached end-of-life status in
      September 2020. This product is no longer available from Mitel.</p>
    </article>
    """
    path = tmp_path / "what_happened_mitel_products.html"
    path.write_text(html, encoding="utf-8")

    rows = {row["Model"]: row for row in extract_mitel_lifecycle_rows(path)}

    assert rows["MiCloud Connect"]["End of Sale"] == "2022-06-30"
    assert "End of Support" not in rows["MiCloud Connect"]
    assert rows["MiCloud Flex Retail and Partner Delivered"]["End of Sale"] == (
        "2022-06-30"
    )
    assert "End of Support" not in rows["MiCloud Flex Retail and Partner Delivered"]
    assert rows["MiCloud Flex Wholesale"]["End of Sale"] == "2023-12-31"
    assert rows["MiCloud Business"]["End of Sale"] == "2019-12-31"
    assert rows["MiCloud Business"]["End of Life"] == "2024-06-30"
    assert rows["MiCloud Business"]["End of Support"] == "2024-06-30"
    assert rows["MiCloud Business"]["End of Security Updates"] == "2024-06-30"
    assert rows["ShoreTel 14.2 / Mitel 14.2"]["End of Support"] == "2020-09-30"


def test_mitel_shoretel_connect_onsite_imports_exact_eots(tmp_path):
    html = """
    <article>
      <p>What happened to ShoreTel Connect Onsite? ShoreTel Connect Onsite was
      renamed MiVoice Connect. This platform entered into its Product Lifecycle
      Management Plan and the End of Technical Support will be December 31,
      2029. For MiVoice Connect customers, we have several options for
      upgrading to MiVoice Business.</p>
    </article>
    """
    path = tmp_path / "what_happened_shoretel_products.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_mitel_lifecycle_rows(path)

    assert rows == [
        {
            "Model": "MiVoice Connect",
            "Part Number": "MiVoice Connect",
            "Product Name": "MiVoice Connect",
            "Description": (
                "Mitel communications platform formerly ShoreTel Connect Onsite"
            ),
            "Product Status": "End of Technical Support scheduled",
            "Replacement Products": "MiVoice Business",
            "_source_table": (
                "what_happened_shoretel_products.html Mitel lifecycle article"
            ),
            "_source_hint": "Mitel lifecycle article import",
            "_prefer_model": True,
            "_aliases": ["ShoreTel Connect Onsite"],
            "End of Support": "2029-12-31",
            "End of Vulnerability Support": "2029-12-31",
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


def test_oring_mirrored_phase_out_notice_imports_but_sitemap_is_ignored(tmp_path):
    html = """
    <h1>Phase-out Model\uff1aRES-3242GC</h1>
    <p>Product End of Life / Change Notification</p>
    <time datetime="2017-01-23T08:00:00+08:00">2017-01-23</time>
    """
    notice_path = tmp_path / "nhedb__raw__phase-out-res-3242gc.html"
    notice_path.write_text(html, encoding="utf-8")

    sitemap_path = tmp_path / "nhedb__raw__sitemap-product-eol-links.html"
    sitemap_path.write_text(html, encoding="utf-8")

    rows = [row for row in extract_rows(notice_path, "oring") if row.get("_source_hint")]

    assert [row["Model"] for row in rows] == ["RES-3242GC"]
    assert rows[0]["Announcement Date"] == "2017-01-23"
    assert extract_rows(sitemap_path, "oring") == []


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


def test_schneider_apc_connexium_pdf_imports_explicit_product_support_end():
    text = """
    CN Information
    RED Flag Notice
    Product Name(s): ConneXium Unmanaged Switch 3TX
    Product Line Description: Modicon Network Switch (IDPAC) Document Issued: 01/13/2023
    Description of Change:
    Following the release of the new Modicon Switch Family, the below ConneXium unmanaged switch
    (TCSESU033FN0) will be reach end of commercialization effective December 31, 2023. The
    recommended replacement part (MCSESU053FN0) is listed below.

    EOC Product ConneXium Unmanaged Switch - 3TX (TCSESU033FN0)
    New Product Modicon Switch 5TX (MCSESU053FN0)

    Critical Dates
    Last Buy: Product Support Ends: Availability Date of New Product: End of Commercialization
    12/31/2023 12/31/2023 Available Now 12/31/2023
    Transition Tools:
    """

    rows = parse_schneider_apc_connexium_pdf_rows_from_text(
        text,
        "connexium_unmanaged_switch_end_of_commercialization_ral22am0003-idpac.pdf",
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["Model"] == "TCSESU033FN0"
    assert row["Part Number"] == "TCSESU033FN0"
    assert row["Product Name"] == "Schneider Electric ConneXium Unmanaged Switch 3TX"
    assert row["Announcement Date"] == "2023-01-13"
    assert row["Last Sale"] == "2023-12-31"
    assert row["End of Sale"] == "2023-12-31"
    assert row["End of Support"] == "2023-12-31"
    assert row["Replacement Products"] == "MCSESU053FN0"
    assert "MCSESU053FN0" not in row["_aliases"]
    assert row["_source_url"].endswith("/download/document/RAL22AM0003-IDPAC/")


def test_schneider_apc_pdf_parser_skips_nmc_policy_without_exact_product_row():
    text = """
    Network Management Card End-of-Life Support Policy
    Network Management Card 2 (NMC2) entered maintenance mode for cybersecurity updates only.
    Stand-alone NMC3 options include AP9640, AP9641, AP9643.
    """

    assert parse_schneider_apc_connexium_pdf_rows_from_text(text, "nmc2.pdf") == []


def test_spectralink_kirk_ip_base_pdf_imports_eol_eos_skus():
    text = """
    Technical Bulletin CS-22-02
    Compatibility ends for KIRK IP Base

    Systems Affected
    IP-DECT Server 400
    IP-DECT Server 6500
    KIRK IP Base Station

    Description
    From software R1 2022 - PCS22Aa - the KIRK IP Base is no longer compatible with the
    IP-DECT server software on the IP-DECT Server 400 and IP-DECT Server 6500.
    The old KIRK IP-Base Stations (SKU# 02337300, 02337301) went EOL (End of Life) on
    October 1, 2013, and EOS (End of Service) on October 31, 2016, and the old base will no
    longer be supported beginning with this release.
    """

    rows = parse_spectralink_pdf_rows_from_text(
        text,
        "cs_22_02_kirk_ip_base_eol_eos_bulletin.pdf",
    )

    assert len(rows) == 2
    assert [row["Part Number"] for row in rows] == ["02337300", "02337301"]
    assert all(row["Model"] == "KIRK IP Base Station" for row in rows)
    assert rows[0]["End of Life"] == "2013-10-01"
    assert rows[0]["End of Service"] == "2016-10-31"
    assert rows[0]["Description"] == "IP-DECT base station"
    assert rows[0]["_review_policy"] == "spectralink_kirk_ip_base_eos_is_end_of_service"
    assert "02337300" in rows[0]["_aliases"]
    assert rows[0]["_suppress_description_aliases"] is True

    assert parse_spectralink_pdf_rows_from_text(
        text,
        "pcs26aa_release_notes_kirk_ip_base_eol_eos.pdf",
    ) == []


def test_matrox_video_product_pages_import_status_only_eol(tmp_path):
    pages = {
        "matrox_maevex_5100_series.html": (
            "Maevex 5100 Series Encoder & Decoder",
            (
                "Matrox Video has publicly announced end-of-life (EOL) "
                "notification in March of 2026 for the Maevex 5100 Series. "
                "Customers looking for the nearest product alternative should "
                "consider the Maevex 6100 Series."
            ),
        ),
        "matrox_maevex_6020_remote_recorder.html": (
            "Maevex 6020 Remote Recorder",
            (
                "Matrox Video has publicly announced end-of-life (EOL) "
                "notification in July of 2025 for the Maevex 6020 Remote "
                "Recorder. Last time buy orders of this product will be "
                "accepted until September 30, 2025, or until supplies last. "
                "Customers looking for the nearest product alternative should "
                "consider the Maevex 7100 Series or Maevex 6100 Series."
            ),
        ),
        "matrox_monarch_hd.html": (
            "Monarch HD Encoder Appliance",
            (
                "Matrox Video has publicly announced end-of-life (EOL) "
                "notification in June of 2024 for the Monarch HD and this "
                "product is sold out. Customers looking for the nearest "
                "product alternative should consider the Maevex 7100 Series "
                "or the Monarch LCS."
            ),
        ),
        "matrox_monarch_hdx.html": (
            "Monarch HDX Encoder Appliance",
            (
                "Matrox Video has publicly announced end-of-life (EOL) "
                "notification in April of 2025 for the Monarch HDX and this "
                "product is sold out. Customers looking for the nearest "
                "product alternative should consider the Maevex 7100 Series "
                "or the Monarch LCS."
            ),
        ),
    }

    rows = []
    for filename, (heading, notice) in pages.items():
        path = tmp_path / filename
        path.write_text(
            f"""
            <html>
              <head><link rel="canonical" href="https://video.matrox.com/{filename}"></head>
              <body><h1>{heading}</h1><p>{notice}</p></body>
            </html>
            """,
            encoding="utf-8",
        )
        rows.extend(extract_matrox_video_eol_rows(path))

    assert [row["Model"] for row in rows] == [
        "Maevex 5100 Series",
        "Maevex 6020 Remote Recorder",
        "Monarch HD",
        "Monarch HDX",
    ]
    assert rows[1]["End of Sale"] == "2025-09-30"
    assert "End of Life" not in rows[0]
    assert all(row["_status_only_review"] is True for row in rows)
    assert all(row["_suppress_description_aliases"] is True for row in rows)
    assert rows[0]["_remove_aliases"] == ["Matrox Video Matrox Maevex 5100 Series"]
    assert rows[2]["Replacement"] == "Maevex 7100 Series; Monarch LCS"


def test_wago_discontinued_product_page_imports_status_only_item(tmp_path):
    path = tmp_path / "product_750_512_2_channel_relay_output.html"
    path.write_text(
        """
        <html>
          <head>
            <link rel="canonical" href="https://www.wago.com/global/i-o-systems/2-channel-relay-output/p/750-512">
          </head>
          <body>
            <h1>2-channel relay output; AC 250 V; 2.0 A; 2 make contact</h1>
            <div>Item no. 750-512</div>
            <wg-alert message="This item has been discontinued and is no longer available as of 01/07/2026."></wg-alert>
            <script>{"events.date.pattern":"dd/MM/yyyy"}</script>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_wago_discontinued_product_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "750-512"
    assert rows[0]["Product Name"] == "WAGO 750-512"
    assert rows[0]["End of Sale"] == "2026-07-01"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_suppress_description_aliases"] is True
    assert rows[0]["_review_policy"] == "wago_discontinued_product_page_status_only"


def test_ctsystem_fos_ies_html_imports_phaseout_models(tmp_path):
    path = tmp_path / "eol_202008001_fos_5126_ies_3106.html"
    path.write_text(
        """
        <html>
          <head><link rel="canonical" href="https://www.ctsystem.com/eol-202008001"></head>
          <body>
            <p>Product End-of-Life Notice: FOS-5126 and IES-3106</p>
            <table>
              <tr><td>Product Family</td><td>FOS-5126</td><td>IES-3106</td></tr>
              <tr>
                <td>Phase-out Model</td>
                <td>FOS-5126-1A FOS-5126-1D</td>
                <td>IES-3106TP IES-3106SFP-PLUS-BT</td>
              </tr>
              <tr>
                <td>Alternative Solution</td>
                <td>FOS-5128-1A FOS-5128-1D</td>
                <td>IES-3110SFP IES-3110SFP-BT</td>
              </tr>
              <tr>
                <td>Phase-out Schedule</td>
                <td>EOL Notification: 14-Aug-2020 Last Time Order Date: 13-Nov-2020 Last Customer Ship Date: 11-Dec-2020 End of Service Date*: 11-Dec-2022</td>
                <td>EOL Notification: 14-Aug-2020 Last Time Order Date: 13-Nov-2020 Last Customer Ship Date: 11-Dec-2020 End of Service Date*: 11-Dec-2025</td>
              </tr>
            </table>
            <p>* End-of-Service date is the date after which any type of technical support, such as manufactured, improved, repaired, or maintained will no longer be available.</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_ctsystem_fos_ies_eol_rows(path)

    assert [row["Model"] for row in rows] == [
        "FOS-5126-1A",
        "FOS-5126-1D",
        "IES-3106TP",
        "IES-3106SFP-PLUS-BT",
    ]
    assert rows[0]["Announcement Date"] == "2020-08-14"
    assert rows[0]["End of Sale"] == "2020-11-13"
    assert rows[0]["End of Service"] == "2022-12-11"
    assert rows[2]["End of Service"] == "2025-12-11"
    assert rows[0]["Replacement"] == "FOS-5128-1A; FOS-5128-1D"
    assert rows[0]["_review_policy"] == "ctsystem_end_of_service_no_technical_support"
    assert rows[0]["_remove_aliases"] == ["Ctsystem CTS FOS-5126-1A"]


def test_ctsystem_eol_products_pdf_imports_clean_service_groups():
    text = """
                                                                     End of Life Products
        EOL#             Phase-out Series                  Phase-out Models                        Alternatives           Announce Date Last-order Day End of Service

                                               PLR-2012-TX
   EOL-202404001             PLR-2012          PLR-2012-RX                               N/A                                4/19/2024         5/31/2024       6/30/2026
                                               PLR-2012-KIT
    """

    rows = parse_ctsystem_eol_products_pdf_rows_from_text(
        text,
        "end_of_life_products_v1_9_02112026.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "PLR-2012-TX",
        "PLR-2012-RX",
        "PLR-2012-KIT",
    ]
    assert rows[0]["Announcement Date"] == "2024-04-19"
    assert rows[0]["End of Sale"] == "2024-05-31"
    assert rows[0]["End of Service"] == "2026-06-30"
    assert rows[0]["_review_policy"] == "ctsystem_end_of_service_no_technical_support"


def test_ctsystem_eol_products_pdf_preserves_models_and_ignores_alternatives():
    text = """
                                                                     End of Life Products
        EOL#             Phase-out Series                  Phase-out Models                        Alternatives           Announce Date Last-order Day End of Service

                                            HES-3012BTFC
                                            HES-3012BTFC(SM-10/20/30/50/80)
                                            HES-3012W2A(SM-10/20/40)              HMC-3012W2A(SM-10)
                             HET-3012       HES-3012W2B(SM-10/20/40)              FTC-3012BW2A(SM-10)-DR-DS                            3/31/2022       6/30/2024
                                            HES-3012W2A(SM-10/20)-DR              FTC-3012BW2A(SM-10)-DR
                                            HES-3012W2B(SM-10/20)-DR
                                            HES-3012SFP-DR
    """

    rows = parse_ctsystem_eol_products_pdf_rows_from_text(
        text,
        "end_of_life_products_v1_9_02112026.pdf",
    )

    models = [row["Model"] for row in rows]
    assert models == [
        "HES-3012BTFC",
        "HES-3012BTFC(SM-10/20/30/50/80)",
        "HES-3012W2A(SM-10/20/40)",
        "HES-3012W2B(SM-10/20/40)",
        "HES-3012W2A(SM-10/20)-DR",
        "HES-3012W2B(SM-10/20)-DR",
        "HES-3012SFP-DR",
    ]
    assert "SM-10" not in models
    assert "FTC-3012BW2A(SM-10)-DR-DS" not in models
    assert all(row["End of Sale"] == "2022-03-31" for row in rows)
    assert all(row["End of Service"] == "2024-06-30" for row in rows)


def test_ctsystem_eol_products_pdf_skips_dash_and_sw_support_groups():
    text = """
                                                                     End of Life Products
        EOL#             Phase-out Series                  Phase-out Models                        Alternatives           Announce Date Last-order Day End of Service

   EOL-201803001                                                                     HES-3106 Series                     2018/3/29          2018/4/6            -
                                             HET-3005FC

                                             VRGIII-31412SFP-CW-N-DR
                           VRGIII-31412      VRGIII-31412SFP-CW-N-DR-RF
                                                                                                                                                        2019/12/17
                                                                                                                                                           (S/W)
                                                                                                                                                        2022/12/17
                                                                                                                                                          (support)
    """

    rows = parse_ctsystem_eol_products_pdf_rows_from_text(
        text,
        "end_of_life_products_v1_9_02112026.pdf",
    )

    assert rows == []


def test_beijer_korenix_pdf_imports_bracketed_eol_rows():
    text = """
    2023-03-28
    Life Cycle Notification
    End of Life for "Product - JetCon 2201/2401"
    The following products have not been available for sales due to sudden key components EoL.
    End of life     Replaced by               Replacement
    Part number                              Model name
    date            part number               model name
    [JetCon 2201i-w V1.0]
    Industrial RS-232 to RS-
    F00V2201300000                                                        2023/03/28
    422/485 Isolated Rail-                                 N/A                      N/A
    [JetCon 2201i-wTB V1.0]
    Industrial RS-232 to RS-
    F00V2201300001                                                        2023/03/28
    """

    rows = parse_beijer_korenix_pdf_rows_from_text(
        text,
        "EOL_Korenix_life_cycle_notification-JetCon_2201_2401.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "JetCon 2201i-w V1.0",
        "JetCon 2201i-wTB V1.0",
    ]
    assert rows[0]["Part Number"] == "F00V2201300000"
    assert rows[0]["End of Sale"] == "2023-03-28"
    assert "End of Life" not in rows[0]
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "beijer_korenix_eol_date_not_support_end"


def test_beijer_korenix_pdf_ignores_replacement_bracket_and_part_number():
    text = """
    2021-12-29
    Life Cycle Notification
    End of Life for "Product - JetNet 5310G"
    Part number                      Model name                                model name
    date
                                                       [JetNet 5310G V1.2]                                        [JetNet 5210GP-2C]
                                                       Industrial 8 PoE + 2                                       Industrial 8G RJ45 + 2G
                                                                                                 F00N5210GP0001
                                                       Gigabit RJ / SFP DIN                                       Combo Managed PoE
                      F00N5310000002                                               2021-12-30
                                                       Rail Managed High                                          Ethernet Switch with
    """

    rows = parse_beijer_korenix_pdf_rows_from_text(
        text,
        "EOL_Korenix_life_cycle_notification-JetNet_5310G-20211229.pdf",
    )

    assert len(rows) == 1
    assert rows[0]["Model"] == "JetNet 5310G V1.2"
    assert rows[0]["Part Number"] == "F00N5310000002"
    assert rows[0]["End of Sale"] == "2021-12-30"
    assert "5210GP" not in rows[0]["Model"]


def test_beijer_korenix_pdf_imports_split_model_table_rows():
    text = """
    2023-1-16
    Life Cycle Notification
    End of Life for Product - JetNet 5728G
    For the products listed below, we are now issuing EOL.
                    Part number      Model name             End of life    Replacement      Replacement
                                                            date           Part Number      model name
                                     JetNet 5728G-16P-AC-
                    F00N5728002004                          2023/1/16
                                     EU V2.0
                                     JetNet 5728G-24P-AC-                                  JetNet 5728G-24P-AC-
                    F00N5728002006                          2023/1/16     F00N5728002007
                                     EU V2.0                                               2DC-EU V2.1
    """

    rows = parse_beijer_korenix_pdf_rows_from_text(
        text,
        "EOL_Korenix_life_cycle_notification-JetNet_5728G_V2.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "JetNet 5728G-16P-AC-EU V2.0",
        "JetNet 5728G-24P-AC-EU V2.0",
    ]
    assert rows[0]["Part Number"] == "F00N5728002004"
    assert rows[1]["Part Number"] == "F00N5728002006"


def test_beijer_korenix_pdf_imports_eol_filename_case_and_skips_ltb():
    text = """
    2022-12-29
    Life Cycle Notification
    End of Life for "Product - JetLink 2308"
    Part number                Model name             End of Life          Replaced by   Replacement
    part number   model name
    F00L2308000000             JetLink 2308           2022-12-28           n/a           n/a
    F00L2308000001             JetLink 2308M          2022-12-28           n/a           n/a
    """

    rows = parse_beijer_korenix_pdf_rows_from_text(
        text,
        "EoL_Korenix_life_cycle_notification-JetLink_2308_-20221229-2022031.pdf",
    )

    assert [row["Model"] for row in rows] == ["JetLink 2308", "JetLink 2308M"]
    assert parse_beijer_korenix_pdf_rows_from_text(
        text,
        "LTB_Korenix_life_cycle_notification-JetNet_2005-20221212-2022024.pdf",
    ) == []


def test_ctc_union_pdf_imports_multiple_eol_models_as_review_only():
    text = """
    Product EOL Notification
    Issue Date: 2013/06/01
    Dear Valued Customer:
    upcoming end of life (EOL) on the following items.
    EOL Model Name : ETU-DXC/A16-DC, ETU-DXC/A-16-AC, ETU-DXC/A8-DC, ETU-DXC/A8-AC
    Substitute Item : iSAP2000 - 8E1R/16E1R
    Effective Date : June 2013
    Last Buy Date : Dec 2013
    """

    rows = parse_ctc_union_pdf_rows_from_text(
        text,
        "ctc_union_eol-etu-dxc-a16-a8.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "ETU-DXC/A16-DC",
        "ETU-DXC/A-16-AC",
        "ETU-DXC/A8-DC",
        "ETU-DXC/A8-AC",
    ]
    assert rows[0]["Announcement Date"] == "2013-06-01"
    assert rows[0]["End of Sale"] == "2013-12-31"
    assert "End of Life" not in rows[0]
    assert rows[0]["Replacement"] == "iSAP2000 - 8E1R/16E1R"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "ctc_union_eol_discontinuation_not_support_end"


def test_ctc_union_pdf_parses_ordinal_effective_date_without_last_buy():
    text = """
    Product End-Of-Life Notice
    Issue Date: 2024/03/21
    EOL Model Name : GSW-2020PA
    Substitute Item : Not available
    Effective Date : Mar. 31th 2024
    Last Buy Date : N/A
    """

    rows = parse_ctc_union_pdf_rows_from_text(
        text,
        "ctc_union_eol-notice_gsw-2020pa_20240321.pdf",
    )

    assert len(rows) == 1
    assert rows[0]["Model"] == "GSW-2020PA"
    assert rows[0]["End of Sale"] == "2024-03-31"
    assert "Replacement" not in rows[0]


def test_ctc_union_pdf_joins_wrapped_model_suffix():
    text = """
    Product End-Of-Life Notice
    Issue Date:2022/03/02
    EOL Model Name : FRM220-10GC
                           10GC-TS
    Substitute Item : FRM220-10G G-3R with 10G Copper SFP
    Effective Date  : Mar. 2022
    """

    rows = parse_ctc_union_pdf_rows_from_text(
        text,
        "ctc_union_eol-notice_frm220-10gc-ts.pdf",
    )

    assert len(rows) == 1
    assert rows[0]["Model"] == "FRM220-10GC-TS"
    assert rows[0]["End of Sale"] == "2022-03-31"


def test_ctc_union_pdf_imports_eol_models_without_colon():
    text = """
    Product End-Of-Life Notice
    Issue Date:2020/06/22
    EOL Models FRM220A-1000EAS/X FRM220-1000EAS/X-1 FRM220-100AS-1
    Substitute Models FRM220A-2000EAS/2 FRM220A-2000EAS/1 --
    Effective Date : Jun 22, 2020
    Last Buy Date : Sep 30, 2020
    """

    rows = parse_ctc_union_pdf_rows_from_text(
        text,
        "ctc_union_eol-notice_frm220-1000eas_x-series.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "FRM220A-1000EAS/X",
        "FRM220-1000EAS/X-1",
        "FRM220-100AS-1",
    ]
    assert rows[0]["End of Sale"] == "2020-09-30"
    assert parse_ctc_union_pdf_rows_from_text(
        text,
        "ctc_union_eol-notice_frm220-1000eas_x-1series.pdf",
    ) == []


def test_ctc_union_pdf_preserves_parentheses_and_no_digit_models():
    text = """
    Product EOL Notification
    Issue Date:2019/02/01
    EOL Model Name : ERM-MUX/Plus, FMC-100M(S), HCT-BERT-C
    Substitute Item : N/A
    Effective Date : Feb. 2019
    Last Buy Date : Aug. 2019
    """

    rows = parse_ctc_union_pdf_rows_from_text(
        text,
        "ctc_union_eol-erm-mus-plus.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "ERM-MUX/Plus",
        "FMC-100M(S)",
        "HCT-BERT-C",
    ]


def test_ctc_union_pdf_keeps_parenthetical_variant_list_as_one_model():
    text = """
    Product End-Of-Life Notice
    Issue Date:2022/08/24
    EOL Model Name : FRM220-E1/Data (V35,X21,RS530,RS449,RS232)
    Substitute Item : None
    Effective Date : Aug 2022
    """

    rows = parse_ctc_union_pdf_rows_from_text(
        text,
        "ctc_union_eol-notice_frm220-e1-data_20220824.pdf",
    )

    assert [row["Model"] for row in rows] == [
        "FRM220-E1/Data (V35,X21,RS530,RS449,RS232)"
    ]


def test_netcontrol_pdf_uses_title_model_when_milestone_heading_is_wrong():
    text = """
    End-of-Life Announcement 1 (1)
    N00297-LT-EN-1
    March 10, 2026
    Netcon 1+ End-of-Life Announcement
    This is the formal announcement that Netcontrol is initiating the End-of-Life process for the Netcon 1+.
    Key milestones in the End-of-Life process are given below.
    End of Life Milestones - Netcon 1
    Milestone Date Explanation
    End of Life (EOL) 10 March 2026 Notification of the product entering the end-of-life period.
    Last Time Buy (LTB) Date N/A There will not be any Last Time Buy for this product.
    End of spare parts; support 10 March 2036 Netcontrol will provide spare parts, support and service as long as possible.
    """

    rows = parse_netcontrol_pdf_rows_from_text(
        text,
        "netcontrol_n00297_lt_en_1_netcon_1_end_of_life_announcement_2.pdf",
    )

    assert len(rows) == 1
    assert rows[0]["Model"] == "Netcon 1+"
    assert rows[0]["Announcement Date"] == "2026-03-10"
    assert rows[0]["End of Support"] == "2036-03-10"
    assert "End of Sale" not in rows[0]


def test_netcontrol_pdf_imports_combined_models_and_ltb_date():
    text = """
    RTU28 and RTU28-IP End-of-Life Announcement
    This is the formal announcement that Netcontrol is initiating the End-of-Life process for the RTU28 and RTU28-IP RTU:s.
    End of Life Milestones - RTU28
    End of Life (EOL) 10 March 2026 Notification of the product entering the end-of-life period.
    Last Time Buy (LTB) Date 10 June 2026 or until stock sold out.
    End of support and service. 10 June 2031 Netcontrol will do reasonable effort to provide support and service.
    """

    rows = parse_netcontrol_pdf_rows_from_text(
        text,
        "netcontrol_n00299_lt_en_1_rtu28_and_rtu28_ip_end_of_life_announcement_2.pdf",
    )

    assert [row["Model"] for row in rows] == ["RTU28", "RTU28-IP"]
    assert rows[0]["End of Sale"] == "2026-06-10"
    assert rows[0]["End of Support"] == "2031-06-10"
    assert rows[0]["_review_policy"] == "netcontrol_end_of_support_and_service_milestone"


def test_netcontrol_pdf_parses_comma_after_month_in_date():
    text = """
    PDR121 350-360 MHz End-of-Life Announcement
    Key milestones in the End-of-Life process are given below.
    End of Life Milestones - PDR121 350-360 MHz
    End of Life (EOL) 13 April, 2026 Notification of the product entering the end-of-life period.
    Last Time Buy (LTB) Date 15 June 2026 Netcontrol will do reasonable efforts to provide units.
    End of support for product. 13 April 2028 Netcontrol will do reasonable effort to provide support.
    """

    rows = parse_netcontrol_pdf_rows_from_text(
        text,
        "netcontrol_n00309_lt_en_1_pdr121_350_360_mhz_end_of_life_announcement.pdf",
    )

    assert len(rows) == 1
    assert rows[0]["Model"] == "PDR121 350-360 MHz"
    assert rows[0]["Announcement Date"] == "2026-04-13"
    assert rows[0]["End of Sale"] == "2026-06-15"
    assert rows[0]["End of Support"] == "2028-04-13"


def test_netcontrol_pdf_prefers_specific_title_over_page_header():
    text = """
    FastNet End-of-Life Announcement 1 (1)
    10 March, 2026
    FastNet RTU End-of-Life Announcement
    This is the formal announcement that Netcontrol is initiating the End-of-Life process for the FastNet RTU.
    End of Life Milestones - FastNet
    End of Life (EOL) 10 March 2026 Notification of the product entering the end-of-life period.
    End of support and service. 10 March 2031 Netcontrol will do reasonable effort to provide support.
    """

    rows = parse_netcontrol_pdf_rows_from_text(
        text,
        "netcontrol_n00300_lt_en_1_fastnet_end_of_life_announcement_1.pdf",
    )

    assert [row["Model"] for row in rows] == ["FastNet RTU"]


def test_garland_pdf_imports_supported_eol_eos_rows():
    text = """
    EOL / EOS Announcement
    Garland Technology officially announces the End-of-Life (EOL) / End-of-Sale (EOS) date(s) for the
    below Part Numbers in the EdgeSafeTM: Bypass Modular Network TAP product line.
    Garland Part Numbers affected:
    End of Life Part Numbers
    M40G1AC
    INT10G8SRBP16SFP+
    Key Dates:
    Milestone Timing
    End-of-Life January 1, 2023
    End-of-Sales Date June 30, 2023
    End of Support July 1, 2024
    """

    rows = parse_garland_pdf_rows_from_text(
        text,
        "EOL_EOS_Letter_EdgeSafe_2023.pdf",
    )

    assert [row["Model"] for row in rows] == ["M40G1AC", "INT10G8SRBP16SFP+"]
    assert rows[0]["End of Sale"] == "2023-06-30"
    assert rows[0]["End of Support"] == "2024-07-01"
    assert rows[0]["End of Life"] == "2023-01-01"
    assert "_force_lifecycle_review" not in rows[0]


def test_garland_pdf_imports_advanced_features_split_date_groups():
    text = """
    EOL / EOS Announcement
    Garland Technology officially announces the End-of-Life (EOL) / End-of-Sale (EOS) date(s) for the
    below Part Numbers in the PacketMaxTM: Advanced Features product line.
    Garland Part Numbers affected:
    End of Life Part Numbers
    AF1G40AC AF40G24AC
    AF10G72AC
    Key Dates:
    AF1G40AC
    Milestone Timing
    End-of-Life March 31, 2025
    End-of-Sales Date March 31, 2025
    End of Support March 31, 2026
    AF1G40DC, AF10G72AC, AF10G72DC, AF40G24AC, AF40G24DC, AF100G4ACE, and AF100G4DCE
    Milestone Timing
    End-of-Life January 1, 2023
    End-of-Sales Date January 1, 2023
    End of Support January 2, 2024
    """

    rows = parse_garland_pdf_rows_from_text(
        text,
        "EOL_EOS_Letter_AdvancedFeatures_2023.pdf",
    )

    by_model = {row["Model"]: row for row in rows}
    assert by_model["AF1G40AC"]["End of Support"] == "2026-03-31"
    assert by_model["AF10G72AC"]["End of Support"] == "2024-01-02"


def test_garland_pdf_forces_review_without_support_date():
    text = """
    EOL / EOS Announcement
    Garland Technology officially announces the End-of-Life (EOL) / End-of-Sale (EOS) date for the
    Filtering Aggregating Load Balancer (FAB) product line.
    Garland Part Numbers affected:
    End of Life Part Numbers
    FAB10G8AC
    FAB10G16AC
    Key Dates:
    Milestone Timing
    End-of-Life / End-of-Sales Date 7/1/2018
    """

    rows = parse_garland_pdf_rows_from_text(text, "GT-EOL_EOS_Letter_FABv2.pdf")

    assert [row["Model"] for row in rows] == ["FAB10G8AC", "FAB10G16AC"]
    assert rows[0]["End of Sale"] == "2018-07-01"
    assert "End of Life" not in rows[0]
    assert rows[0]["_force_lifecycle_review"] is True


def test_adtran_bluesocket_bsap_pdf_imports_support_dates():
    text = """
    Q3 2015
    End of Sale Notice (EOSN)
    (or End of Life Announcement)
    for Bluesocket 1800 Series Access Points
    ADTRAN Inc. announces the End of Sale and End of Life dates for the ADTRAN Bluesocket 1800
    Series Access Points.
    Table 1. Part Numbers Affected by this Announcement
    End of Sale Product              Product                     Reason for Withdrawal
    Part Number                      Description
    1700910F1
                                    BSAP 1800 2x3:2               Vendor end of Life (EOL) components no
                                    w/Internal Antennas           longer available to assemble product
                                    BSAP 1840 802.11N 2x3:2       Vendor end of Life (EOL) components no
    1700911F1                       w/External Antenna
                                                                 longer available to assemble product
                                    Connectors
                                    BSAP 1840 802.11ABG           Vendor end of Life (EOL) components no
    1700912F1                       w/External Antenna
                                                                 longer available to assemble product
                                    Connectors
    Table 2. End of Life Milestones and Dates
    End of Life Announcement Date
    March 30, 2015
    End of Sale Date (ESD)
    June 30, 2015
    Last Date of Support (AKA End of Life Date (EOL))
    June 30, 2016
    PRODUCT MIGRATION OPTIONS
    The recommended replacements for the affected ADTRAN Bluesocket 1800 Series Access Points are
    ADTRAN Bluesocket 1900 and 2000 Series Access Points.
    """

    rows = parse_adtran_bluesocket_pdf_rows_from_text(
        text,
        "document_eol_bsap1800_052915_069Tq00000PAxn1IAD.pdf",
    )

    assert [row["Part Number"] for row in rows] == [
        "1700910F1",
        "1700911F1",
        "1700912F1",
    ]
    assert [row["Model"] for row in rows] == [
        "BSAP 1800",
        "BSAP 1840 802.11N",
        "BSAP 1840 802.11ABG",
    ]
    assert rows[0]["End of Sale"] == "2015-06-30"
    assert rows[0]["End of Support"] == "2016-06-30"
    assert rows[0]["Announcement Date"] == "2015-03-30"
    assert rows[0]["Description"] == "Wireless access point"
    assert rows[0]["Replacement Products"] == "ADTRAN Bluesocket 1900 and 2000 Series Access Points"
    assert rows[0]["_source_url"].endswith("EOL%20-%20BSAP1800_052915.pdf")


def test_adtran_bluesocket_controller_pdf_imports_support_dates():
    text = """
    Q4 2014
    End of Sale Notice (EOSN)
    (or End of Life Announcement)
    for Bluesocket BlueSecure Controllers (BSC)
    ADTRAN Inc. announces the End of Sale and End of Life dates for the ADTRAN Bluesocket
    BlueSecure Controllers (BSC).
    Table 1. Part Numbers Affected by this Announcement
    End of Sale Product          Product                  Reason for Withdrawal
    Part Number                  Description
    1700902F1                    BSC-600, 64 Users, 8 APs   Market demand has shifted to next
                                                           generation cloud-based and virtualized
                                                           solutions
                                  BSC-1200, 200 Users, 25
    1700903F1
                                  Aps                        generation cloud-based and virtualized
                                                           solutions
                                  BSC-2200, 400 Users, 50
    1700904G1
                                  APs Copper Ethernet        generation cloud-based and virtualized
                                                           solutions
    Table 2. End of Life Milestones and Dates
    End of Life Announcement Date
    September 3, 2014
    End of Sale Date (ESD)
    December 31, 2014
    Last Date of Support (AKA End of Life Date (EOL))
    December 31, 2015
    PRODUCT MIGRATION OPTIONS
    The recommended replacements for the affected ADTRAN Bluesocket BlueSecure Controllers are
    ADTRAN Bluesocket vWLAN and ProCloud Wi-Fi.
    """

    rows = parse_adtran_bluesocket_pdf_rows_from_text(
        text,
        "document_eol_bluesocket_bluesecure_controllers_090314_069Tq00000PAf6qIAD.pdf",
    )

    assert [row["Part Number"] for row in rows] == [
        "1700902F1",
        "1700903F1",
        "1700904G1",
    ]
    assert [row["Model"] for row in rows] == ["BSC-600", "BSC-1200", "BSC-2200"]
    assert rows[0]["End of Sale"] == "2014-12-31"
    assert rows[0]["End of Support"] == "2015-12-31"
    assert rows[0]["Announcement Date"] == "2014-09-03"
    assert rows[0]["Description"] == "Wireless LAN controller"
    assert rows[0]["Replacement Products"] == "ADTRAN Bluesocket vWLAN and ProCloud Wi-Fi"


def test_adtran_discontinued_product_page_imports_status_only_review(tmp_path):
    html = """
    <html>
      <head>
        <meta name="PART_NUMBER" content="17101548F1"/>
        <meta name="PRODUCT_NAME" content="NetVanta 1550-48"/>
        <title>NetVanta 1550-48</title>
      </head>
      <body>
        <h1>NetVanta 1550-48</h1>
        <p>This product has been discontinued. Check out the NetVanta 1560-48 Switches
        <a href="/web/page/portal/Adtran/product/17108148PF2/6">17108148PF2</a>
        for your needs.</p>
      </body>
    </html>
    """
    path = tmp_path / "nhedb__raw__adtran-product-page-discontinued-example.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_rows(path, "adtran")

    assert len(rows) == 1
    assert rows[0]["Model"] == "NetVanta 1550-48"
    assert rows[0]["Part Number"] == "17101548F1"
    assert rows[0]["Replacement Products"] == "NetVanta 1560-48 Switches / 17108148PF2"
    assert rows[0]["_status_only_review"] is True


def test_adtran_aos_support_dates_import_exact_software_support_rows(tmp_path):
    html = """
    <html>
      <head><title>AOS End of Software Support Dates</title></head>
      <body>
        <p>Currently Supported AOS Versions</p>
        <table>
          <tr><td>AOS Version</td><td>End of Software Support Date</td></tr>
          <tr><td>R14.4 (Extended Maintenance Branch)</td><td>May 23, 2026</td></tr>
          <tr><td>R14.3 (Extended Maintenance Branch)</td><td>September 28, 2025</td></tr>
        </table>
        <p>Unsupported AOS Versions</p>
        <table>
          <tr><td>AOS Version</td><td>End of Software Support Date</td></tr>
          <tr><td>R14.2 (Extended Maintenance Branch)</td><td>February 23, 2025</td></tr>
          <tr><td>R13.6</td><td>August , 2020</td></tr>
        </table>
        <p>Software Support Expiration Exceptions</p>
        <table>
          <tr><td>Product</td><td>Supported AOS Versions</td></tr>
          <tr><td>NetVanta 1534</td><td>R13.2.x and R13.4.0</td></tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "article_aos_end_of_software_support_dates.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_adtran_aos_support_rows(path)

    assert [row["Model"] for row in rows] == ["AOS R14.4", "AOS R14.3", "AOS R14.2"]
    assert [row["End of Software Support"] for row in rows] == [
        "2026-05-23",
        "2025-09-28",
        "2025-02-23",
    ]
    assert rows[0]["Version"] == "R14.4"
    assert rows[0]["Description"] == "ADTRAN Operating System software release"
    assert rows[0]["_source_url"].endswith("AOS-End-of-Software-Support-Dates/ta-p/30392")
    assert extract_rows(path, "adtran") == rows


def test_lenovo_networking_withdrawn_product_guide_status_only(tmp_path):
    html = """
    <html>
      <head>
        <title>Lenovo RackSwitch G8264CS Product Guide (withdrawn product) &gt; Lenovo Press</title>
        <meta property="og:url" content="https://lenovopress.lenovo.com/tips0970"/>
      </head>
      <body>
        <h1>Lenovo RackSwitch G8264CS</h1>
        <h2>Abstract</h2>
        <p>This Product Guide describes withdrawn models of the RackSwitch G8264CS
        that are no longer available for ordering.</p>
        <div class="callout">
          <p><strong>Withdrawn from marketing:</strong> This networking switch is now withdrawn from marketing.</p>
        </div>
        <h2>Part number information</h2>
        <table>
          <tr><th>Description</th><th>Part number</th><th>Feature code</th></tr>
          <tr><td>RackSwitch G8264CS</td><td>7309DRX</td><td>A3FL</td></tr>
          <tr><td>Console Cable Kit Spare</td><td>90Y9462</td><td>A2MG</td></tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "rackswitch_g8264cs.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_lenovo_networking_withdrawn_product_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "Lenovo RackSwitch G8264CS"
    assert rows[0]["Description"] == "Network Switch"
    assert rows[0]["Product Status"] == (
        "Withdrawn from marketing: This networking switch is now withdrawn from marketing."
    )
    assert rows[0]["Lifecycle Status Source"].endswith("/solutions/endofservice")
    assert rows[0]["_source_url"] == "https://lenovopress.lenovo.com/tips0970"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "lenovo_withdrawn_from_marketing_not_support_eol"
    assert "7309DRX" not in rows[0].get("_aliases", [])
    assert extract_rows(path, "lenovo_networking") == rows


def test_cyberdata_eol_products_json_imports_status_only_supported_rows(tmp_path):
    data = {
        "products": [
            {
                "title": "011579 SIP Paging 25V/70V Amplifier (Replacement Product is 011598)",
                "handle": "011579",
                "product_type": "VoIP",
                "tags": ["End-of-Life", "related-product-011598"],
                "body_html": "<p>Replacement Product is 011598</p>",
                "variants": [{"sku": "011579", "available": False}],
            },
            {
                "title": "011511 Current Speaker",
                "handle": "011511",
                "product_type": "VoIP",
                "tags": [],
                "variants": [{"sku": "011511", "available": True}],
            },
        ]
    }
    path = tmp_path / "end_of_life_products.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    rows = extract_cyberdata_eol_product_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "011579"
    assert rows[0]["Part Number"] == "011579"
    assert rows[0]["Product Name"] == "011579 SIP Paging 25V/70V Amplifier (Replacement Product is 011598)"
    assert rows[0]["Description"] == "Paging Amplifier"
    assert rows[0]["Product Status"] == (
        "End-of-Life product; no longer being sold but still supported; sold out"
    )
    assert rows[0]["Replacement Products"] == "011598"
    assert rows[0]["Lifecycle Status Source"].endswith("/collections/end-of-life-products")
    assert rows[0]["_source_url"] == "https://www.cyberdata.net/products/011579"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "cyberdata_eol_no_longer_sold_still_supported"
    assert extract_rows(path, "cyberdata") == rows


def test_akuvox_security_update_page_imports_update_and_no_maintenance_rows(tmp_path):
    html = """
    <html>
      <body>
        <h2>Security Updates</h2>
        <table>
          <tr><th>Product</th><th>Update until</th></tr>
          <tr><td>C313</td><td>2027/12/31</td></tr>
        </table>
        <h2>EOL Product List</h2>
        <p class="title1">EOL Product List (Under Maintenance)</p>
        <p>Indoor Monitor</p>
        <table>
          <tr><th>Product</th><th>Updates Until</th></tr>
          <tr><td>IT83</td><td>2026/6</td></tr>
        </table>
        <p class="title1">EOL Product List (No Maintenance)</p>
        <p>Door Phone</p>
        <table>
          <tr><td>R20A v1.0</td><td>E10R</td></tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "security_update_eol_product_list.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_akuvox_security_update_rows(path)

    assert [row["Model"] for row in rows] == ["C313", "IT83", "R20A v1.0", "E10R"]
    assert rows[0]["End of Security Updates"] == "2027-12-31"
    assert rows[0]["Description"] == "Indoor Monitor"
    assert rows[0]["_review_policy"] == "akuvox_security_update_until"
    assert rows[1]["End of Security Updates"] == "2026-06-30"
    assert rows[1]["Product Status"] == "EOL Product List (Under Maintenance); updates until 2026-06-30"
    assert rows[2]["Description"] == "IP Door Phone"
    assert rows[2]["_allow_status_only"] is True
    assert rows[2]["_security_updates_ended_without_exact_date"] is True
    assert rows[2]["_review_policy"] == "akuvox_eol_no_maintenance_security_updates_ended"
    assert extract_rows(path, "akuvox") == rows


def test_no_exact_date_security_update_end_override_marks_unsupported(tmp_path):
    class Builder:
        ROOT = tmp_path

        @staticmethod
        def make_record(**kwargs):
            return {
                "id": "akuvox_r20a_v1",
                "vendor": kwargs["vendor_slug"],
                "vendor_slug": kwargs["vendor_slug"],
                "model": kwargs["model"],
                "device_class": "network_device",
                "dates": kwargs["dates"],
                "lifecycle": {
                    "status": "unknown",
                    "risk": "unknown",
                    "receives_security_updates": None,
                    "replacement_recommended": False,
                    "confidence": "low",
                    "reason": "",
                    "days_to_security_eol": None,
                },
                "source": {},
                "sunsetscan": {},
            }

    row = {
        "Model": "R20A v1.0",
        "Part Number": "R20A v1.0",
        "Product Status": "EOL Product List (No Maintenance)",
        "_allow_status_only": True,
        "_security_updates_ended_without_exact_date": True,
        "_review_policy": "akuvox_eol_no_maintenance_security_updates_ended",
        "_review_reason": "Vendor says security updates have ended without an exact date.",
        "_prefer_model": True,
    }

    record = row_to_record(
        builder=Builder,
        vendor_slug="akuvox",
        display_name="Akuvox",
        raw_file=tmp_path / "security_update_eol_product_list.html",
        row=row,
        source_url="https://www.akuvox.com/securitycompliance/security-update",
        source_hint="Akuvox test",
        as_of=date(2026, 6, 2),
    )

    assert record is not None
    assert record["lifecycle"]["status"] == "unsupported"
    assert record["lifecycle"]["receives_security_updates"] is False
    assert record["lifecycle"]["confidence"] == "medium"
    assert record["lifecycle"]["days_to_security_eol"] is None
    assert record["quality"]["interpretation_policy"] == (
        "akuvox_eol_no_maintenance_security_updates_ended"
    )
    assert record["quality"]["previous_lifecycle"]["status"] == "unknown"


def test_netally_legacy_page_imports_discontinued_models_with_support_date(tmp_path):
    html = """
    <html>
      <head>
        <title>LinkRunner G2 - Smart Ethernet &amp; Network Tester</title>
        <meta property="og:url" content="https://www.netally.com/products/linkrunnerg2/"/>
      </head>
      <body>
        <h1>DISCONTINUED - Support only</h1>
        <p>NOTE: The LinkRunner G2 Smart Network Testers has been discontinued and
        will be supported by AllyCare until April 29, 2027.</p>
        <table>
          <tr><th>Model Number/Name</th><th>Description</th></tr>
          <tr><td>LR-G2 - Discontinued</td><td>Includes: (1) LinkRunner G2 tester</td></tr>
          <tr><td>LR-G2-KIT - Discontinued</td><td>Includes: (1) LinkRunner G2 kit</td></tr>
          <tr><td>LR-G2-3YS - Discontinued</td><td>3 year AllyCare Support for LR-G2</td></tr>
          <tr><td>PWR-CHARGER</td><td>AC Charger Replacement</td></tr>
        </table>
      </body>
    </html>
    """
    path = tmp_path / "linkrunner_g2_legacy.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_netally_legacy_product_rows(path)

    assert [row["Model"] for row in rows] == ["LR-G2", "LR-G2-KIT"]
    assert rows[0]["End of Support"] == "2027-04-29"
    assert rows[0]["Description"] == "Network Cable Tester"
    assert rows[0]["_source_url"] == "https://www.netally.com/products/linkrunnerg2/"
    assert rows[0]["_review_policy"] == "netally_discontinued_support_only_allycare_until"
    assert extract_rows(path, "netally") == rows


def test_peplink_legacy_product_feed_imports_status_only_not_eol_rows(tmp_path):
    path = tmp_path / "legacy_product_feed.txt"
    path.write_text(
        """
Legacy Product Name: Balance 20
Legacy Product Datasheet URL: https://download.peplink.com/resources/peplink_balance_20_datasheet.pdf
Legacy Product Image URL: https://www.peplink.com/wp-content/uploads/2023/12/Balance_20.png
Replacement Product Names: B One
Replacement Product Website URLs: https://www.peplink.com/products/enterprise-branch-routers/b-one/
Replacement Product Image URLs: https://www.peplink.com/wp-content/uploads/2024/02/B_One.png

Legacy Product Name: SD Switch 8-Port Rugged
Legacy Product Datasheet URL: https://download.peplink.com/resources/peplink_switch_rugged_datasheet.pdf
Legacy Product Image URL: https://www.peplink.com/wp-content/uploads/2025/01/SD-Switch-8-Port-Rugged.png
Replacement Product Names: 24 PoE 2.5G Switch Rugged | 24 PoE 2.5G Switch
Replacement Product Website URLs: https://download.peplink.com/resources/peplink_switch_series_datasheet.pdf
Replacement Product Image URLs: https://www.peplink.com/wp-content/uploads/2025/01/24_PoE_2.5G_Switch_Rugged.png
""",
        encoding="utf-8",
    )

    rows = extract_peplink_legacy_product_rows(path)

    assert len(rows) == 2
    assert rows[0]["Model"] == "Balance 20"
    assert rows[0]["Description"] == "Router"
    assert rows[0]["Replacement Products"] == "B One"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "peplink_legacy_product_not_vendor_eol"
    assert "does not discontinue or EOL products" in rows[0]["Product Status"]
    assert rows[1]["Description"] == "Network Switch"
    assert (
        rows[1]["Replacement Products"]
        == "24 PoE 2.5G Switch Rugged; 24 PoE 2.5G Switch"
    )
    assert extract_rows(path, "peplink") == rows


def test_teradek_cube_serv_pro_eol_article_imports_sku_rows_with_review(tmp_path):
    path = tmp_path / "teradek_cube_serv_pro_eol_article.html"
    path.write_text(
        """
<html>
<head><title>End-of-Life Notification for Cube 6xx / Cube 7xx / Serv Pro | Notices | Teradek User Guide</title></head>
<body>
<table>
  <thead><tr><th>Product SKU</th><th>Product Description</th></tr></thead>
  <tbody>
    <tr><td>10-0654</td><td>Serv Pro SDI/HDMI Video Server GbE WiFi</td></tr>
    <tr><td>10-0605</td><td>Cube 605 HDMI/SDI Encoder 10/100/1000 USB</td></tr>
  </tbody>
</table>
<table>
  <thead><tr><th>Milestone</th><th>Definition</th><th>Date</th></tr></thead>
  <tbody>
    <tr><td>End-of-Life Announcement</td><td>Notification distributed to customers.</td><td>November 8, 2022</td></tr>
    <tr><td>End-of-Sale</td><td>The last day to place an order.</td><td>January 31, 2023</td></tr>
    <tr><td>End-of-Support</td><td>The last day to receive full technical support and service. After this date, affected products will transition to limited support.</td><td>December 31, 2025</td></tr>
  </tbody>
</table>
</body>
</html>
""",
        encoding="utf-8",
    )

    rows = extract_teradek_cube_serv_pro_eol_rows(path)

    assert len(rows) == 2
    assert rows[0]["Model"] == "10-0654"
    assert rows[0]["Product Name"] == "Serv Pro SDI/HDMI Video Server GbE WiFi"
    assert rows[0]["Description"] == "IP Video Server"
    assert rows[0]["Announcement"] == "2022-11-08"
    assert rows[0]["End of Sale"] == "2023-01-31"
    assert rows[0]["End of Support"] == "2025-12-31"
    assert rows[0]["End of Service"] == "2025-12-31"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "teradek_full_support_end_limited_support_continues"
    assert "limited support" in rows[0]["_review_reason"]
    assert rows[1]["Description"] == "IP Video Encoder"
    assert extract_rows(path, "teradek") == rows


def test_fluke_networks_dtx_eol_page_imports_service_calibration_review_rows(tmp_path):
    path = tmp_path / "dtx_1800_series_end_of_life_accessories_parts.html"
    path.write_text(
        """
<html>
<head><title>DTX-1800 Series Cable Analyzer End of Life for Accessories Parts | Fluke Networks</title></head>
<body>
<h1>DTX-1800 Series Cable Analyzer End of Life for Accessories Parts</h1>
<p>Fluke Networks no longer produces any mainframe units or accessories parts for DTX-1800 Series testers.</p>
<p>Fluke Networks launched the DTX-1800, and DTX-1200 CableAnalyzers in 2004. Fluke Service ended repair and calibration services as of June 30, 2018.</p>
<p>The DTX Series is replaced by the DSX CableAnalyzer Series.</p>
</body>
</html>
""",
        encoding="utf-8",
    )

    rows = extract_fluke_networks_dtx_eol_rows(path)

    assert len(rows) == 2
    assert rows[0]["Model"] == "DTX-1800"
    assert rows[0]["Product Name"] == "DTX-1800 CableAnalyzer"
    assert rows[0]["End of Service"] == "2018-06-30"
    assert rows[0]["Replacement Products"] == "DSX CableAnalyzer Series"
    assert rows[0]["_force_lifecycle_review"] is True
    assert (
        rows[0]["_review_policy"]
        == "fluke_networks_dtx_repair_calibration_end_not_security_eol"
    )
    assert rows[1]["Model"] == "DTX-1200"
    assert extract_rows(path, "fluke_networks") == rows


def test_aiphone_discontinued_product_page_imports_status_only_rows(tmp_path):
    path = tmp_path / "page_products_43051_gt-102h.html"
    path.write_text(
        """
<html>
<head>
<title>GT-102H (Discontinued) - Aiphone</title>
<meta name="description" content="The GT-102H is a Discontinued Aiphone 1x2 Module Rain Hood."/>
</head>
<body>
<h1>GT-102H (Discontinued)</h1>
<p>1x2 Module Rain Hood</p>
</body>
</html>
""",
        encoding="utf-8",
    )

    rows = extract_aiphone_discontinued_product_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "GT-102H"
    assert rows[0]["Description"] == "Intercom Mounting Accessory"
    assert rows[0]["_source_url"] == "https://www.aiphone.com/products/gt-102h/"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "aiphone_discontinued_product_page_status_only"
    assert extract_rows(path, "aiphone") == rows


def test_aiphone_resource_pages_do_not_import_as_products(tmp_path):
    path = tmp_path / "page_resources_90000_gt-102h_manual.html"
    path.write_text(
        """
<html>
<head><title>GT-102H (Discontinued) - Aiphone</title></head>
<body><h1>GT-102H installation manual</h1></body>
</html>
""",
        encoding="utf-8",
    )

    assert extract_aiphone_discontinued_product_rows(path) == []
    assert extract_rows(path, "aiphone") == []


def test_crestron_discontinued_product_page_imports_status_only_row(tmp_path):
    path = tmp_path / "product_CEN-SW-POE-5_Products_Catalog_Inactive_Discontinued_C_CEN-SW-POE-5.html"
    path.write_text(
        """
<html>
<head>
<title>CEN-SW-POE-5 [Crestron Electronics, Inc.]</title>
<meta property="og:url" content="https://www.crestron.com/Products/Catalog/Inactive/Discontinued/C/CEN-SW-POE-5" />
<script type="application/ld+json">
{"type":"Product","name":"CEN-SW-POE-5","description":"5-Port PoE Switch","sku":"CEN-SW-POE-5","brand":{"type":"Brand","name":"Crestron"}}
</script>
</head>
<body>
<p class="availability-header discontinued">Discontinued</p>
<table>
<tr><th>Security</th><th></th></tr>
<tr><td>LAN 1 - 5</td><td>RJ45 ports</td></tr>
</table>
</body>
</html>
""",
        encoding="utf-8",
    )

    rows = extract_crestron_discontinued_product_rows(path)

    assert len(rows) == 1
    assert rows[0]["Model"] == "CEN-SW-POE-5"
    assert rows[0]["Description"] == "Network Switch"
    assert rows[0]["_source_url"].endswith("/CEN-SW-POE-5")
    assert rows[0]["_status_only_review"] is True
    assert (
        rows[0]["_review_policy"]
        == "crestron_discontinued_product_page_status_only"
    )
    assert extract_rows(path, "crestron") == rows


def test_crestron_active_product_pages_do_not_import(tmp_path):
    path = tmp_path / "product_AM-TX3-100-I_Products_Catalog_Presentation-and-Conferencing_AirMedia_Transmitter_AM-TX3-100-I.html"
    path.write_text(
        """
<html>
<head>
<meta property="og:url" content="https://www.crestron.com/Products/Catalog/Presentation-and-Conferencing/AirMedia/Transmitters/AM-TX3-100-I" />
<script type="application/ld+json">
{"type":"Product","name":"AM-TX3-100-I","description":"AirMedia transmitter","sku":"AM-TX3-100-I"}
</script>
</head>
<body><p class="availability-header">Available</p></body>
</html>
""",
        encoding="utf-8",
    )

    assert extract_crestron_discontinued_product_rows(path) == []
    assert extract_rows(path, "crestron") == []


def test_aaeon_phaseout_notice_imports_last_buy_as_review(tmp_path):
    html = """
    <html><head>
      <title>FWS-8500: FWS-8500 - Network Appliances</title>
      <link rel="canonical" href="https://www.aaeon.com/en/product/detail/rackmount-network-appliance-fws-8500">
      <meta name="description" content="2U Rackmount High Performance Network Appliance">
    </head><body>
      <h3 class="ph_notice_title">Phaseout Notice</h3>
      <p>Phase-out Reason(s): Due to overall demand ceased, we would like to
      notify you that these product series of FWS-8500 are going to EOL.</p>
      <p>Last Buy Date: Jul. 15, 2020</p>
      <p>Recommend Product: FWS-8600</p>
    </body></html>
    """
    path = tmp_path / "rackmount-network-appliance-fws-8500.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_aaeon_network_appliance_phaseout_rows(path)

    assert rows[0]["Model"] == "FWS-8500"
    assert rows[0]["End of Sale"] == "2020-07-15"
    assert rows[0]["Replacement"] == "FWS-8600"
    assert rows[0]["_force_lifecycle_review"] is True
    assert rows[0]["_review_policy"] == "aaeon_phaseout_last_buy_date_not_security_eol"
    assert extract_rows(path, "aaeon_network_appliances") == rows


def test_status_marked_product_pages_import_as_review(tmp_path):
    cases = [
        (
            "atlona",
            "atlona_product_vgw-250-discontinued.html",
            """
            <html><head>
              <title>AT-VGW-250 *** Discontinued *** - Atlona</title>
              <link rel="canonical" href="https://atlona.com/product/vgw-250-discontinued/" />
              <meta property="og:title" content="AT-VGW-250 *** Discontinued *** - Atlona" />
              <meta property="og:description" content="Velocity Control Gateway" />
            </head><body><h1>AT-VGW-250 *** Discontinued ***</h1></body></html>
            """,
            "AT-VGW-250",
            "atlona_discontinued_product_page_status_only",
        ),
        (
            "atlona",
            "atlona_product_at-ome-sw32.html",
            """
            <html><head>
              <title>3x2 Matrix Switcher with USB-C and HDMI Inputs *** Discontinued *** - Atlona</title>
              <link rel="canonical" href="https://atlona.com/product/at-ome-sw32/" />
              <meta property="og:title" content="3x2 Matrix Switcher with USB-C and HDMI Inputs *** Discontinued *** - Atlona" />
              <meta property="og:description" content="The Atlona AT-OME-SW32 is a 3x2 matrix switcher." />
            </head><body><h1>3x2 Matrix Switcher with USB-C and HDMI Inputs *** Discontinued ***</h1></body></html>
            """,
            "AT-OME-SW32",
            "atlona_discontinued_product_page_status_only",
        ),
        (
            "congatec",
            "product_conga_tfs_eol.html",
            """
            <html><head>
              <title>conga-TFS (EOL) - congatec</title>
              <link rel="canonical" href="https://www.congatec.com/en/products/com-express-type-6/conga-tfs-eol/">
              <meta name="description" content="COM Express Type 6 module">
            </head><body><h1>conga-TFS (EOL)</h1></body></html>
            """,
            "conga-TFS",
            "congatec_eol_product_page_status_only",
        ),
        (
            "portwell",
            "product_webs_35c3.html",
            """
            <html><head>
              <title>WEBS-35C3, 6th Gen Intel Core based Fanless Embedded System</title>
              <meta name="description" content="Fanless embedded system">
            </head><body>
              <h1>WEBS-35C3</h1>
              <h2>*Status: EOL | Migration options: WEBS-45J3</h2>
            </body></html>
            """,
            "WEBS-35C3",
            "portwell_eol_product_page_status_only",
        ),
        (
            "poynting",
            "poynting_product_29561_puck-12-v1-eol.html",
            """
            <html><head>
              <title>POYNTING PUCK-12-V1 (EOL)</title>
              <link rel="canonical" href="https://poynting.tech/antennas/puck-12-v1-eol/" />
              <meta property="og:title" content="PUCK-12-V1 (EOL)" />
              <meta name="description" content="2X2 Wi-Fi MIMO antenna">
            </head><body><h1>End of Life Product</h1></body></html>
            """,
            "PUCK-12-V1",
            "poynting_eol_product_page_status_only",
        ),
    ]

    for vendor_slug, filename, html, model, policy in cases:
        path = tmp_path / filename
        path.write_text(html, encoding="utf-8")

        rows = extract_status_marked_product_page_rows(path, vendor_slug)

        assert rows[0]["Model"] == model
        assert rows[0]["_status_only_review"] is True
        assert rows[0]["_review_policy"] == policy
        assert "End of Support" not in rows[0]
        assert extract_rows(path, vendor_slug) == rows


def test_exfo_discontinued_product_imports_support_end_date(tmp_path):
    html = """
    <html><head>
      <title>T100S-HP | Discontinued product | EXFO</title>
      <link href="https://www.exfo.com/en/products/discontinued-products/t100s-hp/" rel="canonical" />
    </head><body>
      <h1>T100S-HP - High-power continuously tunable laser</h1>
      <span>Discontinued date:</span> 2/1/2023
      <span>End-of-service and support date:</span> 2/1/2028
      <span>End-of-calibration date:</span> 2/1/2028
    </body></html>
    """
    path = tmp_path / "product_t100s_hp.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_exfo_discontinued_product_rows(path)

    assert rows[0]["Model"] == "T100S-HP"
    assert rows[0]["End of Sale"] == "2023-02-01"
    assert rows[0]["End of Support"] == "2028-02-01"
    assert rows[0]["End of Service"] == "2028-02-01"
    assert "_force_lifecycle_review" not in rows[0]
    assert extract_rows(path, "exfo") == rows


def test_nexcom_aiot_mart_eol_product_imports_no_updates_without_date(tmp_path):
    html = """
    <html><head>
      <title>NEXCOM Desktop Network Appliance | DNA 130 Series [EOL] | NEXCOM AIoT Mart</title>
      <link rel="canonical" href="https://www.aiotmart.nexcom.com/product_d.php?lang=en&tb=7&id=1221">
      <meta property="og:description" content="Desktop network security appliance">
    </head><body>
      <h1>NEXCOM Desktop Network Appliance | DNA 130 Series [EOL]</h1>
      <p>This is an <strong>End-of-Life (EOL) model</strong>. Please be advised
      that technical maintenance has been officially discontinued for this product.</p>
      <p><strong>No further software or firmware updates or maintenance will be released</strong>
      for this model.</p>
    </body></html>
    """
    path = tmp_path / "dna_130_series_eol.html"
    path.write_text(html, encoding="utf-8")

    rows = extract_nexcom_aiot_mart_eol_product_rows(path)

    assert rows[0]["Model"] == "DNA 130 Series"
    assert rows[0]["_allow_status_only"] is True
    assert rows[0]["_security_updates_ended_without_exact_date"] is True
    assert rows[0]["_review_policy"] == (
        "nexcom_aiot_mart_eol_no_further_software_firmware_updates_no_exact_date"
    )
    assert extract_rows(path, "nexcom_aiot_mart") == rows


def test_acrosser_eol_products_catalog_imports_model_links(tmp_path):
    path = tmp_path / "eol_products.html"
    path.write_text(
        """
        <html><head>
          <title>EOL products - EOL supplier/manufacturer|ACROSSER</title>
        </head><body>
          <h1>EOL products</h1>
          <a href="productdetail_en.php?id=100">ACM-XD15B7</a>
          <a href="productdetail_en.php?id=41">IVS-6000(AIV-Q170)</a>
          <a href="tel:+886-2-2999-9000">+886 2 2999-9000</a>
        </body></html>
        """,
        encoding="utf-8",
    )

    rows = extract_acrosser_eol_product_rows(path)

    assert [row["Model"] for row in rows] == ["ACM-XD15B7", "IVS-6000(AIV-Q170)"]
    assert all(row["_status_only_review"] is True for row in rows)
    assert all(
        row["_review_policy"] == "acrosser_eol_products_catalog_status_only"
        for row in rows
    )
    assert extract_rows(path, "acrosser") == rows


def test_cincoze_eol_support_page_imports_table_models(tmp_path):
    path = tmp_path / "eol.html"
    path.write_text(
        """
        <html><head><title>EOL | Supports | Cincoze</title></head>
        <body>
          <div class="tb-box">
            <h3 class="ti" title="Rugged Embedded Computers">Rugged Embedded Computers</h3>
            <table>
              <tr><th>Product</th><th>Model</th><th>CPU</th><th>I/O</th></tr>
              <tr><td></td><td>DS-1000P</td><td>Intel Core i7</td><td>4x PoE, 2x LAN</td></tr>
              <tr><td></td><td>No digits here</td><td>Intel</td><td>LAN</td></tr>
            </table>
          </div>
          <div class="tb-box">
            <h3 class="ti" title="CMI Module">CMI Module</h3>
            <table>
              <tr><th>Product</th><th>Model</th><th>Description</th></tr>
              <tr><td></td><td>CMI-LAN104</td><td>CMI Module with 4x Intel GbE LAN</td></tr>
            </table>
          </div>
        </body></html>
        """,
        encoding="utf-8",
    )

    rows = extract_cincoze_eol_rows(path)

    assert [row["Model"] for row in rows] == ["DS-1000P", "CMI-LAN104"]
    assert rows[0]["Description"] == "Rugged Embedded Computer"
    assert rows[1]["Description"] == "Embedded Module"
    assert all(
        row["_review_policy"] == "cincoze_eol_product_table_status_only"
        for row in rows
    )
    assert extract_rows(path, "cincoze") == rows


def test_comnet_discontinued_products_table_imports_product_numbers(tmp_path):
    path = tmp_path / "discontinued_products.html"
    path.write_text(
        """
        <html><head><title>Discontinued Products | Comnet</title></head>
        <body>
          <table>
            <tr><th>Product Number</th><th>Product Name</th><th>Documentation</th></tr>
            <tr><td>CNGE26FX2TX24MSPOE</td><td>Hardened Managed L2+ PoE Switch</td><td>View</td></tr>
            <tr><td>C2</td><td>Card Cage Rackmount</td><td>View</td></tr>
            <tr><td>Documentation</td><td>Not a model</td><td>View</td></tr>
          </table>
        </body></html>
        """,
        encoding="utf-8",
    )

    rows = extract_comnet_discontinued_product_rows(path)

    assert [row["Model"] for row in rows] == ["CNGE26FX2TX24MSPOE", "C2"]
    assert rows[0]["Description"] == "Network Switch"
    assert all(
        row["_review_policy"] == "comnet_discontinued_products_table_status_only"
        for row in rows
    )
    assert extract_rows(path, "comnet") == rows


def test_birddog_previous_lines_imports_no_longer_manufactured_models(tmp_path):
    path = tmp_path / "birddog_previous_lines.html"
    path.write_text(
        """
        <html>
          <head>
            <title>Previous Lines - BirdDog</title>
            <link rel="canonical" href="https://birddog.tv/previous-lines/" />
          </head>
          <body>
            <h2>NO LONGER IN MANUFACTURING (Still Supported &amp; Loved)</h2>
            <table>
              <tr>
                <th class="model">Model</th>
                <th>PF120</th><th>P100</th><th>P110</th><th>P120</th>
                <th>P200</th><th>P240</th><th>P400</th><th>P4K</th>
                <th>A200 &#8226; GEN 2</th><th>A300 &#8226; GEN 2</th>
              </tr>
              <tr><td>CAMERA</td><td></td><td></td><td></td></tr>
            </table>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_birddog_previous_lines_rows(path)

    assert [row["Model"] for row in rows] == [
        "PF120",
        "P100",
        "P110",
        "P120",
        "P200",
        "P240",
        "P400",
        "P4K",
        "A200 \u2022 GEN 2",
        "A300 \u2022 GEN 2",
    ]
    assert rows[0]["Description"] == "Broadcast NDI camera"
    assert rows[0]["Product Status"] == "No longer in manufacturing; still supported"
    assert rows[0]["_status_only_review"] is True
    assert (
        rows[0]["_review_policy"]
        == "birddog_previous_lines_status_only_still_supported"
    )
    assert "A200 GEN 2" in rows[8]["_aliases"]
    assert "Broadcast NDI camera" not in rows[0]["_aliases"]
    assert rows[0]["_suppress_description_aliases"] is True
    assert "End of Support" not in rows[0]
    assert extract_rows(path, "birddog") == rows


def test_uplogix_older_hardware_imports_status_only_platforms(tmp_path):
    path = tmp_path / "uplogix_older_hardware_eol.html"
    path.write_text(
        """
        <html>
          <head>
            <title>End-of-life announced for older hardware - Uplogix Now Lantronix</title>
            <link rel="canonical" href="https://uplogix.com/2016/04/end-of-life-announced-for-older-hardware/" />
          </head>
          <body>
            <p>Uplogix is announcing the end-of-life of a few older hardware platforms,
            specifically the Uplogix 3200, Uplogix 430 and Uplogix 400 platforms.</p>
            <p>Therefore, effective December 31, 2016, we will no longer offer
            maintenance renewal contracts for these products. Hardware not under
            maintenance isn't eligible for software upgrades.</p>
            <h2>Current Uplogix hardware</h2>
            <h2>End-of-life hardware platforms</h2>
            <h2>Uplogix 3200</h2>
            <h2>Uplogix 430</h2>
            <h2>Uplogix 400</h2>
            <h2>Published:</h2>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_uplogix_lantronix_rows(path)

    assert [row["Model"] for row in rows] == [
        "Uplogix 3200",
        "Uplogix 430",
        "Uplogix 400",
    ]
    assert rows[0]["Description"] == "Out-of-band local manager"
    assert "maintenance renewal contracts" in rows[0]["Product Status"]
    assert rows[0]["_status_only_review"] is True
    assert (
        rows[0]["_review_policy"]
        == "uplogix_older_hardware_maintenance_renewal_status_only"
    )
    assert "End of Support" not in rows[0]
    assert rows[0]["_suppress_description_aliases"] is True
    assert extract_rows(path, "uplogix_lantronix") == rows


def test_uplogix_control_center_hardware_support_imports_review_date(tmp_path):
    path = tmp_path / "uplogix_control_center_hardware_support.html"
    path.write_text(
        """
        <html>
          <head>
            <title>End of Hardware Support Notice - Uplogix Now Lantronix</title>
            <link rel="canonical" href="https://uplogix.com/end-of-hardware-support-notice/" />
          </head>
          <body>
            <p>Uplogix is announcing an End of Hardware Support for all Uplogix Control
            Centers running on Dell PowerEdge 2850 and 2950 servers due to the age
            of these servers and the availability of replacement parts.</p>
            <p>The End of Hardware Support is set for October 1, 2016.</p>
            <p>Uplogix will remain committed to supporting future releases of our
            Control Center software on the Dell PowerEdge 2850 and 2950, but reserves
            the right to end that support at any time. Additionally, Uplogix will no
            longer be able to support Hardware failures on these platforms after
            October 1, 2016.</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_uplogix_lantronix_rows(path)

    assert [row["Model"] for row in rows] == [
        "Uplogix Control Center on Dell PowerEdge 2850",
        "Uplogix Control Center on Dell PowerEdge 2950",
    ]
    assert rows[0]["End of Support"] == "2016-10-01"
    assert rows[0]["_force_lifecycle_review"] is True
    assert (
        rows[0]["_review_policy"]
        == "uplogix_control_center_hardware_support_not_security_eol"
    )
    assert "future Control Center software releases may continue" in rows[0]["Product Status"]
    assert "Dell PowerEdge 2850" in rows[0]["_aliases"]
    assert rows[0]["_suppress_description_aliases"] is True
    assert extract_rows(path, "uplogix_lantronix") == rows


def test_ricoh_discontinued_printer_pages_import_sales_ended_names(tmp_path):
    path = tmp_path / "discontinued_color_laser_printers.html"
    path.write_text(
        """
        <html>
          <head>
            <title>カラーレーザープリンター 販売終了品 | リコー</title>
            <link rel="canonical" href="https://www.ricoh.co.jp/products/discontinued/laser-printer-color" />
          </head>
          <body>
            <table>
              <tr>
                <td class="c-products__name">RICOH SP C751/C751M/C750</td>
                <td><a><span class="c-link-a__text">RICOH SP C751/C751M/C750</span></a></td>
              </tr>
              <tr>
                <td class="c-products__name">IPSiO NX860e/760/660S</td>
                <td><a><span class="c-link-a__text">IPSiO NX860e/760/660S</span></a></td>
              </tr>
            </table>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_ricoh_discontinued_printer_rows(path)

    assert [row["Model"] for row in rows] == [
        "RICOH SP C751/C751M/C750",
        "IPSiO NX860e/760/660S",
    ]
    assert rows[0]["Description"] == "Color laser printer"
    assert rows[0]["Product Status"] == "Sales-ended product list (販売終了品)"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "ricoh_discontinued_sales_ended_status_only"
    assert "RICOH SP C751M" in rows[0]["_aliases"]
    assert "RICOH SP C750" in rows[0]["_aliases"]
    assert "IPSiO NX760" in rows[1]["_aliases"]
    assert "IPSiO NX660S" in rows[1]["_aliases"]
    assert rows[0]["_suppress_description_aliases"] is True
    assert "End of Support" not in rows[0]
    assert extract_rows(path, "ricoh_printers") == rows


def test_ricoh_discontinued_parser_skips_repair_service_page(tmp_path):
    path = tmp_path / "repair_end_of_service.html"
    path.write_text(
        """
        <html><head><title>修理対応終了製品のご案内 | リコー</title></head>
        <body>
          <table>
            <tr><th>シリーズ名</th><th>機種名</th></tr>
            <tr><td>RICOH SP 製品群</td><td>RICOH SP C251<br>RICOH SP C250L</td></tr>
          </table>
        </body></html>
        """,
        encoding="utf-8",
    )

    assert extract_ricoh_discontinued_printer_rows(path) == []
    assert extract_rows(path, "ricoh_printers") == []


def test_ip_com_eol_products_table_imports_models_and_skips_junk(tmp_path):
    path = tmp_path / "ip_com_us_end_of_life_products.html"
    path.write_text(
        """
        <html>
          <head><title>EOL-IP-COM    United States</title></head>
          <body>
            <div class="title"><h2>IP-COM End of Life Products</h2></div>
            <table>
              <tr><th>#</th><th>Models</th><th>Description</th></tr>
              <tr><td>1</td><td>AP255(EOL) v2</td><td>300Mbps Wireless In-wall Access Point</td></tr>
              <tr><td>2</td><td>G5324-16F</td><td>L3 Cloud Managed Switch</td></tr>
              <tr><td>3</td><td>iUAP-AC-LR(EOL)</td><td>802.11ac Dual-Band Long Range Access Point</td></tr>
              <tr><td>4</td><td>b</td><td>b</td></tr>
              <tr><td>5</td><td>OpenVPN-Client</td><td>oneword show vv</td></tr>
              <tr><td>6</td><td>TEST2</td><td>TEST</td></tr>
            </table>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    rows = extract_ip_com_eol_product_rows(path)

    assert [row["Model"] for row in rows] == ["AP255 v2", "G5324-16F", "iUAP-AC-LR"]
    assert rows[0]["Hardware Version"] == "v2"
    assert rows[0]["Description"] == "Wireless Access Point"
    assert rows[1]["Description"] == "Network Switch"
    assert rows[0]["Product Status"] == "End of Life products table"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_suppress_description_aliases"] is True
    assert rows[0]["_review_policy"] == "ip_com_eol_products_table_status_only"
    assert "300Mbps Wireless In-wall Access Point" not in rows[0]["_aliases"]
    assert extract_rows(path, "ip_com") == rows


def test_thecus_nas_archive_json_imports_status_only_products(tmp_path):
    path = tmp_path / "linux_archive_soho_home.json"
    path.write_text(
        json.dumps(
            [
                {"PROD_NAME": "N2100", "ANGLE_IMG1": "N2100.png", "PROD_ID": "1"},
                {
                    "PROD_NAME": "N0503 ComboNAS",
                    "ANGLE_IMG1": "N0503.png",
                    "PROD_ID": "26",
                },
            ]
        ),
        encoding="utf-8",
    )

    rows = extract_thecus_nas_archive_rows(path)

    assert [row["Model"] for row in rows] == ["N2100", "N0503 ComboNAS"]
    assert rows[0]["Description"] == "SOHO/Home NAS"
    assert rows[0]["Product Status"] == "Linux NAS archive product list"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_review_policy"] == "thecus_linux_nas_archive_status_only"
    assert rows[0]["_source_url"].endswith("PROD_ID=1")
    assert rows[0]["_suppress_description_aliases"] is True
    assert "SOHO/Home NAS" not in rows[0]["_aliases"]
    assert "1" not in rows[0]["_aliases"]
    assert extract_rows(path, "thecus_nas") == rows


def test_idis_discontinued_products_table_imports_status_only_rows(tmp_path):
    path = tmp_path / "nhedb__raw__discontinued-products.html"
    path.write_text(
        """
        <html><head><title>One Solution. One Company. | IDIS</title></head>
        <body>
          <table>
            <tr><th>Product Name</th><th>Description</th><th>type</th></tr>
            <tr><td>Center</td><td>Enterprise video management software</td><td>Learn More ></td></tr>
            <tr><td>DP-HE1201</td><td>HDMI/VGA Video Encoder</td><td>Learn More ></td></tr>
            <tr><td>DA-LP1101R / DA-LP1101T</td><td>Long Reach PoE Extender</td><td>Learn More ></td></tr>
          </table>
        </body></html>
        """,
        encoding="utf-8",
    )

    rows = extract_idis_discontinued_product_rows(path)

    assert [row["Model"] for row in rows] == [
        "DP-HE1201",
        "DA-LP1101R",
        "DA-LP1101T",
    ]
    assert all(row["_status_only_review"] is True for row in rows)
    assert all(
        row["_review_policy"] == "idis_discontinued_products_table_status_only"
        for row in rows
    )
    assert rows[1]["Description"] == "PoE Network Accessory"
    assert extract_rows(path, "idis") == rows


def test_uniview_discontinued_products_catalog_imports_model_links(tmp_path):
    path = tmp_path / "arab_uniarch_cameras_discontinued_products.html"
    path.write_text(
        """
        <html><head><title>Discontinued Products - Uniview</title></head>
        <body>
          <a href="/arab/Products/DVR/XVR302-16Q3/">XVR302-16Q3</a>
          <a href="/arab/Products/DVR/KIT-XVR301-08Q3-8-UAC-B115-F28/">KIT XVR301-08Q3&8 UAC-B115-F28</a>
          <a href="/Products/Network_Video_Recorders/Ultra_HD_1_0/">울트라 HD 1.0</a>
          <a href="/arab/Technology/201906/853612_322651_0.htm">Ultra265 & U-code 2.0</a>
          <a href="/Products/Network_Cameras/Owlview_Series/">Owlview Series F1.0 lens</a>
        </body></html>
        """,
        encoding="utf-8",
    )

    rows = extract_uniview_discontinued_product_rows(path)

    assert [row["Model"] for row in rows] == [
        "XVR302-16Q3",
        "KIT XVR301-08Q3&8 UAC-B115-F28",
    ]
    assert all(
        row["_review_policy"] == "uniview_discontinued_products_catalog_status_only"
        for row in rows
    )
    assert rows[0]["Description"] == "Video Surveillance Device"
    assert extract_rows(path, "uniview") == rows


def test_legrand_luxul_discontinued_search_imports_json_results(tmp_path):
    path = tmp_path / "luxul_discontinued_search_page_001.json"
    path.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "title": "XAP-1240",
                        "raw": {
                            "computedproducttitle": (
                                "High Power Wireless 300N Outdoor Access Point - DISCONTINUED"
                            ),
                            "computedproductnumber": "XAP-1240",
                            "computedproducturl": (
                                "/products/wireless/wireless_access_points/"
                                "high_power_wireless_300n_outdoor_access_point/xap-1240"
                            ),
                            "productz32xstatus": "Discontinued",
                            "brandfacet": ["Luxul"],
                        },
                    },
                    {
                        "title": "Luxul Easy Setup App",
                        "raw": {
                            "computedproducttitle": "Luxul Easy Setup App",
                            "computedproductnumber": "Luxul Easy Setup App",
                            "productz32xstatus": "Discontinued",
                            "brandfacet": ["Luxul"],
                        },
                    },
                    {
                        "title": "Chief Mount",
                        "raw": {
                            "computedproducttitle": "Chief Mount - DISCONTINUED",
                            "computedproductnumber": "FCAV1U",
                            "productz32xstatus": "Discontinued",
                            "brandfacet": ["Chief"],
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    rows = extract_legrand_luxul_discontinued_search_rows(path)

    assert [row["Model"] for row in rows] == ["XAP-1240"]
    assert rows[0]["Description"] == "Wireless Access Point"
    assert rows[0]["_review_policy"] == (
        "legrand_luxul_discontinued_search_status_only"
    )
    assert extract_rows(path, "legrand_luxul") == rows


def test_verkada_gitbook_index_imports_english_end_of_sale_models(tmp_path):
    path = tmp_path / "verkada_gitbook_site_index.json"
    path.write_text(
        json.dumps(
            {
                "pages": [
                    {
                        "title": "End-of-Sale Products",
                        "pathname": "/command/need-help/end-of-sale-products-policy-overview",
                        "description": "Learn the guidelines for support availability.",
                        "breadcrumbs": [{"label": "Need Help?"}],
                        "lang": "en",
                    },
                    {
                        "title": "CD42-F & CD52-F",
                        "pathname": (
                            "/command/need-help/end-of-sale-products-policy-overview/"
                            "end-of-sale-announcement-for-cd42-f-cd52-f"
                        ),
                        "description": (
                            "Learn details about the end-of-sale information for "
                            "the Verkada CD42-F & CD52-F"
                        ),
                        "breadcrumbs": [{"label": "End-of-Sale Products"}],
                        "lang": "en",
                    },
                    {
                        "title": "BR31 & BR32 (US/CA)",
                        "pathname": (
                            "/command/need-help/end-of-sale-products-policy-overview/"
                            "br31-and-br32-us-ca"
                        ),
                        "description": "End-of-Sale of the Verkada BR31 and BR32 sensors.",
                        "breadcrumbs": [{"label": "End-of-Sale Products"}],
                        "lang": "en",
                    },
                    {
                        "title": "CD42-F y CD52-F",
                        "pathname": "/command/es/necesitas-ayuda/end-of-sale-products-policy-overview/cd42-f-cd52-f",
                        "description": "Spanish duplicate",
                        "breadcrumbs": [{"label": "Productos al final de su vida comercial"}],
                        "lang": "es",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    rows = extract_verkada_end_of_sale_rows(path)

    assert [(row["Model"], row.get("Region", "")) for row in rows] == [
        ("CD42-F", ""),
        ("CD52-F", ""),
        ("BR31", "US/CA"),
        ("BR32", "US/CA"),
    ]
    assert all(
        row["_review_policy"] == "verkada_end_of_sale_product_status_only"
        for row in rows
    )
    assert extract_rows(path, "verkada") == rows


def test_row_to_record_applies_nexcom_no_updates_without_exact_date(tmp_path):
    class FakeBuilder:
        ROOT = tmp_path

        @staticmethod
        def normalize_lookup_key(value):
            return str(value or "").lower().replace(" ", "-")

        @staticmethod
        def make_record(**kwargs):
            return {
                "id": "hw_nexcom_dna_130_series",
                "vendor": "NEXCOM AIoT Mart",
                "vendor_slug": kwargs["vendor_slug"],
                "model": kwargs["model"],
                "model_key": kwargs["model"].lower(),
                "part_number": kwargs["part_number"],
                "device_class": "network_device",
                "dates": kwargs["dates"],
                "lifecycle": {
                    "status": "unknown",
                    "risk": "unknown",
                    "receives_security_updates": None,
                    "reason": "unknown",
                },
                "source": {
                    "source_hint": kwargs["source_hint"],
                    "raw_file": str(kwargs["raw_file"].relative_to(tmp_path)),
                },
                "netwatch": {
                    "match_priority": 1,
                    "finding_title": "old title",
                },
            }

        @staticmethod
        def match_priority(device_class, lifecycle_status):
            return 99 if lifecycle_status == "unsupported" else 1

    raw_file = tmp_path / "dna_130_series_eol.html"
    raw_file.write_text("{}", encoding="utf-8")
    row = {
        "Model": "DNA 130 Series",
        "Product Name": "NEXCOM Desktop Network Appliance | DNA 130 Series [EOL]",
        "Description": "Network Appliance",
        "Product Status": "No further software or firmware updates",
        "_allow_status_only": True,
        "_security_updates_ended_without_exact_date": True,
        "_review_policy": (
            "nexcom_aiot_mart_eol_no_further_software_firmware_updates_no_exact_date"
        ),
        "_prefer_model": True,
    }

    record = row_to_record(
        builder=FakeBuilder(),
        vendor_slug="nexcom_aiot_mart",
        display_name="NEXCOM AIoT Mart",
        raw_file=raw_file,
        row=row,
        source_url="https://www.aiotmart.nexcom.com/product_d.php?lang=en&tb=7&id=1221",
        source_hint="NEXCOM AIoT Mart EOL product page import",
        as_of=date(2026, 6, 4),
    )

    assert record["lifecycle"]["status"] == "unsupported"
    assert record["lifecycle"]["receives_security_updates"] is False
    assert record["lifecycle"]["days_to_security_eol"] is None
    assert record["sunsetscan"]["match_priority"] == 99
    assert record["quality"]["review_required"] is True
    assert record["quality"]["interpretation_policy"] == (
        "nexcom_aiot_mart_eol_no_further_software_firmware_updates_no_exact_date"
    )


def test_grandstream_firmware_eol_table_imports_status_only_products(tmp_path):
    path = tmp_path / "firmware_end_of_life_products.html"
    path.write_text(
        """
<html>
<body>
<table>
<tr><td colspan="3"><h2>End-Of-Life Products</h2></td></tr>
<tr><td><strong>Model</strong></td><td><strong>Firmware</strong></td><td><strong>Notes</strong></td></tr>
<tr><td>BT101/102</td><td>1.1.0.26</td><td></td></tr>
<tr><td>GXE5024<br/>GXE5028</td><td>1.0.1.63</td><td>Special Notes</td></tr>
<tr><td>GXP Language Pack</td><td></td><td></td></tr>
</table>
</body>
</html>
""",
        encoding="utf-8",
    )

    rows = extract_grandstream_status_rows(path)

    assert [row["Model"] for row in rows] == ["BT101/102", "GXE5024", "GXE5028"]
    assert rows[0]["Description"] == "IP Phone"
    assert rows[1]["Description"] == "IP PBX Appliance"
    assert rows[0]["Product Status"] == "end-of-life"
    assert rows[0]["_status_only_review"] is True
    assert rows[0]["_source_url"] == "https://www.grandstream.com/support/firmware"
    assert (
        rows[0]["_review_policy"]
        == "grandstream_eol_firmware_table_status_only"
    )
    assert extract_rows(path, "grandstream") == rows


def test_known_false_positive_html_table_vendors_skip_generic_tables(tmp_path):
    geovision_html = """
    <table>
      <tr><th>Advisory ID</th><th>Advisory</th><th>Status</th><th>Date Published</th></tr>
      <tr><td>GV-IP-2024-11-1</td><td>EOL IP devices OS injection vulnerabilities</td><td>Completed</td><td>20-Nov-24</td></tr>
    </table>
    """
    path = tmp_path / "cyber-security-advisories.html"
    path.write_text(geovision_html, encoding="utf-8")

    assert extract_rows(path, "geovision") == []

    crestron_html = """
    <html>
      <body>
        <h1>CEN-NAS-4TB</h1>
        <p class="availability-header discontinued">Discontinued</p>
        <table>
          <tr><th>Security</th><th></th><th></th></tr>
          <tr>
            <td>LAN 1 - 2</td>
            <td>(2) 8-wire RJ45 female; 10/100/1000BaseT Ethernet ports</td>
            <td></td>
          </tr>
        </table>
      </body>
    </html>
    """
    crestron_path = tmp_path / "product_CEN-NAS-4TB.html"
    crestron_path.write_text(crestron_html, encoding="utf-8")

    assert extract_rows(crestron_path, "crestron") == []

    kramer_html = """
    <html>
      <body>
        <h1>Discontinued products</h1>
        <table>
          <tr><th>Name</th><th>Similar products</th></tr>
          <tr><td>ZUHDBP</td><td>ZyPerUHD Blank Filler Plate</td></tr>
        </table>
      </body>
    </html>
    """
    kramer_path = tmp_path / "legacy_discontinued_products.html"
    kramer_path.write_text(kramer_html, encoding="utf-8")

    assert extract_rows(kramer_path, "kramer_av") == []

    iei_nav_html = """
    <table>
      <tr>
        <th>About IEI About IEI Integration Corp. IEI Group</th>
        <th>Product AIoT & Edge Computing Networking Embedded Computer</th>
      </tr>
      <tr>
        <td>Buy Sales Inquiry Local Distributor USA E-SHOP</td>
        <td>Resource Case Study Catalog & Brochure Download Center</td>
      </tr>
    </table>
    """
    iei_path = tmp_path / "eol_index.html"
    iei_path.write_text(iei_nav_html, encoding="utf-8")

    assert extract_rows(iei_path, "iei") == []

    sierra_html = """
    <table>
      <tr><th>Release</th><th>Product</th><th>End of Software</th><th>Date</th></tr>
      <tr><td>ALEOS 4.18</td><td>RV50X</td><td>Release notes</td><td>2025-03-21</td></tr>
    </table>
    """
    sierra_path = tmp_path / "aleos.html"
    sierra_path.write_text(sierra_html, encoding="utf-8")

    assert extract_rows(sierra_path, "sierra_wireless_airlink") == []

    rockwell_html = """
    <table>
      <tr><th>End of Life</th><th>Discontinued</th></tr>
      <tr>
        <td>Discontinued date announced - actively execute migrations and last time buys.</td>
        <td>New product no longer manufactured or procured. Repair/exchange services may be available.</td>
      </tr>
    </table>
    """
    rockwell_path = tmp_path / "product_lifecycle_status.html"
    rockwell_path.write_text(rockwell_html, encoding="utf-8")

    assert extract_rows(rockwell_path, "rockwell_automation") == []

    lantronix_policy_html = """
    <table>
      <tr><th>End-of-Sale Date</th><th>Last Date of Support</th></tr>
      <tr>
        <td>The last date to order and ship the product/service.</td>
        <td>The date through which Lantronix supports the product/service.</td>
      </tr>
    </table>
    """
    lantronix_path = tmp_path / "lantronix-eol-policy.html"
    lantronix_path.write_text(lantronix_policy_html, encoding="utf-8")

    assert extract_rows(lantronix_path, "lantronix_transition") == []

    moxa_security_html = """
    <html>
      <body>
        <h1>OnCell G3470A-LTE and WDR-3124A Series Cellular Gateways/Router Vulnerabilities</h1>
        <table>
          <tr><th>Item</th><th>Vulnerability Type</th><th>Impact</th></tr>
          <tr>
            <td>8</td>
            <td>Authenticated Command Injection CVE-2021-39279</td>
            <td>A specially crafted command can cause privilege escalation.</td>
          </tr>
        </table>
        <p>As the WDR-3124A Series has been discontinued, mitigation actions are recommended.</p>
      </body>
    </html>
    """
    moxa_path = tmp_path / "oncell-g3470a-wdr-3124a-security-advisory.html"
    moxa_path.write_text(moxa_security_html, encoding="utf-8")

    assert extract_rows(moxa_path, "moxa") == []

    adtran_portal_html = """
    <html>
      <body>
        <h1>Register a Product</h1>
        <table>
          <tr><th>Support</th><th>Product Registration</th><th>End-of-Life</th></tr>
          <tr>
            <td>Open a support case</td>
            <td>View My Products and Licenses</td>
            <td>End-of-Life information link</td>
          </tr>
        </table>
      </body>
    </html>
    """
    adtran_path = tmp_path / "portal-product-registration.html"
    adtran_path.write_text(adtran_portal_html, encoding="utf-8")

    assert extract_rows(adtran_path, "adtran") == []

    lenovo_lookup_html = """
    <html>
      <head>
        <title>Lenovo End of Service Date Lookup for Servers/Storage/Networking products - Lenovo Support US</title>
      </head>
      <body>
        <h1>End of Service Date Lookup</h1>
        <table>
          <tr><th>Geo Code</th><th>Machine Type</th><th>Model</th></tr>
          <tr><td>NA</td><td>No data found</td><td>No data found</td></tr>
        </table>
      </body>
    </html>
    """
    lenovo_lookup_path = tmp_path / "nhedb__raw__end-of-service-lookup.html"
    lenovo_lookup_path.write_text(lenovo_lookup_html, encoding="utf-8")

    assert extract_rows(lenovo_lookup_path, "lenovo_networking") == []

    cyberdata_html = """
    <html>
      <head><title>End-of-Life Products - CyberData Corporation</title></head>
      <body>
        <p>Here are the End-of-Life CyberData products that are no longer being sold,
        but are still supported.</p>
        <table>
          <tr><th>Product</th><th>Status</th></tr>
          <tr><td>011579 SIP Paging 25V/70V Amplifier</td><td>Sold Out</td></tr>
        </table>
      </body>
    </html>
    """
    cyberdata_path = tmp_path / "end_of_life_products_page_1.html"
    cyberdata_path.write_text(cyberdata_html, encoding="utf-8")

    assert extract_rows(cyberdata_path, "cyberdata") == []


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
            dates = dict(kwargs["dates"])
            if dates.get("end_of_life"):
                dates["end_of_security_updates"] = dates["end_of_life"]
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
                "dates": dates,
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
        "End of Life": "2025-07-07",
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
    assert record["dates"]["end_of_life"] == "2025-07-07"
    assert record["dates"]["end_of_security_updates"] is None
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
