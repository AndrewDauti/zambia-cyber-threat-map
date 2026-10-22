"""Write the Tableau CSV extracts from the committed snapshot.

Row-level KEV rows are taken from the public CISA catalog only when that
catalog's version, release time, and counts match data/snapshot.json.
Ransomware country and sector tables come from the snapshot aggregates.
Victim names and IP addresses are never written.
"""

from __future__ import annotations

import csv
import json
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.transform import EDGE_VENDORS  # noqa: E402

SNAPSHOT_PATH = ROOT / "data" / "snapshot.json"
OUT_DIR = Path(__file__).resolve().parent / "data"
TWB_PATH = Path(__file__).resolve().parent / "Zambia_Cyber_Threat_Map.twb"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_snapshot() -> dict:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def fetch_kev() -> dict:
    request = urllib.request.Request(
        KEV_URL,
        headers={"User-Agent": "zambia-cyber-threat-map tableau export"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def write_csv(path: Path, header: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row[key] for key in header})


def country_labels(snapshot: dict) -> dict[str, str]:
    labels = {}
    for row in snapshot["countries"]:
        labels[row["iso2"]] = row.get("label") or row.get("name") or row["iso2"]
    return labels


def kev_rows(catalog: dict) -> list[dict]:
    rows = []
    for vuln in catalog["vulnerabilities"]:
        rows.append(
            {
                "cve_id": vuln.get("cveID") or "",
                "vendor": vuln.get("vendorProject") or "Not named",
                "product": vuln.get("product") or "Not named",
                "date_added": str(vuln.get("dateAdded") or "")[:10],
                "ransomware_flag": vuln.get("knownRansomwareCampaignUse") or "Unknown",
            }
        )
    rows.sort(key=lambda row: (row["date_added"], row["cve_id"]))
    return rows


def assert_catalog_matches(snapshot: dict, catalog: dict, rows: list[dict]) -> None:
    kev = snapshot["sources"]["kev"]["data"]
    if catalog.get("catalogVersion") != kev["catalog_version"]:
        raise SystemExit("CISA catalog version does not match the snapshot")
    if catalog.get("dateReleased") != kev["date_released"]:
        raise SystemExit("CISA catalog release time does not match the snapshot")
    if len(rows) != kev["total"] or catalog.get("count") != kev["total"]:
        raise SystemExit("CISA catalog count does not match the snapshot")
    flags = Counter(row["ransomware_flag"] for row in rows)
    if flags.get("Known", 0) != kev["ransomware_known"]:
        raise SystemExit("Known ransomware count does not match the snapshot")
    vendors = Counter(row["vendor"] for row in rows)
    known = Counter(row["vendor"] for row in rows if row["ransomware_flag"] == "Known")
    for item in kev["top_vendors"]:
        if vendors[item["name"]] != item["count"] or known[item["name"]] != item["ransomware_known"]:
            raise SystemExit(f"Vendor count drifted for {item['name']}")
    months = Counter(row["date_added"][:7] for row in rows)
    for item in kev["by_month"]:
        if months.get(item["month"], 0) != item["count"]:
            raise SystemExit(f"Month count drifted for {item['month']}")
    edge = [row for row in rows if row["vendor"] in EDGE_VENDORS]
    if len(edge) != kev["edge"]["total"]:
        raise SystemExit("Edge subset count does not match the snapshot")
    if sum(1 for row in edge if row["ransomware_flag"] == "Known") != kev["edge"]["ransomware_known"]:
        raise SystemExit("Edge ransomware count does not match the snapshot")


def build_tables(snapshot: dict, rows: list[dict]) -> dict[str, tuple[list[str], list[dict]]]:
    kev = snapshot["sources"]["kev"]["data"]
    ransom = snapshot["sources"]["ransomware"]["data"]
    africa = ransom["africa"]
    dshield = snapshot["sources"]["dshield"]["data"]
    labels = country_labels(snapshot)
    zambia = next(row for row in snapshot["countries"] if row["iso2"] == "ZM")

    vendors = Counter(row["vendor"] for row in rows)
    known = Counter(row["vendor"] for row in rows if row["ransomware_flag"] == "Known")
    vendor_counts = [
        {"vendor": name, "entries": count, "ransomware_known": known[name]}
        for name, count in vendors.most_common()
    ]
    top_vendors = [
        {"vendor": item["name"], "entries": item["count"], "ransomware_known": item["ransomware_known"]}
        for item in kev["top_vendors"]
    ]
    edge_entries = [row for row in rows if row["vendor"] in EDGE_VENDORS]
    edge_vendors = [
        {"vendor": item["name"], "entries": item["count"], "ransomware_known": item["ransomware_known"]}
        for item in kev["edge"]["by_vendor"]
    ]
    by_month = [{"month": item["month"], "entries_added": item["count"]} for item in kev["by_month"]]

    sector_rows = [
        {"sector": item["sector"], "victim_count": item["count"], "in_website_chart": "yes"}
        for item in africa["by_sector"]
    ]
    named = sum(item["count"] for item in africa["by_sector"])
    remainder = africa["total"] - named
    if remainder < 0:
        raise SystemExit("Africa sector rows exceed the Africa total")
    if remainder:
        sector_rows.append(
            {"sector": "Other sectors", "victim_count": remainder, "in_website_chart": "no"}
        )
    country_rows = []
    for item in africa["by_country"]:
        country_rows.append(
            {
                "iso2": item["iso2"],
                "country": labels.get(item["iso2"], item["iso2"]),
                "victim_count": item["count"],
            }
        )
    zambia_sectors = [
        {"sector": item["sector"], "victim_count": item["count"]}
        for item in ransom["zambia"]["by_sector"]
    ]
    kpis = [
        {
            "kev_entries": kev["total"],
            "ransomware_known_percent": kev["ransomware_pct"],
            "dshield_zambia_sources": zambia["dshield_sources"],
            "zambia_ransomware_victims": ransom["zambia"]["total"],
            "africa_ransomware_victims": africa["total"],
        }
    ]
    dshield_zambia = [
        {
            "iso2": "ZM",
            "country": "Zambia",
            "sources": zambia["dshield_sources"],
            "reports": zambia["dshield_reports"],
            "targets": zambia["dshield_targets"],
            "summary_sources": dshield["total_sources"],
            "summary_reports": dshield["total_reports"],
            "summary_targets": dshield["total_targets"],
            "ransomware_victims": zambia["ransomware_victims"],
            "feodo_c2": zambia["feodo_c2"],
        }
    ]

    if sum(row["victim_count"] for row in country_rows) != africa["total"]:
        raise SystemExit("Africa country counts do not add up")
    if sum(row["victim_count"] for row in sector_rows) != africa["total"]:
        raise SystemExit("Africa sector counts do not add up")
    if sum(row["victim_count"] for row in zambia_sectors) != ransom["zambia"]["total"]:
        raise SystemExit("Zambia sector counts do not add up")
    if dshield_zambia[0]["sources"] != 48 or dshield["total_sources"] != 308620:
        raise SystemExit("DShield Zambia figures do not match the committed snapshot")

    return {
        "kev_entries.csv": (
            ["cve_id", "vendor", "product", "date_added", "ransomware_flag"],
            rows,
        ),
        "kev_vendor_counts.csv": (["vendor", "entries", "ransomware_known"], vendor_counts),
        "kev_top_vendors.csv": (["vendor", "entries", "ransomware_known"], top_vendors),
        "kev_edge_entries.csv": (
            ["cve_id", "vendor", "product", "date_added", "ransomware_flag"],
            edge_entries,
        ),
        "kev_edge_vendors.csv": (["vendor", "entries", "ransomware_known"], edge_vendors),
        "kev_by_month.csv": (["month", "entries_added"], by_month),
        "africa_ransomware_by_country.csv": (["iso2", "country", "victim_count"], country_rows),
        "africa_ransomware_by_sector.csv": (
            ["sector", "victim_count", "in_website_chart"],
            sector_rows,
        ),
        "zambia_ransomware_by_sector.csv": (["sector", "victim_count"], zambia_sectors),
        "dshield_zambia.csv": (
            [
                "iso2",
                "country",
                "sources",
                "reports",
                "targets",
                "summary_sources",
                "summary_reports",
                "summary_targets",
                "ransomware_victims",
                "feodo_c2",
            ],
            dshield_zambia,
        ),
        "kpis.csv": (
            [
                "kev_entries",
                "ransomware_known_percent",
                "dshield_zambia_sources",
                "zambia_ransomware_victims",
                "africa_ransomware_victims",
            ],
            kpis,
        ),
    }


def q(name: str) -> str:
    return "{" + str(uuid4()).upper() + "}"


def datasource(name: str, filename: str, columns: list[tuple[str, str]]) -> ET.Element:
    node = ET.Element("datasource", {"caption": filename, "inline": "true", "name": name, "version": "18.1"})
    connection = ET.SubElement(node, "connection", {"class": "federated"})
    named = ET.SubElement(connection, "named-connections")
    scan = f"textscan.{filename.replace('.csv', '')}"
    named_connection = ET.SubElement(named, "named-connection", {"caption": filename, "name": scan})
    ET.SubElement(
        named_connection,
        "connection",
        {
            "class": "textscan",
            "directory": "data",
            "filename": filename,
            "password": "",
            "server": "",
        },
    )
    relation = ET.SubElement(
        connection,
        "relation",
        {
            "connection": scan,
            "name": filename,
            "table": f"[{filename.replace('.', '#')}]",
            "type": "table",
        },
    )
    cols = ET.SubElement(
        relation,
        "columns",
        {"character-set": "UTF-8", "header": "yes", "locale": "en_US", "separator": ","},
    )
    maps = ET.SubElement(connection, "cols")
    for ordinal, (column_name, datatype) in enumerate(columns):
        ET.SubElement(cols, "column", {"datatype": datatype, "name": column_name, "ordinal": str(ordinal)})
        ET.SubElement(maps, "map", {"key": f"[{column_name}]", "value": f"[{filename}].[{column_name}]"})
    ET.SubElement(node, "aliases", {"enabled": "yes"})
    for column_name, datatype in columns:
        attrs = {
            "datatype": datatype,
            "name": f"[{column_name}]",
            "role": "measure" if datatype in {"integer", "real"} else "dimension",
            "type": "quantitative" if datatype in {"integer", "real"} else "nominal",
        }
        if column_name == "iso2":
            attrs["semantic-role"] = "[Country].[ISO3166_2]"
        ET.SubElement(node, "column", attrs)
    if any(column_name == "iso2" for column_name, _datatype in columns):
        for generated, role in (
            ("Latitude (generated)", "[Geographical].[Latitude]"),
            ("Longitude (generated)", "[Geographical].[Longitude]"),
        ):
            ET.SubElement(
                node,
                "column",
                {
                    "datatype": "real",
                    "hidden": "true",
                    "name": f"[{generated}]",
                    "role": "measure",
                    "semantic-role": role,
                    "type": "quantitative",
                },
            )
    return node


def column_instance(parent: ET.Element, column: str, derivation: str, instance: str, kind: str) -> None:
    ET.SubElement(
        parent,
        "column-instance",
        {
            "column": f"[{column}]",
            "derivation": derivation,
            "name": instance,
            "pivot": "key",
            "type": kind,
        },
    )


def worksheet(
    name: str,
    ds: str,
    fields: list[tuple[str, str, str, str, str]],
    rows: str,
    cols: str,
    mark: str,
    title: str,
    sort_column: str | None = None,
    sort_values: list[str] | None = None,
    color: str | None = None,
    encodings: list[tuple[str, str]] | None = None,
) -> ET.Element:
    sheet = ET.Element("worksheet", {"name": name})
    layout = ET.SubElement(sheet, "layout-options")
    formatted = ET.SubElement(ET.SubElement(layout, "title"), "formatted-text")
    ET.SubElement(formatted, "run").text = title
    table = ET.SubElement(sheet, "table")
    view = ET.SubElement(table, "view")
    sources = ET.SubElement(view, "datasources")
    ET.SubElement(sources, "datasource", {"name": ds})
    dependencies = ET.SubElement(view, "datasource-dependencies", {"datasource": ds})
    for column, datatype, derivation, instance, kind in fields:
        attrs = {
            "datatype": datatype,
            "name": f"[{column}]",
            "role": "measure" if datatype in {"integer", "real"} else "dimension",
            "type": "quantitative" if kind == "quantitative" else "nominal",
        }
        if column == "iso2":
            attrs["semantic-role"] = "[Country].[ISO3166_2]"
        ET.SubElement(dependencies, "column", attrs)
        column_instance(dependencies, column, derivation, instance, kind)
    if sort_column and sort_values:
        manual = ET.SubElement(
            view,
            "manual-sort",
            {"column": f"[{ds}].[{sort_column}]", "direction": "ASC"},
        )
        dictionary = ET.SubElement(manual, "dictionary")
        for value in sort_values:
            ET.SubElement(dictionary, "bucket").text = f'"{value}"'
    ET.SubElement(view, "aggregation", {"value": "true"})
    style = ET.SubElement(table, "style")
    if color:
        rule = ET.SubElement(style, "style-rule", {"element": "mark"})
        ET.SubElement(rule, "format", {"attr": "mark-color", "value": color})
    panes = ET.SubElement(table, "panes")
    pane = ET.SubElement(panes, "pane", {"selection-relaxation-option": "selection-relaxation-allow"})
    ET.SubElement(ET.SubElement(pane, "view"), "breakdown", {"value": "auto"})
    ET.SubElement(pane, "mark", {"class": mark})
    if encodings:
        encoding = ET.SubElement(pane, "encodings")
        for kind, column in encodings:
            ET.SubElement(encoding, kind, {"column": column})
    ET.SubElement(table, "rows").text = rows
    ET.SubElement(table, "cols").text = cols
    ET.SubElement(sheet, "simple-id", {"uuid": q("id")})
    return sheet


def build_workbook(tables: dict[str, tuple[list[str], list[dict]]]) -> ET.ElementTree:
    root = ET.Element(
        "workbook",
        {
            "original-version": "18.1",
            "source-build": "2025.3.1 (20253.25.1210.1815)",
            "source-platform": "win",
            "version": "18.1",
            "xmlns:user": "http://www.tableausoftware.com/xml/user",
        },
    )
    ET.SubElement(root, "preferences")
    datasources = ET.SubElement(root, "datasources")
    specs = {
        "federated.kpis": (
            "kpis.csv",
            [
                ("kev_entries", "integer"),
                ("ransomware_known_percent", "real"),
                ("dshield_zambia_sources", "integer"),
                ("zambia_ransomware_victims", "integer"),
                ("africa_ransomware_victims", "integer"),
            ],
        ),
        "federated.africa": (
            "africa_ransomware_by_country.csv",
            [("iso2", "string"), ("country", "string"), ("victim_count", "integer")],
        ),
        "federated.months": ("kev_by_month.csv", [("month", "string"), ("entries_added", "integer")]),
        "federated.vendors": (
            "kev_top_vendors.csv",
            [("vendor", "string"), ("entries", "integer"), ("ransomware_known", "integer")],
        ),
        "federated.sectors": (
            "africa_ransomware_by_sector.csv",
            [("sector", "string"), ("victim_count", "integer"), ("in_website_chart", "string")],
        ),
    }
    for name, (filename, columns) in specs.items():
        datasources.append(datasource(name, filename, columns))

    sheets = ET.SubElement(root, "worksheets")
    kpi_fields = {
        "KPI KEV entries": ("kev_entries", "integer", "CISA KEV entries"),
        "KPI Known ransomware percent": ("ransomware_known_percent", "real", "Known ransomware use, percent"),
        "KPI Zambia sources": ("dshield_zambia_sources", "integer", "Zambia DShield source IPs"),
        "KPI Zambia victims": ("zambia_ransomware_victims", "integer", "Zambia ransomware victims"),
        "KPI Africa victims": ("africa_ransomware_victims", "integer", "Africa ransomware victims"),
    }
    for sheet_name, (field, datatype, title) in kpi_fields.items():
        instance = f"[sum:{field}:qk]"
        sheets.append(
            worksheet(
                sheet_name,
                "federated.kpis",
                [(field, datatype, "Sum", instance, "quantitative")],
                f"[federated.kpis].{instance}",
                "",
                "Text",
                title,
            )
        )
    sheets.append(
        worksheet(
            "Africa map",
            "federated.africa",
            [
                ("iso2", "string", "None", "[none:iso2:nk]", "nominal"),
                ("country", "string", "None", "[none:country:nk]", "nominal"),
                ("victim_count", "integer", "Sum", "[sum:victim_count:qk]", "quantitative"),
            ],
            "[federated.africa].[Latitude (generated)]",
            "[federated.africa].[Longitude (generated)]",
            "Multipolygon",
            "Africa disclosed ransomware victims",
            encodings=[
                ("color", "[federated.africa].[sum:victim_count:qk]"),
                ("lod", "[federated.africa].[none:iso2:nk]"),
                ("text", "[federated.africa].[none:country:nk]"),
            ],
        )
    )
    sheets.append(
        worksheet(
            "KEV over time",
            "federated.months",
            [
                ("month", "string", "None", "[none:month:nk]", "nominal"),
                ("entries_added", "integer", "Sum", "[sum:entries_added:qk]", "quantitative"),
            ],
            "[federated.months].[sum:entries_added:qk]",
            "[federated.months].[none:month:nk]",
            "Line",
            "CISA KEV entries added by month",
            color="#5ee0c3",
            sort_column="none:month:nk",
            sort_values=[row["month"] for row in tables["kev_by_month.csv"][1]],
        )
    )
    sheets.append(
        worksheet(
            "Top vendors",
            "federated.vendors",
            [
                ("vendor", "string", "None", "[none:vendor:nk]", "nominal"),
                ("entries", "integer", "Sum", "[sum:entries:qk]", "quantitative"),
            ],
            "[federated.vendors].[none:vendor:nk]",
            "[federated.vendors].[sum:entries:qk]",
            "Bar",
            "Top exploited vendors in the CISA catalog",
            color="#e7b34a",
            sort_column="none:vendor:nk",
            sort_values=[row["vendor"] for row in tables["kev_top_vendors.csv"][1]],
        )
    )
    sheets.append(
        worksheet(
            "Africa sectors",
            "federated.sectors",
            [
                ("sector", "string", "None", "[none:sector:nk]", "nominal"),
                ("victim_count", "integer", "Sum", "[sum:victim_count:qk]", "quantitative"),
            ],
            "[federated.sectors].[none:sector:nk]",
            "[federated.sectors].[sum:victim_count:qk]",
            "Bar",
            "Africa ransomware victims by sector",
            color="#e7b34a",
            sort_column="none:sector:nk",
            sort_values=[row["sector"] for row in tables["africa_ransomware_by_sector.csv"][1]],
        )
    )

    dashboards = ET.SubElement(root, "dashboards")
    dashboard = ET.SubElement(dashboards, "dashboard", {"name": "Zambia Cyber Threat Map"})
    title = ET.SubElement(ET.SubElement(ET.SubElement(dashboard, "layout-options"), "title"), "formatted-text")
    ET.SubElement(title, "run").text = "Zambia Cyber Threat Map"
    ET.SubElement(dashboard, "style")
    ET.SubElement(
        dashboard,
        "size",
        {"maxheight": "1100", "maxwidth": "1400", "minheight": "1100", "minwidth": "1400", "sizing-mode": "fixed"},
    )
    zones = ET.SubElement(dashboard, "zones")
    outer = ET.SubElement(zones, "zone", {"h": "100000", "id": "1", "type-v2": "layout-basic", "w": "100000", "x": "0", "y": "0"})
    flow = ET.SubElement(
        outer,
        "zone",
        {"h": "98000", "id": "2", "param": "vert", "type-v2": "layout-flow", "w": "98000", "x": "1000", "y": "1000"},
    )
    ET.SubElement(
        flow,
        "zone",
        {"fixed-size": "48", "h": "6000", "id": "3", "is-fixed": "true", "type-v2": "title", "w": "98000", "x": "1000", "y": "1000"},
    )
    kpi_row = ET.SubElement(
        flow,
        "zone",
        {"h": "14000", "id": "4", "param": "horz", "type-v2": "layout-flow", "w": "98000", "x": "1000", "y": "7000"},
    )
    for index, sheet_name in enumerate(kpi_fields):
        ET.SubElement(
            kpi_row,
            "zone",
            {
                "h": "14000",
                "id": str(10 + index),
                "name": sheet_name,
                "w": "19600",
                "x": str(1000 + index * 19600),
                "y": "7000",
            },
        )
    middle = ET.SubElement(
        flow,
        "zone",
        {"h": "40000", "id": "20", "param": "horz", "type-v2": "layout-flow", "w": "98000", "x": "1000", "y": "21000"},
    )
    ET.SubElement(middle, "zone", {"h": "40000", "id": "21", "name": "Africa map", "w": "52000", "x": "1000", "y": "21000"})
    ET.SubElement(middle, "zone", {"h": "40000", "id": "22", "name": "KEV over time", "w": "46000", "x": "53000", "y": "21000"})
    bottom = ET.SubElement(
        flow,
        "zone",
        {"h": "38000", "id": "23", "param": "horz", "type-v2": "layout-flow", "w": "98000", "x": "1000", "y": "61000"},
    )
    ET.SubElement(bottom, "zone", {"h": "38000", "id": "24", "name": "Top vendors", "w": "49000", "x": "1000", "y": "61000"})
    ET.SubElement(bottom, "zone", {"h": "38000", "id": "25", "name": "Africa sectors", "w": "49000", "x": "50000", "y": "61000"})
    ET.SubElement(dashboard, "simple-id", {"uuid": q("dash")})

    windows = ET.SubElement(root, "windows", {"source-height": "30"})
    for sheet_name in list(kpi_fields) + ["Africa map", "KEV over time", "Top vendors", "Africa sectors"]:
        window = ET.SubElement(windows, "window", {"class": "worksheet", "name": sheet_name})
        cards = ET.SubElement(window, "cards")
        left = ET.SubElement(ET.SubElement(cards, "edge", {"name": "left"}), "strip", {"size": "160"})
        ET.SubElement(left, "card", {"type": "pages"})
        ET.SubElement(left, "card", {"type": "filters"})
        ET.SubElement(left, "card", {"type": "marks"})
        top = ET.SubElement(cards, "edge", {"name": "top"})
        ET.SubElement(ET.SubElement(top, "strip", {"size": "30"}), "card", {"type": "columns"})
        ET.SubElement(ET.SubElement(top, "strip", {"size": "30"}), "card", {"type": "rows"})
        ET.SubElement(window, "simple-id", {"uuid": q("window")})
    dash = ET.SubElement(windows, "window", {"class": "dashboard", "maximized": "true", "name": "Zambia Cyber Threat Map"})
    viewpoints = ET.SubElement(dash, "viewpoints")
    for sheet_name in list(kpi_fields) + ["Africa map", "KEV over time", "Top vendors", "Africa sectors"]:
        ET.SubElement(viewpoints, "viewpoint", {"name": sheet_name})
    ET.SubElement(dash, "simple-id", {"uuid": q("dash-window")})
    return ET.ElementTree(root)


def assert_no_secrets(directory: Path) -> None:
    banned = {"post_title", "victim_name", "organization", "ip_address", "website", "description"}
    for path in directory.glob("*.csv"):
        text = path.read_text(encoding="utf-8")
        header = text.splitlines()[0].split(",")
        found = banned.intersection(header)
        if found:
            raise SystemExit(f"{path.name} has a forbidden column {sorted(found)}")
        for line in text.splitlines()[1:]:
            for part in line.split(","):
                if part.count(".") == 3 and all(piece.isdigit() for piece in part.split(".")):
                    raise SystemExit(f"{path.name} contains an IP-like value")


def main() -> None:
    snapshot = load_snapshot()
    catalog = fetch_kev()
    rows = kev_rows(catalog)
    assert_catalog_matches(snapshot, catalog, rows)
    tables = build_tables(snapshot, rows)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for filename, (header, records) in tables.items():
        write_csv(OUT_DIR / filename, header, records)
    tree = build_workbook(tables)
    ET.indent(tree, space="  ")
    tree.write(TWB_PATH, encoding="utf-8", xml_declaration=True)
    parsed = ET.parse(TWB_PATH)
    filenames = [node.get("filename") for node in parsed.iter("connection") if node.get("filename")]
    for filename in filenames:
        if not (OUT_DIR / filename).is_file():
            raise SystemExit(f"Workbook points at a missing file: {filename}")
        directory = next(node.get("directory") for node in parsed.iter("connection") if node.get("filename") == filename)
        if directory != "data":
            raise SystemExit(f"{filename} is not a relative data/ connection")
    assert_no_secrets(OUT_DIR)
    print(f"wrote {len(tables)} csv files and {TWB_PATH.name}")
    print("connections:", ", ".join(filenames))


if __name__ == "__main__":
    main()
