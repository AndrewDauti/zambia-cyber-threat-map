"""Pure transforms for the threat-map snapshot.

Nothing in this module touches the network. Counts come only from the
records passed in. A missing feed is None, never a fabricated zero.
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_right
from collections import Counter
from datetime import date, datetime
from typing import Any, Iterable, Mapping, Optional, Sequence


# Exact CISA KEV `vendorProject` strings. This is a curated lens for the
# banking write-up, not a claim that every Zambian bank runs every product.
EDGE_VENDORS = (
    "Fortinet",
    "Cisco",
    "Palo Alto Networks",
    "Citrix",
    "Ivanti",
    "SonicWall",
    "F5",
    "Juniper",
    "Check Point",
    "Pulse Secure",
    "Barracuda Networks",
    "WatchGuard",
    "Sophos",
)

BANKING_VENDORS = EDGE_VENDORS + (
    "Microsoft",
    "VMware",
    "VMware Tanzu",
    "Oracle",
    "Apache",
    "Atlassian",
    "Progress",
    "Fortra",
    "SAP",
    "IBM",
    "Qlik",
    "SolarWinds",
    "Zoho",
    "ConnectWise",
    "Veeam",
)

EXCHANGE_RULE = (
    "vendorProject is Microsoft and the product is 'Exchange', starts with "
    "'Exchange ', or contains 'Exchange Server'. Internet Key Exchange is not counted."
)

# Short map labels. Official ISO names stay in the `name` field.
SHORT_LABELS = {
    "BO": "Bolivia",
    "BN": "Brunei",
    "CD": "DR Congo",
    "CZ": "Czechia",
    "GB": "United Kingdom",
    "IR": "Iran",
    "KP": "North Korea",
    "KR": "South Korea",
    "LA": "Laos",
    "MD": "Moldova",
    "NL": "Netherlands",
    "RU": "Russia",
    "SY": "Syria",
    "TW": "Taiwan",
    "TZ": "Tanzania",
    "US": "United States",
    "VE": "Venezuela",
    "VN": "Vietnam",
    "XK": "Kosovo",
    "XX": "Unknown code",
}


def is_microsoft_exchange(vendor: str, product: str) -> bool:
    """Exchange the mail platform. Not the IKE 'Internet Key Exchange' component."""
    if vendor != "Microsoft":
        return False
    name = (product or "").strip().lower()
    if "internet key exchange" in name:
        return False
    return (
        name == "exchange"
        or name.startswith("exchange ")
        or "exchange server" in name
    )


def percent(part: int, total: int) -> Optional[float]:
    if not total:
        return None
    return round(100 * part / total, 1)


def month_span(start: str, end: str) -> list[str]:
    """Inclusive YYYY-MM range. Gaps in the source become explicit zeros."""
    year, month = (int(piece) for piece in start.split("-"))
    end_year, end_month = (int(piece) for piece in end.split("-"))
    months: list[str] = []
    while (year, month) <= (end_year, end_month):
        months.append(f"{year:04d}-{month:02d}")
        month += 1
        if month == 13:
            month = 1
            year += 1
    return months


def _as_int(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise ValueError(f"expected a count, got {value!r}")
    return int(value)


def _top(counter: Counter, limit: int, name_key: str = "name") -> tuple[list[dict], int, int]:
    ranked = counter.most_common()
    head = [{name_key: name, "count": count} for name, count in ranked[:limit]]
    rest = sum(count for _, count in ranked[limit:])
    return head, rest, len(ranked)


def _vendor_rows(vulns: Sequence[Mapping[str, Any]], names: Sequence[str]) -> list[dict]:
    wanted = set(names)
    totals: Counter = Counter()
    ransomware: Counter = Counter()
    for vuln in vulns:
        vendor = vuln.get("vendorProject") or ""
        if vendor not in wanted:
            continue
        totals[vendor] += 1
        if vuln.get("knownRansomwareCampaignUse") == "Known":
            ransomware[vendor] += 1
    rows = []
    for name in names:
        rows.append(
            {
                "name": name,
                "count": totals[name],
                "ransomware_known": ransomware[name],
            }
        )
    rows.sort(key=lambda row: (-row["count"], row["name"]))
    return rows


def aggregate_kev(vulns: Sequence[Mapping[str, Any]], as_of: date) -> dict:
    if not vulns:
        raise ValueError("KEV feed contained no vulnerabilities")

    flags: Counter = Counter()
    months: Counter = Counter()
    vendors: Counter = Counter()
    vendor_ransomware: Counter = Counter()
    products: Counter = Counter()
    recent: list[dict] = []

    microsoft_total = 0
    microsoft_ransomware = 0
    exchange = 0

    for vuln in vulns:
        flag = vuln.get("knownRansomwareCampaignUse") or "Unknown"
        flags[flag] += 1
        added = str(vuln.get("dateAdded") or "")
        if len(added) < 7:
            raise ValueError(f"KEV row missing dateAdded: {vuln.get('cveID')}")
        months[added[:7]] += 1
        vendor = vuln.get("vendorProject") or "Not named"
        product = vuln.get("product") or "Not named"
        vendors[vendor] += 1
        if flag == "Known":
            vendor_ransomware[vendor] += 1
        products[(vendor, product)] += 1
        if vendor == "Microsoft":
            microsoft_total += 1
            if flag == "Known":
                microsoft_ransomware += 1
            if is_microsoft_exchange(vendor, product):
                exchange += 1
        recent.append(
            {
                "cve": vuln.get("cveID") or "",
                "vendor": vendor,
                "product": product,
                "name": vuln.get("vulnerabilityName") or "",
                "date_added": added[:10],
                "ransomware": flag,
                "description": vuln.get("shortDescription") or "",
            }
        )

    total = len(vulns)
    known = flags.get("Known", 0)
    month_keys = month_span(min(months), max(months))
    by_month = [{"month": key, "count": months.get(key, 0)} for key in month_keys]

    def added_within(days: int) -> int:
        count = 0
        for vuln in vulns:
            added = datetime.strptime(str(vuln["dateAdded"])[:10], "%Y-%m-%d").date()
            delta = (as_of - added).days
            if 0 <= delta <= days:
                count += 1
        return count

    top_vendors = []
    for name, count in vendors.most_common(10):
        top_vendors.append(
            {
                "name": name,
                "count": count,
                "ransomware_known": vendor_ransomware[name],
            }
        )
    top_products = [
        {"vendor": vendor, "product": product, "count": count}
        for (vendor, product), count in products.most_common(8)
    ]
    recent.sort(key=lambda row: (row["date_added"], row["cve"]), reverse=True)

    banking_rows = _vendor_rows(vulns, BANKING_VENDORS)
    edge_rows = _vendor_rows(vulns, EDGE_VENDORS)
    return {
        "total": total,
        "as_of": as_of.isoformat(),
        "ransomware_by_flag": [
            {"flag": flag, "count": count} for flag, count in flags.most_common()
        ],
        "ransomware_known": known,
        "ransomware_other": total - known,
        "ransomware_pct": percent(known, total),
        "added_last_30_days": added_within(30),
        "added_last_90_days": added_within(90),
        "by_month": by_month,
        "top_vendors": top_vendors,
        "top_products": top_products,
        "banking": {
            "rule": "Exact vendorProject match against the curated list stored in vendors.",
            "vendors": list(BANKING_VENDORS),
            "by_vendor": banking_rows,
            "total": sum(row["count"] for row in banking_rows),
            "ransomware_known": sum(row["ransomware_known"] for row in banking_rows),
        },
        "edge": {
            "rule": "Exact vendorProject match against the edge and remote-access list.",
            "vendors": list(EDGE_VENDORS),
            "by_vendor": edge_rows,
            "ransomware_by_vendor": [
                row for row in sorted(edge_rows, key=lambda item: (-item["ransomware_known"], item["name"]))
                if row["ransomware_known"] > 0
            ],
            "total": sum(row["count"] for row in edge_rows),
            "ransomware_known": sum(row["ransomware_known"] for row in edge_rows),
        },
        "microsoft": {
            "total": microsoft_total,
            "ransomware_known": microsoft_ransomware,
            "exchange": exchange,
            "exchange_rule": EXCHANGE_RULE,
        },
        "recent": recent[:8],
    }


def aggregate_dshield(rows: Sequence[Mapping[str, Any]]) -> dict:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise ValueError("DShield country payload was not a list")
    if len(rows) < 50:
        raise ValueError(f"DShield country payload looks truncated ({len(rows)} rows)")

    countries = []
    unknown_sources = 0
    unknown_reports = 0
    unknown_targets = 0
    for row in rows:
        code = str(row.get("country") or "").strip().upper()
        sources = _as_int(row.get("sources"))
        reports = _as_int(row.get("reports"))
        targets = _as_int(row.get("targets"))
        if len(code) != 2 or not code.isalpha():
            unknown_sources += sources
            unknown_reports += reports
            unknown_targets += targets
            continue
        persistence = row.get("persistance", row.get("persistence"))
        persistence_value = float(persistence) if persistence not in (None, "") else None
        current = next((item for item in countries if item["iso2"] == code), None)
        if current is None:
            countries.append(
                {
                    "iso2": code,
                    "sources": sources,
                    "reports": reports,
                    "targets": targets,
                    "persistence": persistence_value,
                }
            )
        else:
            current["sources"] += sources
            current["reports"] += reports
            current["targets"] += targets
            if current["persistence"] is None:
                current["persistence"] = persistence_value
    countries.sort(key=lambda item: (-item["sources"], item["iso2"]))
    return {
        "endpoint": "https://isc.sans.edu/api/country/?json",
        "countries": countries,
        "country_rows": len(countries),
        "total_sources": sum(item["sources"] for item in countries) + unknown_sources,
        "total_reports": sum(item["reports"] for item in countries) + unknown_reports,
        "total_targets": sum(item["targets"] for item in countries) + unknown_targets,
        "unknown_country_sources": unknown_sources,
        "unknown_country_reports": unknown_reports,
        "unknown_country_targets": unknown_targets,
        "field_notes": {
            "sources": "Distinct source IP addresses, as labeled by SANS ISC.",
            "reports": "Report count, as labeled by SANS ISC.",
            "targets": "Distinct target IP addresses, as labeled by SANS ISC.",
            "persistence": "SANS field `persistance`, stored unchanged. The API docs do not define the unit, so the page does not chart it.",
            "window": "The country endpoint does not label its time window. This project does not guess one.",
        },
    }


def _max_text(values: Iterable[Optional[str]]) -> Optional[str]:
    cleaned = [value for value in values if value]
    return max(cleaned) if cleaned else None


def aggregate_feodo(rows: Sequence[Mapping[str, Any]], feed_updated: Optional[str]) -> dict:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise ValueError("Feodo payload was not a list")
    by_country: Counter = Counter()
    online_by_country: Counter = Counter()
    by_malware: Counter = Counter()
    online = 0
    offline = 0
    for row in rows:
        code = str(row.get("country") or "").strip().upper()
        malware = row.get("malware") or "Not named"
        status = str(row.get("status") or row.get("c2_status") or "").strip().lower()
        by_malware[malware] += 1
        if status == "online":
            online += 1
        else:
            offline += 1
        if len(code) == 2 and code.isalpha():
            by_country[code] += 1
            if status == "online":
                online_by_country[code] += 1
    countries = [
        {"iso2": code, "count": count, "online": online_by_country[code]}
        for code, count in by_country.most_common()
    ]
    families, rest, distinct = _top(by_malware, 12)
    return {
        "feed_updated": feed_updated,
        "newest_first_seen": _max_text(str(row.get("first_seen") or "") for row in rows),
        "newest_last_online": _max_text(
            str(row.get("last_online") or "") for row in rows
        ),
        "total": len(rows),
        "online": online,
        "offline": offline,
        "by_country": countries,
        "by_malware": families,
        "other_families": rest,
        "distinct_families": distinct,
        "zambia": by_country.get("ZM", 0),
    }


def _year_of(record: Mapping[str, Any]) -> str:
    for key in ("discovered", "published"):
        raw = str(record.get(key) or "")
        if len(raw) >= 4 and raw[:4].isdigit():
            return raw[:4]
    return "Unknown"


def aggregate_ransomware(rows: Sequence[Mapping[str, Any]], africa_codes: set[str]) -> dict:
    if not rows:
        raise ValueError("ransomware.live dataset contained no records")

    by_country: Counter = Counter()
    by_sector: Counter = Counter()
    by_year: Counter = Counter()
    by_group: Counter = Counter()
    africa_country: Counter = Counter()
    africa_sector: Counter = Counter()
    africa_group: Counter = Counter()
    zambia_sector: Counter = Counter()
    zambia_group: Counter = Counter()
    zambia_year: Counter = Counter()
    unknown_country = 0
    unknown_sector = 0
    global_finance = 0
    africa_total = 0
    africa_finance = 0

    for row in rows:
        code = str(row.get("country") or "").strip().upper()
        sector = str(row.get("activity") or "").strip() or "Not tagged"
        group = str(row.get("group_name") or "").strip() or "Not tagged"
        year = _year_of(row)
        known_country = len(code) == 2 and code.isalpha()
        if not known_country:
            unknown_country += 1
        else:
            by_country[code] += 1
        if sector in {"Not Found", "Not tagged", "none"}:
            unknown_sector += 1
        by_sector[sector] += 1
        by_year[year] += 1
        by_group[group] += 1
        if sector == "Financial Services":
            global_finance += 1
        if known_country and code in africa_codes:
            africa_total += 1
            africa_country[code] += 1
            africa_sector[sector] += 1
            africa_group[group] += 1
            if sector == "Financial Services":
                africa_finance += 1
        if code == "ZM":
            zambia_sector[sector] += 1
            zambia_group[group] += 1
            zambia_year[year] += 1

    def pairs(counter: Counter, key: str, limit: Optional[int] = None) -> list[dict]:
        ranked = counter.most_common(limit)
        return [{key: name, "count": count} for name, count in ranked]

    years = sorted(year for year in by_year if year.isdigit())
    if years:
        by_year_rows = [
            {"year": str(year), "count": by_year.get(str(year), 0)}
            for year in range(int(years[0]), int(years[-1]) + 1)
        ]
    else:
        by_year_rows = []
    if by_year.get("Unknown"):
        by_year_rows.append({"year": "Unknown", "count": by_year["Unknown"]})

    groups, group_rest, group_distinct = _top(by_group, 10)
    return {
        "total": len(rows),
        "unknown_country": unknown_country,
        "unknown_sector": unknown_sector,
        "global_finance": global_finance,
        "by_country": pairs(by_country, "iso2"),
        "by_sector": pairs(by_sector, "sector", 12),
        "by_year": by_year_rows,
        "top_groups": groups,
        "other_groups": group_rest,
        "distinct_groups": group_distinct,
        "africa": {
            "total": africa_total,
            "finance": africa_finance,
            "by_country": pairs(africa_country, "iso2"),
            "by_sector": pairs(africa_sector, "sector", 8),
            "top_groups": pairs(africa_group, "name", 5),
        },
        "zambia": {
            "total": by_country.get("ZM", 0),
            "by_sector": pairs(zambia_sector, "sector"),
            "by_group": pairs(zambia_group, "name"),
            "by_year": pairs(zambia_year, "year"),
        },
    }


def extract_ip(ioc_type: str, value: str) -> Optional[str]:
    """Pull an IPv4 address out of an abuse.ch IOC. IPv6 is left ungeolocated."""
    kind = (ioc_type or "").strip().lower()
    raw = (value or "").strip()
    if kind not in {"ip", "ip:port"}:
        return None
    if raw.count(":") == 1 and "." in raw:
        raw = raw.split(":", 1)[0]
    if ":" in raw:
        return None
    try:
        return str(ipaddress.IPv4Address(raw))
    except ipaddress.AddressValueError:
        return None


def host_ip_from_url(url: str) -> Optional[str]:
    raw = (url or "").strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        from urllib.parse import urlparse

        host = urlparse(raw).hostname or ""
    except ValueError:
        return None
    host = host.strip("[]")
    if ":" in host:
        return None
    try:
        return str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        return None


def build_geo_index(rows: Iterable[tuple[str, str, str]]) -> dict:
    """Index DB-IP style start,end,country rows for bisect lookup."""
    v4: list[tuple[int, int, str]] = []
    v6: list[tuple[int, int, str]] = []
    for start, end, code in rows:
        code = (code or "").strip().upper()
        if not code or code == "ZZ":
            continue
        try:
            if ":" in start:
                v6.append(
                    (
                        int(ipaddress.IPv6Address(start)),
                        int(ipaddress.IPv6Address(end)),
                        code,
                    )
                )
            else:
                v4.append(
                    (
                        int(ipaddress.IPv4Address(start)),
                        int(ipaddress.IPv4Address(end)),
                        code,
                    )
                )
        except ipaddress.AddressValueError:
            continue
    v4.sort()
    v6.sort()
    return {"4": v4, "6": v6}


def lookup_ip(ip: str, index: Mapping[str, Sequence[tuple[int, int, str]]]) -> Optional[str]:
    try:
        if ":" in ip:
            version, number = "6", int(ipaddress.IPv6Address(ip))
        else:
            version, number = "4", int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return None
    rows = index.get(version) or []
    if not rows:
        return None
    starts = [row[0] for row in rows]
    pos = bisect_right(starts, number) - 1
    if pos < 0:
        return None
    start, end, code = rows[pos]
    if start <= number <= end:
        return code
    return None


def count_countries(codes: Iterable[Optional[str]]) -> list[dict]:
    counter: Counter = Counter()
    for code in codes:
        if code and len(code) == 2 and code.isalpha():
            counter[code.upper()] += 1
    return [{"iso2": code, "count": count} for code, count in counter.most_common()]


def aggregate_named_counts(values: Iterable[str], limit: int = 15) -> dict:
    counter: Counter = Counter(value or "Not named" for value in values)
    head, rest, distinct = _top(counter, limit)
    return {"rows": head, "other": rest, "distinct": distinct, "total": sum(counter.values())}


def merge_section(fresh: Mapping[str, Any], previous: Optional[Mapping[str, Any]]) -> dict:
    """Keep the last good copy when a feed fails or the optional key is absent."""
    fresh_copy = dict(fresh)
    previous_ok = bool(previous and previous.get("ok") and previous.get("data") is not None)
    if fresh_copy.get("ok"):
        fresh_copy["stale"] = False
        fresh_copy["stale_reason"] = None
        return fresh_copy
    if previous_ok and (fresh_copy.get("skipped") or not fresh_copy.get("ok")):
        kept = dict(previous)
        kept["stale"] = True
        kept["stale_reason"] = fresh_copy.get("error") or fresh_copy.get("reason") or "Feed unavailable"
        kept["last_attempt_at"] = fresh_copy.get("retrieved_at")
        return kept
    fresh_copy.setdefault("stale", False)
    fresh_copy.setdefault("stale_reason", None)
    return fresh_copy


def _index_by_iso(rows: Optional[Sequence[Mapping[str, Any]]], field: str = "iso2") -> dict:
    if not rows:
        return {}
    return {str(row[field]).upper(): row for row in rows if row.get(field)}


def build_countries(
    iso_rows: Sequence[Mapping[str, Any]],
    dshield: Optional[Mapping[str, Any]],
    ransomware: Optional[Mapping[str, Any]],
    feodo: Optional[Mapping[str, Any]],
    infra: Optional[Mapping[str, Any]],
) -> list[dict]:
    """Join country reference data to whatever feeds actually returned.

    When a feed succeeded, a country that is absent from it is a real zero.
    When a feed failed, the metric is null so the page does not draw a fake zero.
    """
    dshield_rows = _index_by_iso((dshield or {}).get("countries"))
    ransom_rows = _index_by_iso(((ransomware or {}).get("by_country")))
    feodo_rows = _index_by_iso((feodo or {}).get("by_country"))
    infra_rows = _index_by_iso((infra or {}).get("by_country"))
    dshield_ok = dshield is not None
    ransom_ok = ransomware is not None
    feodo_ok = feodo is not None
    infra_ok = infra is not None

    seen = set()
    countries = []
    for row in iso_rows:
        code = str(row.get("alpha-2") or "").upper()
        if len(code) != 2:
            continue
        seen.add(code)
        numeric = str(row.get("country-code") or "").strip()
        official = row.get("name") or code
        countries.append(
            _country_record(
                code,
                official,
                row.get("alpha-3") or "",
                numeric,
                row.get("region") or "",
                row.get("sub-region") or "",
                dshield_rows.get(code),
                ransom_rows.get(code),
                feodo_rows.get(code),
                infra_rows.get(code),
                dshield_ok,
                ransom_ok,
                feodo_ok,
                infra_ok,
            )
        )

    extras = set(dshield_rows) | set(ransom_rows) | set(feodo_rows) | set(infra_rows)
    for code in sorted(extras - seen):
        countries.append(
            _country_record(
                code,
                code,
                "",
                "",
                "",
                "",
                dshield_rows.get(code),
                ransom_rows.get(code),
                feodo_rows.get(code),
                infra_rows.get(code),
                dshield_ok,
                ransom_ok,
                feodo_ok,
                infra_ok,
            )
        )
    countries.sort(key=lambda item: item["name"])
    return countries


def _metric(ok: bool, row: Optional[Mapping[str, Any]], field: str, default: int = 0):
    if not ok:
        return None
    if not row:
        return default
    return row.get(field, default)


def _country_record(
    code,
    official,
    alpha3,
    numeric,
    region,
    subregion,
    dshield_row,
    ransom_row,
    feodo_row,
    infra_row,
    dshield_ok,
    ransom_ok,
    feodo_ok,
    infra_ok,
) -> dict:
    return {
        "iso2": code,
        "iso3": alpha3,
        "numeric": numeric,
        "name": official,
        "label": SHORT_LABELS.get(code, official),
        "region": region,
        "subregion": subregion,
        "dshield_sources": _metric(dshield_ok, dshield_row, "sources"),
        "dshield_reports": _metric(dshield_ok, dshield_row, "reports"),
        "dshield_targets": _metric(dshield_ok, dshield_row, "targets"),
        "ransomware_victims": _metric(ransom_ok, ransom_row, "count"),
        "feodo_c2": _metric(feodo_ok, feodo_row, "count"),
        "feodo_c2_online": _metric(feodo_ok, feodo_row, "online"),
        "abusech_ips": _metric(infra_ok, infra_row, "count"),
    }


def validate_snapshot(snapshot: Mapping[str, Any]) -> None:
    if snapshot.get("schema") != 1:
        raise ValueError("snapshot schema is not 1")
    if not snapshot.get("generated_at"):
        raise ValueError("snapshot missing generated_at")
    countries = snapshot.get("countries")
    if not isinstance(countries, list) or not any(row.get("iso2") == "ZM" for row in countries):
        raise ValueError("snapshot countries do not include Zambia")

    kev = snapshot["sources"]["kev"]
    if kev.get("ok"):
        data = kev["data"]
        flag_total = sum(row["count"] for row in data["ransomware_by_flag"])
        if flag_total != data["total"]:
            raise ValueError("KEV ransomware flags do not add up")
        if sum(row["count"] for row in data["by_month"]) != data["total"]:
            raise ValueError("KEV monthly counts do not add up")
        if data["ransomware_known"] + data["ransomware_other"] != data["total"]:
            raise ValueError("KEV ransomware split does not add up")
        if sum(row["count"] for row in data["banking"]["by_vendor"]) != data["banking"]["total"]:
            raise ValueError("banking vendor counts do not add up")
        if data["total"] <= 0:
            raise ValueError("KEV total must be positive")

    dshield = snapshot["sources"]["dshield"]
    if dshield.get("ok"):
        data = dshield["data"]
        listed = sum(row["sources"] for row in data["countries"])
        if listed + data["unknown_country_sources"] != data["total_sources"]:
            raise ValueError("DShield source counts do not add up")
        joined = sum(
            row["dshield_sources"] or 0
            for row in countries
            if row.get("dshield_sources") is not None
        )
        if joined + data["unknown_country_sources"] != data["total_sources"]:
            raise ValueError("joined DShield counts do not match the feed total")

    ransomware = snapshot["sources"]["ransomware"]
    if ransomware.get("ok"):
        data = ransomware["data"]
        listed = sum(row["count"] for row in data["by_country"])
        if listed + data["unknown_country"] != data["total"]:
            raise ValueError("ransomware country counts do not add up")
        if data["zambia"]["total"] != sum(row["count"] for row in data["zambia"]["by_sector"]):
            raise ValueError("Zambia ransomware sector counts do not add up")
        if data["africa"]["finance"] > data["africa"]["total"]:
            raise ValueError("Africa finance count exceeds Africa total")
        joined = sum(
            row["ransomware_victims"] or 0
            for row in countries
            if row.get("ransomware_victims") is not None
        )
        if joined + data["unknown_country"] != data["total"]:
            raise ValueError("joined ransomware counts do not match the dataset total")
