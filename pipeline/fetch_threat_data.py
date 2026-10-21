"""Download public threat feeds and write the static snapshot.

Raw victim records and IP blocklists are aggregated in memory and are not
written to the repo. If a feed is down, the previous good section is kept
and marked stale. URLhaus and ThreatFox run only when ABUSECH_AUTH_KEY is set.

Usage (from the repo root):
    python3 pipeline/fetch_threat_data.py
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.transform import (
    aggregate_dshield,
    aggregate_feodo,
    aggregate_kev,
    aggregate_named_counts,
    aggregate_ransomware,
    build_countries,
    build_geo_index,
    count_countries,
    extract_ip,
    host_ip_from_url,
    lookup_ip,
    merge_section,
    validate_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
SNAPSHOT_PATH = DATA_DIR / "snapshot.json"
ISO_PATH = Path(__file__).resolve().parent / "vendor" / "iso3166.json"

USER_AGENT = (
    "zambia-cyber-threat-map/1.0 "
    "(academic portfolio; +https://github.com/andrewdauti/zambia-cyber-threat-map)"
)
MAX_BYTES = 80 * 1024 * 1024
CORE_SOURCES = ("kev", "dshield", "ransomware", "feodo")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DSHIELD_URL = "https://isc.sans.edu/api/country/?json"
FEODO_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
FEODO_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
RANSOM_URL = "https://data.ransomware.live/victims.json"
THREATFOX_EXPORT = "https://threatfox-api.abuse.ch/v2/files/exports"
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports"
DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"


class FeedError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _secret() -> str:
    return os.environ.get("ABUSECH_AUTH_KEY", "").strip()


def log(message: str) -> None:
    text = str(message)
    secret = _secret()
    if secret:
        text = text.replace(secret, "[redacted]")
    print(text, flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def request(url: str, timeout: int = 60, retries: int = 3) -> tuple[int, bytes, str]:
    """GET a URL. Errors never include the URL, so an Auth-Key in a path stays out of logs."""
    last: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/csv, text/plain, */*"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                length = response.headers.get("Content-Length")
                if length and int(length) > MAX_BYTES:
                    raise FeedError(f"response is larger than {MAX_BYTES} bytes")
                body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise FeedError(f"response is larger than {MAX_BYTES} bytes")
                content_type = response.headers.get("Content-Type", "")
                return status, body, content_type
        except FeedError:
            raise
        except urllib.error.HTTPError as exc:
            last = FeedError(f"HTTP {exc.code}", status=exc.code)
            if exc.code not in {429, 500, 502, 503, 504}:
                raise last from None
        except urllib.error.URLError as exc:
            reason = exc.reason.__class__.__name__
            last = FeedError(f"network error ({reason})")
        except TimeoutError:
            last = FeedError("timed out")
        if attempt + 1 < retries:
            time.sleep(min(2 ** attempt, 8))
    assert last is not None
    raise last


def _looks_like_html(body: bytes, content_type: str) -> bool:
    if "html" in content_type.lower():
        return True
    snippet = body.lstrip()[:1].lower()
    return snippet == b"<"


def load_json_feed(url: str, timeout: int = 60) -> tuple[object, str]:
    status, body, content_type = request(url, timeout=timeout)
    if _looks_like_html(body, content_type):
        raise FeedError(f"expected data, got HTML (HTTP {status})")
    try:
        return json.loads(body.decode("utf-8-sig")), content_type
    except json.JSONDecodeError as exc:
        raise FeedError(f"response was not JSON ({exc.msg})") from None


def load_text_feed(url: str, timeout: int = 60) -> str:
    _status, body, content_type = request(url, timeout=timeout)
    if _looks_like_html(body, content_type):
        raise FeedError("expected a text feed, got HTML")
    return body.decode("utf-8-sig", errors="replace")


def _section(source_id: str, name: str, url: str, license_name: str, **extra) -> dict:
    section = {
        "id": source_id,
        "name": name,
        "url": url,
        "license": license_name,
        "ok": False,
        "skipped": False,
        "stale": False,
        "error": None,
        "reason": None,
        "stale_reason": None,
        "retrieved_at": _now(),
        "last_attempt_at": None,
        "data": None,
    }
    section.update(extra)
    return section


def fetch_kev() -> dict:
    section = _section(
        "kev",
        "CISA Known Exploited Vulnerabilities Catalog",
        KEV_URL,
        "United States government work (public domain). Catalog terms: https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )
    try:
        payload, _content_type = load_json_feed(KEV_URL, timeout=90)
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise FeedError("KEV payload did not contain a vulnerabilities list")
        vulns = payload["vulnerabilities"]
        as_of = datetime.now(timezone.utc).date()
        data = aggregate_kev(vulns, as_of)
        reported = payload.get("count")
        if isinstance(reported, int) and reported != data["total"]:
            raise FeedError(
                f"KEV count field is {reported} but the list length is {data['total']}"
            )
        data["catalog_version"] = payload.get("catalogVersion")
        data["date_released"] = payload.get("dateReleased")
        data["title"] = payload.get("title")
        data["count_reported"] = reported
        section["data"] = data
        section["ok"] = True
        log(
            f"KEV {data['catalog_version']}: {data['total']} vulnerabilities, "
            f"{data['ransomware_known']} known ransomware use"
        )
    except (FeedError, ValueError) as exc:
        section["error"] = str(exc)
        log(f"KEV failed: {exc}")
    return section


def fetch_dshield() -> dict:
    section = _section(
        "dshield",
        "SANS Internet Storm Center / DShield country summary",
        DSHIELD_URL,
        "CC BY-NC-SA 4.0. Attribute SANS Internet Storm Center. https://creativecommons.org/licenses/by-nc-sa/4.0/ and https://isc.sans.edu/api/",
    )
    try:
        payload, _content_type = load_json_feed(DSHIELD_URL, timeout=60)
        if not isinstance(payload, list):
            raise FeedError("DShield country payload was not a list")
        data = aggregate_dshield(payload)
        section["data"] = data
        section["ok"] = True
        log(
            f"DShield: {data['country_rows']} countries, "
            f"{data['total_sources']} source IPs"
        )
    except (FeedError, ValueError) as exc:
        section["error"] = str(exc)
        log(f"DShield failed: {exc}")
    return section


def _feodo_updated(csv_text: str) -> str | None:
    for line in csv_text.splitlines():
        if "Last updated:" in line:
            raw = line.split("Last updated:", 1)[1]
            raw = raw.replace("#", " ").strip()
            return raw or None
    return None


def fetch_feodo() -> dict:
    section = _section(
        "feodo",
        "abuse.ch Feodo Tracker botnet C2 blocklist",
        FEODO_JSON_URL,
        "abuse.ch Feodo Tracker terms: https://feodotracker.abuse.ch/blocklist/ . Counts only; IP addresses are not republished.",
    )
    try:
        payload, _content_type = load_json_feed(FEODO_JSON_URL, timeout=60)
        if not isinstance(payload, list):
            raise FeedError("Feodo payload was not a list")
        feed_updated = None
        try:
            feed_updated = _feodo_updated(load_text_feed(FEODO_CSV_URL, timeout=60))
        except FeedError as exc:
            log(f"Feodo CSV header unavailable ({exc}); keeping JSON counts")
        data = aggregate_feodo(payload, feed_updated)
        section["data"] = data
        section["ok"] = True
        log(
            f"Feodo: {data['total']} C2 addresses "
            f"({data['online']} online, {data['offline']} offline), "
            f"feed updated {feed_updated or 'unknown'}"
        )
    except (FeedError, ValueError) as exc:
        section["error"] = str(exc)
        log(f"Feodo failed: {exc}")
    return section


def fetch_ransomware(africa_codes: set[str]) -> dict:
    section = _section(
        "ransomware",
        "Ransomware.live open victim dataset",
        RANSOM_URL,
        "Non-commercial academic use with attribution. Source: Ransomware.live (https://www.ransomware.live/). Raw victim records are not republished. Terms: https://www.ransomware.live/t&c",
    )
    try:
        payload, _content_type = load_json_feed(RANSOM_URL, timeout=180)
        if not isinstance(payload, list):
            raise FeedError("ransomware.live payload was not a list")
        # Titles, websites, and descriptions are intentionally dropped here.
        slim = [
            {
                "country": row.get("country"),
                "activity": row.get("activity"),
                "group_name": row.get("group_name"),
                "discovered": row.get("discovered"),
                "published": row.get("published"),
            }
            for row in payload
            if isinstance(row, dict)
        ]
        data = aggregate_ransomware(slim, africa_codes)
        data["dataset_url"] = RANSOM_URL
        data["attribution"] = "Source: Ransomware.live"
        section["data"] = data
        section["ok"] = True
        log(
            f"ransomware.live: {data['total']} victim records, "
            f"{data['africa']['total']} in Africa, "
            f"{data['zambia']['total']} tagged ZM, "
            f"{data['africa']['finance']} Africa financial services"
        )
    except (FeedError, ValueError) as exc:
        section["error"] = str(exc)
        log(f"ransomware.live failed: {exc}")
    return section


def _csv_dicts(text: str) -> list[dict]:
    """Parse an abuse.ch CSV. Banner comments are dropped; a commented header is kept."""
    header = None
    data_lines = []
    header_tokens = ("ioc_value", "ioc_type", "malware", "url", "threat", "first_seen")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= {"#", " "}:
            continue
        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()
            lowered = candidate.lower()
            if header is None and any(token in lowered for token in header_tokens):
                header = candidate
            continue
        data_lines.append(stripped)
    if header is None:
        if not data_lines:
            raise FeedError("CSV feed was empty")
        header = data_lines[0]
        data_lines = data_lines[1:]
    reader = csv.DictReader(io.StringIO("\n".join([header, *data_lines])), skipinitialspace=True)
    if not reader.fieldnames:
        raise FeedError("CSV feed had no header")
    rows = []
    for row in reader:
        cleaned = {}
        for key, value in row.items():
            if key is None:
                continue
            cleaned[key.strip().lstrip("#").strip().strip('"').lower()] = (value or "").strip()
        rows.append(cleaned)
    return rows


def _column(row: dict, *names: str) -> str:
    for name in names:
        if name in row and row[name]:
            return row[name]
    return ""


def _download_dbip() -> tuple[dict, str]:
    today = datetime.now(timezone.utc).date()
    year, month = today.year, today.month
    last_error = "DB-IP download failed"
    for _ in range(3):
        url = DBIP_URL.format(year=year, month=month)
        try:
            _status, body, content_type = request(url, timeout=120)
            if _looks_like_html(body, content_type):
                raise FeedError("DB-IP response was HTML")
            try:
                text = gzip.decompress(body).decode("utf-8", errors="replace")
            except gzip.BadGzipFile:
                text = body.decode("utf-8", errors="replace")
            triples = []
            for line in text.splitlines():
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                triples.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
            if len(triples) < 1000:
                raise FeedError("DB-IP file looked truncated")
            label = f"{year:04d}-{month:02d}"
            log(f"DB-IP Country Lite {label}: {len(triples)} ranges")
            return build_geo_index(triples), label
        except (FeedError, ValueError, OSError) as exc:
            last_error = str(exc)
            log(f"DB-IP {year:04d}-{month:02d} unavailable ({exc})")
            month -= 1
            if month == 0:
                month = 12
                year -= 1
    raise FeedError(last_error)


def _abuse_section(source_id: str, name: str, url: str) -> dict:
    return _section(
        source_id,
        name,
        url,
        "abuse.ch community API. A free Auth-Key is required. Counts only; raw indicators are not republished. https://auth.abuse.ch/",
    )


def _skip_abuse(section: dict, reason: str) -> dict:
    section["skipped"] = True
    section["ok"] = False
    section["reason"] = reason
    section["error"] = None
    return section


def fetch_threatfox(geo_index: dict | None, geo_label: str | None, geo_error: str | None) -> dict:
    section = _abuse_section(
        "threatfox",
        "abuse.ch ThreatFox recent indicators",
        THREATFOX_EXPORT + "/<Auth-Key>/recent.csv",
    )
    key = _secret()
    if not key:
        log("ThreatFox skipped: ABUSECH_AUTH_KEY is not set")
        return _skip_abuse(section, "ABUSECH_AUTH_KEY is not set")
    try:
        text = load_text_feed(f"{THREATFOX_EXPORT}/{key}/recent.csv", timeout=180)
        rows = _csv_dicts(text)
        malware = []
        threats = []
        ips = []
        for row in rows:
            malware.append(_column(row, "malware_printable", "malware"))
            threats.append(_column(row, "threat_type", "threat"))
            ip = extract_ip(_column(row, "ioc_type"), _column(row, "ioc_value", "ioc"))
            if ip:
                ips.append(ip)
        countries = None
        located = 0
        if geo_index is not None:
            codes = []
            for ip in ips:
                code = lookup_ip(ip, geo_index)
                if code:
                    located += 1
                    codes.append(code)
            countries = count_countries(codes)
        data = {
            "rows": len(rows),
            "columns": sorted({key for row in rows[:1] for key in row}),
            "malware": aggregate_named_counts(malware, 15),
            "threat_types": aggregate_named_counts(threats, 10),
            "ip_iocs": len(ips),
            "ip_geolocated": located,
            "by_country": countries,
            "geo_database": (
                f"IP Geolocation by DB-IP (https://db-ip.com/), Country Lite {geo_label}, CC BY 4.0"
                if geo_label
                else None
            ),
            "geo_error": geo_error,
        }
        section["data"] = data
        section["ok"] = True
        log(f"ThreatFox: {len(rows)} indicators, {len(ips)} IPv4 IOCs, {located} geolocated")
    except (FeedError, ValueError, csv.Error) as exc:
        section["error"] = str(exc)
        log(f"ThreatFox failed: {exc}")
    return section


def fetch_urlhaus(geo_index: dict | None, geo_label: str | None, geo_error: str | None) -> dict:
    section = _abuse_section(
        "urlhaus",
        "abuse.ch URLhaus recent malware URLs",
        URLHAUS_EXPORT + "/<Auth-Key>/recent.csv",
    )
    key = _secret()
    if not key:
        log("URLhaus skipped: ABUSECH_AUTH_KEY is not set")
        return _skip_abuse(section, "ABUSECH_AUTH_KEY is not set")
    try:
        text = load_text_feed(f"{URLHAUS_EXPORT}/{key}/recent.csv", timeout=180)
        rows = _csv_dicts(text)
        threats = []
        tags = []
        ips = []
        for row in rows:
            threats.append(_column(row, "threat", "threat_type"))
            tag_field = _column(row, "tags", "tag")
            for tag in tag_field.replace(";", ",").split(","):
                tag = tag.strip()
                if tag:
                    tags.append(tag)
            ip = host_ip_from_url(_column(row, "url"))
            if ip:
                ips.append(ip)
        countries = None
        located = 0
        if geo_index is not None:
            codes = []
            for ip in ips:
                code = lookup_ip(ip, geo_index)
                if code:
                    located += 1
                    codes.append(code)
            countries = count_countries(codes)
        data = {
            "rows": len(rows),
            "columns": sorted({key for row in rows[:1] for key in row}),
            "threats": aggregate_named_counts(threats, 10),
            "tags": aggregate_named_counts(tags, 12),
            "ip_urls": len(ips),
            "ip_geolocated": located,
            "by_country": countries,
            "geo_database": (
                f"IP Geolocation by DB-IP (https://db-ip.com/), Country Lite {geo_label}, CC BY 4.0"
                if geo_label
                else None
            ),
            "geo_error": geo_error,
            "geo_note": "Only URLs whose host is already an IPv4 address are geolocated. Domain names are not resolved.",
        }
        section["data"] = data
        section["ok"] = True
        log(f"URLhaus: {len(rows)} URLs, {len(ips)} with an IPv4 host, {located} geolocated")
    except (FeedError, ValueError, csv.Error) as exc:
        section["error"] = str(exc)
        log(f"URLhaus failed: {exc}")
    return section


def load_iso() -> list[dict]:
    return json.loads(ISO_PATH.read_text(encoding="utf-8"))


def load_previous() -> dict | None:
    if not SNAPSHOT_PATH.exists():
        return None
    try:
        return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log("Existing snapshot.json is not valid JSON and will not be reused")
        return None


def _usable(section: dict | None) -> dict | None:
    if section and section.get("ok") and section.get("data") is not None:
        return section["data"]
    return None


def _infra_from_abuse(threatfox: dict | None, urlhaus: dict | None) -> dict | None:
    """Combine geolocated abuse.ch IP counts. Domains are not included."""
    bags = []
    for section in (threatfox, urlhaus):
        data = _usable(section)
        if data and data.get("by_country"):
            bags.append(data["by_country"])
    if not bags:
        if any(_usable(section) and section["data"].get("geo_error") for section in (threatfox, urlhaus) if section):
            return None
        return None
    counter: dict[str, int] = {}
    for rows in bags:
        for row in rows:
            code = row["iso2"]
            counter[code] = counter.get(code, 0) + row["count"]
    return {
        "by_country": [
            {"iso2": code, "count": count}
            for code, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        ]
    }


def _blank(value):
    return "" if value is None else value


def write_csvs(snapshot: dict) -> None:
    countries = snapshot["countries"]
    country_path = DATA_DIR / "countries.csv"
    with country_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "iso2",
                "iso3",
                "numeric",
                "name",
                "label",
                "region",
                "subregion",
                "dshield_sources",
                "dshield_reports",
                "dshield_targets",
                "ransomware_victims",
                "feodo_c2",
                "feodo_c2_online",
                "abusech_ips",
            ]
        )
        for row in countries:
            writer.writerow(
                [
                    row["iso2"],
                    row["iso3"],
                    row["numeric"],
                    row["name"],
                    row["label"],
                    row["region"],
                    row["subregion"],
                    _blank(row["dshield_sources"]),
                    _blank(row["dshield_reports"]),
                    _blank(row["dshield_targets"]),
                    _blank(row["ransomware_victims"]),
                    _blank(row["feodo_c2"]),
                    _blank(row["feodo_c2_online"]),
                    _blank(row["abusech_ips"]),
                ]
            )

    kev = _usable(snapshot["sources"]["kev"])
    month_path = DATA_DIR / "kev_by_month.csv"
    with month_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["month", "added"])
        if kev:
            for row in kev["by_month"]:
                writer.writerow([row["month"], row["count"]])

    vendor_path = DATA_DIR / "kev_top_vendors.csv"
    with vendor_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["vendor", "kev_entries", "known_ransomware_use"])
        if kev:
            for row in kev["top_vendors"]:
                writer.writerow([row["name"], row["count"], row["ransomware_known"]])


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False
    )
    try:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
        handle.close()
        os.chmod(handle.name, 0o644)
        Path(handle.name).replace(path)
    except Exception:
        handle.close()
        Path(handle.name).unlink(missing_ok=True)
        raise


def build_snapshot(previous: dict | None) -> tuple[dict, bool]:
    iso_rows = load_iso()
    africa = {row["alpha-2"] for row in iso_rows if row.get("region") == "Africa"}
    fresh = {
        "kev": fetch_kev(),
        "dshield": fetch_dshield(),
        "feodo": fetch_feodo(),
        "ransomware": fetch_ransomware(africa),
    }
    geo_index = None
    geo_label = None
    geo_error = None
    if _secret():
        try:
            geo_index, geo_label = _download_dbip()
        except FeedError as exc:
            geo_error = str(exc)
            log(f"Geolocation unavailable: {exc}")
    fresh["threatfox"] = fetch_threatfox(geo_index, geo_label, geo_error)
    fresh["urlhaus"] = fetch_urlhaus(geo_index, geo_label, geo_error)

    previous_sources = (previous or {}).get("sources") or {}
    sources = {}
    any_fresh_core = False
    for key, section in fresh.items():
        sources[key] = merge_section(section, previous_sources.get(key))
        if key in CORE_SOURCES and section.get("ok"):
            any_fresh_core = True

    countries = build_countries(
        iso_rows,
        _usable(sources.get("dshield")),
        _usable(sources.get("ransomware")),
        _usable(sources.get("feodo")),
        _infra_from_abuse(sources.get("threatfox"), sources.get("urlhaus")),
    )
    snapshot = {
        "schema": 1,
        "project": "Zambia Cyber Threat Map",
        "generated_at": _now(),
        "sources": sources,
        "countries": countries,
    }
    return snapshot, any_fresh_core


def main() -> int:
    try:
        previous = load_previous()
        snapshot, any_fresh_core = build_snapshot(previous)
        if not any_fresh_core:
            if previous:
                log("Every core feed failed. Kept the existing snapshot and did not overwrite it.")
                return 0
            log("Every core feed failed and there is no snapshot to keep.")
            return 1
        validate_snapshot(snapshot)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        atomic_json(SNAPSHOT_PATH, snapshot)
        write_csvs(snapshot)
        log(f"Wrote {SNAPSHOT_PATH.relative_to(ROOT)} and CSV extracts")
        return 0
    except Exception as exc:
        secret = _secret()
        trace = traceback.format_exc()
        if secret:
            trace = trace.replace(secret, "[redacted]")
        log(f"Pipeline stopped: {exc}")
        log(trace)
        return 1


if __name__ == "__main__":
    sys.exit(main())
