"""Unit tests for snapshot math. These do not touch the network."""

from __future__ import annotations

import unittest
from datetime import date

from pipeline.transform import (
    aggregate_dshield,
    aggregate_feodo,
    aggregate_kev,
    aggregate_ransomware,
    build_countries,
    build_geo_index,
    extract_ip,
    host_ip_from_url,
    lookup_ip,
    merge_section,
    validate_snapshot,
)


def vuln(cve, vendor, product, added, flag="Unknown"):
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": f"{cve} name",
        "dateAdded": added,
        "shortDescription": "A short description.",
        "knownRansomwareCampaignUse": flag,
    }


ISO = [
    {
        "name": "United States of America",
        "alpha-2": "US",
        "alpha-3": "USA",
        "country-code": "840",
        "region": "Americas",
        "sub-region": "Northern America",
    },
    {
        "name": "Zambia",
        "alpha-2": "ZM",
        "alpha-3": "ZMB",
        "country-code": "894",
        "region": "Africa",
        "sub-region": "Sub-Saharan Africa",
    },
    {
        "name": "South Africa",
        "alpha-2": "ZA",
        "alpha-3": "ZAF",
        "country-code": "710",
        "region": "Africa",
        "sub-region": "Sub-Saharan Africa",
    },
]


class KevTests(unittest.TestCase):
    def test_counts_flags_gaps_and_the_banking_lens(self):
        rows = [
            vuln("CVE-2026-0001", "Microsoft", "Exchange Server", "2026-10-01", "Known"),
            vuln("CVE-2026-0002", "Fortinet", "FortiOS", "2026-08-01", "Known"),
            vuln("CVE-2026-0003", "Checkbox", "CheckboxOS", "2026-01-15", "Unknown"),
            vuln("CVE-2025-0004", "Cisco", "IOS", "2025-12-01", "Unknown"),
        ]
        data = aggregate_kev(rows, date(2026, 10, 21))
        self.assertEqual(data["total"], 4)
        self.assertEqual(data["ransomware_known"], 2)
        self.assertEqual(data["ransomware_pct"], 50.0)
        self.assertEqual(data["added_last_30_days"], 1)
        self.assertEqual(data["added_last_90_days"], 2)
        self.assertEqual(data["microsoft"]["exchange"], 1)
        ike = aggregate_kev(
            [vuln("CVE-2026-0099", "Microsoft", "Internet Key Exchange (IKE) Service Extensions", "2026-10-02")],
            date(2026, 10, 21),
        )
        self.assertEqual(ike["microsoft"]["exchange"], 0)
        self.assertEqual(data["edge"]["total"], 2)
        self.assertEqual(data["edge"]["ransomware_known"], 1)
        self.assertEqual(data["banking"]["total"], 3)
        self.assertNotIn("Checkbox", {row["name"] for row in data["banking"]["by_vendor"]})
        months = {row["month"]: row["count"] for row in data["by_month"]}
        self.assertEqual(months["2026-02"], 0)
        self.assertEqual(sum(months.values()), 4)
        self.assertEqual(data["recent"][0]["cve"], "CVE-2026-0001")


class FeedTests(unittest.TestCase):
    def test_dshield_parks_blank_country_outside_the_map(self):
        rows = [{"country": "", "sources": 5, "reports": 9, "targets": 1, "persistance": 3}]
        rows.append({"country": "zm", "sources": "2", "reports": "4", "targets": "1", "persistance": "1.5"})
        for index in range(60):
            code = chr(65 + (index // 26)) + chr(65 + (index % 26))
            if code == "ZM":
                continue
            rows.append({"country": code, "sources": 1, "reports": 1, "targets": 1, "persistance": 1})
        data = aggregate_dshield(rows)
        self.assertEqual(data["unknown_country_sources"], 5)
        zambia = next(row for row in data["countries"] if row["iso2"] == "ZM")
        self.assertEqual(zambia["sources"], 2)
        self.assertEqual(
            data["total_sources"],
            sum(row["sources"] for row in data["countries"]) + 5,
        )

    def test_feodo_counts_status_and_zambia_zero(self):
        data = aggregate_feodo(
            [
                {"country": "US", "malware": "QakBot", "status": "online", "first_seen": "2026-01-01 00:00:00", "last_online": "2026-03-01"},
                {"country": "US", "malware": "QakBot", "status": "offline", "first_seen": "2026-02-01 00:00:00", "last_online": "2026-02-02"},
            ],
            "2026-03-04 14:28:39 UTC",
        )
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["online"], 1)
        self.assertEqual(data["zambia"], 0)
        self.assertEqual(data["by_malware"][0]["name"], "QakBot")
        self.assertEqual(data["feed_updated"], "2026-03-04 14:28:39 UTC")

    def test_ransomware_africa_and_zambia_are_counts_only(self):
        rows = [
            {"country": "ZM", "activity": "Healthcare", "group_name": "krybit", "discovered": "2026-04-29T00:00:00Z"},
            {"country": "ZA", "activity": "Financial Services", "group_name": "qilin", "discovered": "2026-01-02"},
            {"country": "", "activity": "Not Found", "group_name": "x", "discovered": "2025-05-01"},
            {"country": "US", "activity": "Financial Services", "group_name": "qilin", "discovered": "2024-03-01"},
        ]
        data = aggregate_ransomware(rows, {"ZM", "ZA"})
        self.assertEqual(data["total"], 4)
        self.assertEqual(data["unknown_country"], 1)
        self.assertEqual(data["global_finance"], 2)
        self.assertEqual(data["africa"]["total"], 2)
        self.assertEqual(data["africa"]["finance"], 1)
        self.assertEqual(data["zambia"]["total"], 1)
        self.assertEqual(data["zambia"]["by_sector"][0]["sector"], "Healthcare")
        self.assertNotIn("post_title", data["zambia"])
        years = {row["year"]: row["count"] for row in data["by_year"]}
        self.assertEqual(years["2025"], 1)
        self.assertEqual(years["2024"], 1)


class JoinTests(unittest.TestCase):
    def test_missing_feed_is_null_and_absent_country_is_zero(self):
        dshield = {
            "countries": [{"iso2": "US", "sources": 10, "reports": 20, "targets": 3}],
            "unknown_country_sources": 0,
            "total_sources": 10,
        }
        ransomware = {
            "by_country": [{"iso2": "ZM", "count": 1}, {"iso2": "US", "count": 4}],
            "unknown_country": 0,
            "total": 5,
            "zambia": {"total": 1, "by_sector": [{"sector": "Healthcare", "count": 1}]},
            "africa": {"total": 1, "finance": 0},
        }
        feodo = {"by_country": [{"iso2": "US", "count": 2, "online": 1}]}
        countries = build_countries(ISO, dshield, ransomware, feodo, None)
        zambia = next(row for row in countries if row["iso2"] == "ZM")
        self.assertEqual(zambia["label"], "Zambia")
        self.assertEqual(zambia["dshield_sources"], 0)
        self.assertEqual(zambia["ransomware_victims"], 1)
        self.assertEqual(zambia["feodo_c2"], 0)
        self.assertIsNone(zambia["abusech_ips"])
        self.assertEqual(next(row for row in countries if row["iso2"] == "US")["label"], "United States")

        failed = build_countries(ISO, None, None, None, None)
        zambia = next(row for row in failed if row["iso2"] == "ZM")
        self.assertIsNone(zambia["dshield_sources"])
        self.assertIsNone(zambia["ransomware_victims"])

    def test_merge_keeps_previous_data_when_a_feed_fails(self):
        previous = {"ok": True, "data": {"total": 3}, "retrieved_at": "2026-10-01T00:00:00+00:00", "stale": False}
        failed = {"ok": False, "error": "HTTP 503", "retrieved_at": "2026-10-21T00:00:00+00:00", "data": None}
        merged = merge_section(failed, previous)
        self.assertTrue(merged["stale"])
        self.assertEqual(merged["data"]["total"], 3)
        self.assertEqual(merged["stale_reason"], "HTTP 503")

        skipped = {"ok": False, "skipped": True, "reason": "ABUSECH_AUTH_KEY is not set", "retrieved_at": "2026-10-21T00:00:00+00:00"}
        kept = merge_section(skipped, previous)
        self.assertEqual(kept["data"]["total"], 3)
        self.assertIn("ABUSECH_AUTH_KEY", kept["stale_reason"])

        fresh = {"ok": True, "data": {"total": 9}, "retrieved_at": "2026-10-21T00:00:00+00:00"}
        self.assertFalse(merge_section(fresh, previous)["stale"])

    def test_geolocation_and_ip_extraction(self):
        index = build_geo_index([("1.0.0.0", "1.0.0.255", "AU"), ("2001:db8::", "2001:db8::ffff", "ZZ")])
        self.assertEqual(lookup_ip("1.0.0.10", index), "AU")
        self.assertIsNone(lookup_ip("2.0.0.1", index))
        self.assertEqual(extract_ip("ip:port", "1.2.3.4:443"), "1.2.3.4")
        self.assertIsNone(extract_ip("url", "https://example.test/a"))
        self.assertIsNone(extract_ip("ip:port", "2001:db8::1:443"))
        self.assertEqual(host_ip_from_url("http://8.8.8.8/malware.exe"), "8.8.8.8")
        self.assertIsNone(host_ip_from_url("http://example.test/a"))

    def test_validate_rejects_a_bad_sum(self):
        snapshot = {
            "schema": 1,
            "generated_at": "2026-10-21T00:00:00+00:00",
            "countries": [{"iso2": "ZM", "dshield_sources": 0, "ransomware_victims": 0}],
            "sources": {
                "kev": {
                    "ok": True,
                    "data": {
                        "total": 2,
                        "ransomware_known": 2,
                        "ransomware_other": 1,
                        "ransomware_by_flag": [{"flag": "Known", "count": 2}],
                        "by_month": [{"month": "2026-10", "count": 2}],
                        "banking": {"total": 0, "by_vendor": []},
                    },
                },
                "dshield": {"ok": False, "data": None},
                "ransomware": {"ok": False, "data": None},
            },
        }
        with self.assertRaises(ValueError):
            validate_snapshot(snapshot)


if __name__ == "__main__":
    unittest.main()
