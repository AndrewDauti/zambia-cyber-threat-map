# Tableau Public workbook

This folder is a Tableau copy of the main views on the Zambia Cyber Threat Map. The numbers come from `data/snapshot.json` (built 21 October 2026, 19:41 UTC). The CISA catalog behind the vulnerability rows is the same release as that snapshot: catalog `2026.10.21`, released `2026-10-21T14:04:39.8983Z`, 1,754 entries.

The workbook is `Zambia_Cyber_Threat_Map.twb`. The CSV files sit in `data/`. The workbook points at those files with a relative `data/` folder, not a path on one computer.

## Open it in Tableau Public

Tableau Public is free. The desktop app runs on Windows and Mac. It does not have a Linux app.

1. Download [Tableau Desktop Public Edition](https://www.tableau.com/products/public/download) and install it.
2. Create a free account at [public.tableau.com](https://public.tableau.com/) if you do not have one. Use the email you want on your profile.
3. Download or clone this repository so the `tableau` folder stays intact. The workbook and the `data` folder need to stay next to each other.
4. Open Tableau Public. Choose **File → Open** and select `tableau/Zambia_Cyber_Threat_Map.twb`.
5. If Tableau says it cannot find a text file, click browse and choose that file inside `tableau/data/`. Pick the file it names. Do not substitute a different CSV. Repeat if it asks for another file.
6. The tab **Zambia Cyber Threat Map** is the dashboard. The other tabs are the separate sheets: five numbers, the Africa map, KEV additions by month, top vendors, and Africa sectors.

## Publish it to your profile

1. With the workbook open, use **Server → Tableau Public → Save to Tableau Public**.
2. Sign in when asked.
3. Name the workbook. Something clear is enough, such as `Zambia Cyber Threat Map`.
4. After it finishes, Tableau opens the page on your public profile. Copy that link. Anyone can open it. Tableau Public does not keep a private copy.

Publishing packages the CSV data into the online workbook. Changing a CSV on your laptop does not change the published page. Open the workbook again and save it to Tableau Public a second time.

## What is on the dashboard

| Sheet | What it shows | CSV |
| --- | --- | --- |
| KPI KEV entries | 1,754 catalog entries | `kpis.csv` |
| KPI Known ransomware percent | 20.6 percent flagged Known | `kpis.csv` |
| KPI Zambia sources | 48 DShield source IPs for Zambia | `kpis.csv` |
| KPI Zambia victims | 7 disclosed ransomware victims tagged Zambia | `kpis.csv` |
| KPI Africa victims | 493 disclosed ransomware victims tagged to Africa | `kpis.csv` |
| Africa map | Those 493 victims by country | `africa_ransomware_by_country.csv` |
| KEV over time | Catalog additions for each month from 2021-11 through 2026-10 | `kev_by_month.csv` |
| Top vendors | The same ten vendors as the website, in that order | `kev_top_vendors.csv` |
| Africa sectors | Sector counts, including a remainder row explained below | `africa_ransomware_by_sector.csv` |

The map uses the ISO country code (`iso2`) with Tableau's country geographic role. Color is the victim count. The website colors the world map with a square-root scale. This workbook uses Tableau's ordinary linear color.

## Data dictionary

Every count below is already in the snapshot, or it is a row from the matching CISA catalog. Nothing here was estimated.

### `kev_entries.csv`

One row per Known Exploited Vulnerability in the matching CISA catalog. 1,754 rows.

| Column | Meaning |
| --- | --- |
| `cve_id` | CVE identifier |
| `vendor` | CISA `vendorProject` |
| `product` | CISA `product` |
| `date_added` | Date CISA added it, `YYYY-MM-DD` |
| `ransomware_flag` | `Known` or `Unknown`, from CISA's ransomware campaign field |

Vulnerability descriptions are left out. They are public, and they are not needed for these views.

### `kev_vendor_counts.csv`

Every vendor in that catalog, with `entries` and `ransomware_known`. 290 vendors. Sorted by entries, then the file is the full list behind the top-ten chart.

### `kev_top_vendors.csv`

The ten vendors drawn on the website, in the same order, with the same counts. Microsoft is 390 entries, 117 of them Known.

### `kev_edge_entries.csv`

The 265 catalog rows whose vendor is on the edge and remote-access list used by the website (Fortinet, Cisco, Palo Alto Networks, Citrix, Ivanti, SonicWall, F5, Juniper, Check Point, Pulse Secure, Barracuda Networks, WatchGuard, Sophos). Same columns as `kev_entries.csv`. 68 of these rows are flagged Known.

### `kev_edge_vendors.csv`

Those 265 rows rolled up by vendor. `entries` is the vendor's full catalog count. `ransomware_known` is the count flagged Known. The website's edge bars use the Known column.

### `kev_by_month.csv`

`month` is `YYYY-MM`. `entries_added` is how many catalog rows carry that month. Months with no additions are present with 0, from 2021-11 through 2026-10. Sixty rows.

### `africa_ransomware_by_country.csv`

Disclosed ransomware.live victims with an African country code. `iso2`, `country` (the short name used on the website), `victim_count`. Forty-one countries. The counts add up to 493. There are no organization names.

### `africa_ransomware_by_sector.csv`

`sector`, `victim_count`, `in_website_chart`.

The snapshot keeps the eight sectors shown on the website. Those rows have `in_website_chart` = `yes` and add up to 380. The other 113 African records sit in sectors the snapshot did not store name by name. They are one row, `Other sectors`, with `in_website_chart` = `no`. 380 + 113 = 493. `Other sectors` is that remainder. It is not a sector name from ransomware.live.

A country-by-sector cross-tab (one row per country and sector together) is not in the snapshot. The live victims file had moved on by the time these extracts were built (33,103 records, against 33,084 in the snapshot), so a new cross-tab would not match the dashboard. It is not included.

### `zambia_ransomware_by_sector.csv`

The seven Zambia records, by sector. Financial Services 2, Government & Defense 2, Healthcare 1, Professional Services 1, Technology 1. No organization names. This is the full Zambia split. It is not one of the dashboard sheets.

### `dshield_zambia.csv`

One row for Zambia from the DShield country summary. Counts only.

| Column | Value in this snapshot | Meaning |
| --- | --- | --- |
| `sources` | 48 | Unique source IP addresses attributed to Zambia. The addresses themselves are not in this file. |
| `reports` | 22,944 | Report count for those sources |
| `targets` | 964 | Target count |
| `summary_sources` | 308,620 | All sources in the country summary, used as the denominator for Zambia's share |
| `summary_reports` | 647,383,782 | All reports in the country summary |
| `summary_targets` | 11,526,752 | All targets in the country summary |
| `ransomware_victims` | 7 | Zambia figure from the ransomware aggregate, repeated here for a single-country sheet |
| `feodo_c2` | 0 | Feodo Tracker rows tagged Zambia |

Zambia's share of source IPs is 48 / 308,620, which the website prints as 0.016%. The DShield API does not label the time window, so this file does not invent one. Persistence is omitted because the feed does not define the unit.

### `kpis.csv`

One row. The five figures on the dashboard tiles.

## Rebuild the CSV files

From the repository root, with the network available so the script can re-check the CISA catalog:

```bash
python3 tableau/export_extracts.py
```

The script stops if the catalog version, release time, vendor counts, month counts, or edge counts differ from `data/snapshot.json`. It will not write a newer catalog over this snapshot's figures. It reads the ransomware and DShield numbers only from the snapshot.

## Licenses

The workbook XML and `export_extracts.py` are part of the MIT code. The CSV files are not.

- CISA KEV rows are a United States government work, public domain.
- DShield counts are CC BY-NC-SA 4.0. Attribute SANS Internet Storm Center. Do not resell them.
- Ransomware counts are aggregates only. Attribute “Source: Ransomware.live”. Non-commercial use. Raw victim records are not in this folder.

## Tableau limits that matter here

- Tableau Public allows 15 million rows in a workbook. These files are far smaller. The largest is the 1,754-row catalog.
- A Tableau Public profile gets 10 GB of storage. This workbook is small.
- Anything saved to Tableau Public is public. Do not put secrets in the workbook later.
- Tableau Public stores an extract. It does not keep a live connection to these CSVs, and it will not refresh them on a schedule. Google Sheets is the exception Tableau documents, and this project does not use Google Sheets.
- Tableau Desktop Public Edition is not for commercial use, and it cannot publish to Tableau Cloud or Tableau Server. It can save a local copy or publish to your Tableau Public profile.
- There is no Linux desktop app. Use Windows or Mac, or upload a CSV in the browser at public.tableau.com. A browser upload accepts a text file up to 1 GB, one file at a time, so the packaged workbook from the desktop app is the straightforward way to publish the whole dashboard.
- The `.twb` file is XML plus links. It is not a `.twbx` package. Moving the workbook without the `data` folder breaks the links until you point Tableau at the CSVs.
- If you open the file and Tableau upgrades it, save the upgraded copy yourself. This repository copy stays in the form generated here.
- The Africa map depends on Tableau's maps and geocoding, which need a network connection. Most ISO alpha-2 codes match. Small territories in the file, notably Réunion (`RE`) and Mayotte (`YT`), can remain unmatched. Their counts are still in the CSV.
- Bars are sorted in the workbook to follow the snapshot order. If a sheet opens in alphabetical order, sort the dimension by the count field descending.
- The sector sheet includes the `Other sectors` remainder so the bars add up to 493. The website chart shows only the eight named sectors (`in_website_chart` = `yes`).
