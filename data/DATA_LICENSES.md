# Data licenses

The code in this repository is MIT. The files in this folder are not.

`snapshot.json` and the CSV extracts are a compilation. Each part keeps the terms of its source. Do not treat the compilation as MIT, and do not resell it.

| File | What it contains | Terms |
| --- | --- | --- |
| `snapshot.json` | Counts and country totals from the feeds below | Compilation. The strictest terms apply if you reuse the whole file. |
| `countries.csv` | One row per country with those totals | Same compilation. |
| `kev_by_month.csv`, `kev_top_vendors.csv` | Figures derived only from the CISA KEV catalog | US government work. Public domain. |
| `../pipeline/vendor/iso3166.json` | Country names, codes, and regions | CC BY-SA 4.0. Source: [ISO-3166-Countries-with-Regional-Codes](https://github.com/lukes/ISO-3166-Countries-with-Regional-Codes) by Luke. See `pipeline/vendor/iso3166.LICENSE.md`. |
| `../web/src/geo/countries-50m.json` | Map shapes | [world-atlas](https://github.com/topojson/world-atlas) by Michael Bostock, ISC license (`web/src/geo/WORLD-ATLAS-LICENSE`). Geometry is from [Natural Earth](https://www.naturalearthdata.com/), which is public domain. |

## Sources inside the snapshot

- **CISA Known Exploited Vulnerabilities catalog.** US government work, public domain. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **SANS Internet Storm Center / DShield country summary.** [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). Attribute SANS Internet Storm Center. https://isc.sans.edu/api/
- **abuse.ch Feodo Tracker.** Counts only. IP addresses are not included. Terms: https://feodotracker.abuse.ch/blocklist/
- **Ransomware.live open victim dataset.** Non-commercial academic use with attribution. Say “Source: Ransomware.live” and link to https://www.ransomware.live/. Raw victim records are not included. Terms: https://www.ransomware.live/t&c
- **abuse.ch ThreatFox and URLhaus,** only after an Auth-Key is configured. Counts only. https://auth.abuse.ch/
- **DB-IP Country Lite,** only used to place those IP indicators. “IP Geolocation by DB-IP” (https://db-ip.com/), CC BY 4.0. The database itself is not stored here.

The page footer repeats the attribution next to the charts.
