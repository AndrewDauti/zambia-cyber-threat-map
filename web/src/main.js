import "@fontsource/bricolage-grotesque/latin-600.css";
import "@fontsource/bricolage-grotesque/latin-700.css";
import "@fontsource/bricolage-grotesque/latin-800.css";
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "./style.css";

import { renderBars, renderDonut, renderLegend, renderTimeline } from "./charts.js";
import { formatDay, formatInt, formatShare, formatStamp, formatStoredPct, higherThan, text } from "./format.js";
import { buildInsights } from "./insights.js";
import { drawMap, metricAvailable } from "./map.js";

const METRICS = {
  dshield_sources: {
    note: "Unique source IP addresses in the SANS ISC DShield country summary. This is where hostile packets were seen, not a map of command-and-control servers, and the API does not label the time window.",
  },
  ransomware_victims: {
    note: "Disclosed ransomware victim records in the ransomware.live dataset, by country tag. A leak-site claim is not a confirmed census, and records with no country are excluded from the map.",
  },
  feodo_c2: {
    note: "Botnet command-and-control addresses on the public Feodo Tracker blocklist, using the country field abuse.ch publishes. The list is short and includes offline addresses.",
  },
  abusech_ips: {
    note: "IP indicators from ThreatFox and URLhaus, geolocated with DB-IP Country Lite. Domain names were not resolved, so most malware URLs are not on this layer.",
  },
};

const state = {
  snapshot: null,
  metric: "dshield_sources",
  view: "world",
  selected: "ZM",
  vendorMode: "vendors",
  query: "",
};

const $ = (id) => document.getElementById(id);

async function load() {
  const response = await fetch(`${import.meta.env.BASE_URL}data/snapshot.json`);
  if (!response.ok) throw new Error(`Snapshot request failed (${response.status})`);
  state.snapshot = await response.json();
  $("loading").hidden = true;
  render();
  bind();
  window.addEventListener("resize", debounce(redrawGraphics, 150));
}

function debounce(fn, wait) {
  let timer = 0;
  return () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(fn, wait);
  };
}

function render() {
  const snapshot = state.snapshot;
  $("built-at").textContent = formatStamp(snapshot.generated_at);
  $("built-at").dateTime = snapshot.generated_at;
  renderBanner();
  renderKpis();
  renderMap();
  renderSelected();
  renderCountryList();
  renderKev();
  renderRansomware();
  renderFeodo();
  renderInsights();
  renderRecent();
  renderMethod();
  renderSources();
}

function bind() {
  document.querySelectorAll("[data-metric]").forEach((button) => {
    button.onclick = () => {
      state.metric = button.dataset.metric;
      syncPressed("[data-metric]", state.metric, "metric");
      renderMap();
      renderCountryList();
    };
  });
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.onclick = () => {
      state.view = button.dataset.view;
      syncPressed("[data-view]", state.view, "view");
      renderMap();
    };
  });
  $("show-vendors").onclick = () => setVendorMode("vendors");
  $("show-products").onclick = () => setVendorMode("products");
  $("country-search").oninput = (event) => {
    state.query = event.target.value.trim().toLowerCase();
    renderCountryList();
  };
  $("map-canvas").addEventListener("country", (event) => selectCountry(event.detail));
}

function syncPressed(selector, value, attr) {
  document.querySelectorAll(selector).forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset[attr] === value));
  });
}

function setVendorMode(mode) {
  state.vendorMode = mode;
  $("show-vendors").setAttribute("aria-pressed", String(mode === "vendors"));
  $("show-products").setAttribute("aria-pressed", String(mode === "products"));
  $("vendor-heading").textContent = mode === "vendors" ? "Top exploited vendors" : "Top exploited products";
  renderVendorChart();
}

function selectCountry(iso2) {
  state.selected = iso2;
  renderSelected();
  renderCountryList();
  renderMap();
}

function renderBanner() {
  const stale = Object.values(state.snapshot.sources).filter((source) => source.stale);
  const banner = $("stale-banner");
  if (!stale.length) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  banner.textContent = `Some feeds failed on the last refresh. ${stale
    .map((source) => source.name)
    .join(", ")} still show the last good copy and are marked stale.`;
}

function renderKpis() {
  const { sources } = state.snapshot;
  const kev = sources.kev.ok ? sources.kev.data : null;
  const dshield = sources.dshield.ok ? sources.dshield.data : null;
  const ransom = sources.ransomware.ok ? sources.ransomware.data : null;
  const zambia = country("ZM");
  const cards = [
    figure("01", kev && formatInt(kev.total), "Known exploited vulnerabilities", kev ? `CISA KEV · ${kev.catalog_version}` : missing(sources.kev), sources.kev),
    figure(
      "02",
      kev && formatStoredPct(kev.ransomware_pct),
      "Marked known ransomware use",
      kev ? `${formatInt(kev.ransomware_known)} of ${formatInt(kev.total)}` : missing(sources.kev),
      sources.kev
    ),
    figure("03", kev && formatInt(kev.added_last_90_days), "Added in the last 90 days", kev ? `as of ${formatDay(kev.as_of)}` : missing(sources.kev), sources.kev),
    figure(
      "04",
      dshield && zambia ? formatInt(zambia.dshield_sources) : null,
      "Zambia source IPs",
      dshield ? `DShield · ${formatShare(zambia.dshield_sources, dshield.total_sources)} of the summary` : missing(sources.dshield),
      sources.dshield
    ),
    figure(
      "05",
      ransom ? formatInt(ransom.zambia.total) : null,
      "Zambia ransomware records",
      ransom ? "ransomware.live country tag" : missing(sources.ransomware),
      sources.ransomware
    ),
    figure(
      "06",
      ransom ? formatInt(ransom.africa.finance) : null,
      "Africa financial-services victims",
      ransom ? `${formatInt(ransom.africa.total)} African records in total` : missing(sources.ransomware),
      sources.ransomware
    ),
  ];
  const root = $("kpis");
  root.replaceChildren();
  for (const card of cards) root.append(card);
}

function missing(section) {
  return section?.stale ? "Stale copy unavailable" : section?.error || section?.reason || "Unavailable in this snapshot";
}

function figure(index, value, label, note, section) {
  const article = document.createElement("article");
  article.className = "kpi";
  const idx = document.createElement("span");
  idx.className = "index";
  idx.textContent = section?.stale ? `${index} · STALE` : index;
  const strong = document.createElement("strong");
  strong.textContent = value || "—";
  const name = document.createElement("span");
  name.className = "label";
  name.textContent = label;
  const small = document.createElement("small");
  small.textContent = note;
  article.append(idx, strong, name, small);
  return article;
}

function country(iso2) {
  return state.snapshot.countries.find((row) => row.iso2 === iso2);
}

function renderMap() {
  const abuseButton = document.querySelector('[data-metric="abusech_ips"]');
  const available = metricAvailable(state.snapshot.countries, "abusech_ips");
  abuseButton.hidden = !available;
  if (!available && state.metric === "abusech_ips") state.metric = "dshield_sources";
  const peak = drawMap($("map-canvas"), $("map-tip"), {
    countries: state.snapshot.countries,
    metric: state.metric,
    view: state.view,
    selected: state.selected,
  });
  $("legend-min").textContent = "0";
  $("legend-max").textContent = formatInt(peak);
  $("map-note").textContent = METRICS[state.metric].note;
}

function renderSelected() {
  const row = country(state.selected) || country("ZM");
  const panel = $("selected-panel");
  panel.classList.add("selected-panel");
  panel.replaceChildren();
  const kicker = document.createElement("p");
  kicker.className = "kicker selected-kicker";
  kicker.textContent = row.region || "Feed code";
  const title = document.createElement("h3");
  title.textContent = row.label;
  const official = document.createElement("p");
  official.className = "official";
  official.textContent = row.name === row.label ? row.iso2 : `${row.name} · ${row.iso2}`;
  const list = document.createElement("dl");
  list.className = "metrics";
  addMetric(list, "DShield source IPs", row.dshield_sources);
  addMetric(list, "DShield reports", row.dshield_reports);
  addMetric(list, "DShield targets", row.dshield_targets);
  addMetric(list, "Ransomware victims", row.ransomware_victims);
  addMetric(list, "Feodo C2 addresses", row.feodo_c2);
  if (row.abusech_ips !== null && row.abusech_ips !== undefined) addMetric(list, "abuse.ch IP indicators", row.abusech_ips);
  panel.append(kicker, title, official, list);

  const dshield = state.snapshot.sources.dshield;
  if (dshield.ok && row.dshield_sources !== null) {
    const share = formatShare(row.dshield_sources, dshield.data.total_sources);
    const higher = higherThan(state.snapshot.countries, "dshield_sources", row.iso2);
    const line = document.createElement("p");
    line.className = "share-line";
    line.textContent = `${share} of DShield source IPs. ${formatInt(higher)} countries have more.`;
    panel.append(line);
  }
  if (row.iso2 !== "ZM") {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "text-button";
    button.textContent = "Back to Zambia";
    button.onclick = () => selectCountry("ZM");
    panel.append(button);
  }
}

function addMetric(list, label, value) {
  const wrap = document.createElement("div");
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value === null || value === undefined ? "—" : formatInt(value);
  wrap.append(dt, dd);
  list.append(wrap);
}

function renderCountryList() {
  const root = $("country-list");
  root.replaceChildren();
  const metric = state.metric;
  const rows = state.snapshot.countries
    .filter((row) => typeof row[metric] === "number")
    .sort((a, b) => b[metric] - a[metric] || a.label.localeCompare(b.label));
  let shown;
  if (state.query) {
    shown = rows
      .filter((row) =>
        [row.label, row.name, row.iso2].some((value) => String(value).toLowerCase().includes(state.query))
      )
      .slice(0, 12);
  } else {
    shown = rows.slice(0, 8);
    const zambia = rows.find((row) => row.iso2 === "ZM");
    if (zambia && !shown.some((row) => row.iso2 === "ZM")) {
      const pin = document.createElement("p");
      pin.className = "pinned";
      pin.textContent = "Zambia";
      root.append(...shown.map((row, index) => countryButton(row, index + 1)), pin, countryButton(zambia, rows.indexOf(zambia) + 1));
      return;
    }
  }
  if (!shown.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No country matches that search.";
    root.append(empty);
    return;
  }
  shown.forEach((row, index) => {
    const rank = state.query ? rows.indexOf(row) + 1 : index + 1;
    root.append(countryButton(row, rank));
  });
}

function countryButton(row, rank) {
  const button = document.createElement("button");
  button.type = "button";
  if (row.iso2 === state.selected) button.setAttribute("aria-current", "true");
  const rankEl = document.createElement("span");
  rankEl.className = "rank";
  rankEl.textContent = String(rank).padStart(2, "0");
  const name = document.createElement("span");
  name.textContent = row.label;
  const count = document.createElement("span");
  count.className = "count";
  count.textContent = formatInt(row[state.metric]);
  button.append(rankEl, name, count);
  button.onclick = () => selectCountry(row.iso2);
  return button;
}

function renderKev() {
  const kev = state.snapshot.sources.kev;
  if (!kev.ok) {
    for (const id of ["vendor-chart", "timeline", "edge-chart"]) {
      const node = $(id);
      node.replaceChildren();
      const note = document.createElement("p");
      note.className = "empty";
      note.textContent = kev.error || "CISA KEV was not available.";
      node.append(note);
    }
    return;
  }
  renderVendorChart();
  renderTimeline($("timeline"), kev.data.by_month);
  renderDonut($("donut"), $("donut-center"), kev.data.ransomware_by_flag, formatStoredPct(kev.data.ransomware_pct));
  renderLegend($("donut-legend"), kev.data.ransomware_by_flag);
  renderBars($("edge-chart"), kev.data.edge.ransomware_by_vendor, {
    label: (row) => row.name,
    value: (row) => row.ransomware_known,
    caption: "Edge and remote-access vendors by KEV entries marked Known for ransomware use",
  });
  const quiet = kev.data.edge.by_vendor.filter((row) => row.count > 0 && row.ransomware_known === 0);
  $("edge-note").textContent = quiet.length
    ? `${quiet.map((row) => `${row.name} (${formatInt(row.count)} entries)`).join(", ")} have catalog entries but no Known ransomware flag.`
    : "Every vendor in the edge list has at least one Known ransomware flag in this snapshot.";
}

function renderVendorChart() {
  const data = state.snapshot.sources.kev.data;
  if (!data) return;
  if (state.vendorMode === "products") {
    renderBars($("vendor-chart"), data.top_products, {
      label: (row) => `${row.vendor} · ${row.product}`,
      value: (row) => row.count,
      caption: "Top exploited products in the CISA KEV catalog",
    });
    return;
  }
  renderBars($("vendor-chart"), data.top_vendors, {
    label: (row) => row.name,
    value: (row) => row.count,
    caption: "Top exploited vendors in the CISA KEV catalog",
  });
}

function renderRansomware() {
  const section = state.snapshot.sources.ransomware;
  if (!section.ok) {
    for (const id of ["groups-chart", "years-chart", "africa-chart"]) {
      $(id).replaceChildren();
      const note = document.createElement("p");
      note.className = "empty";
      note.textContent = section.error || "ransomware.live was not available.";
      $(id).append(note);
    }
    return;
  }
  const data = section.data;
  renderBars($("groups-chart"), data.top_groups, {
    label: (row) => row.name,
    value: (row) => row.count,
    caption: "Ransomware groups by disclosed victim records",
  });
  renderBars(
    $("years-chart"),
    data.by_year.filter((row) => row.year !== "Unknown"),
    {
      label: (row) => row.year,
      value: (row) => row.count,
      caption: "Disclosed ransomware victims by discovery year",
    }
  );
  const africa = [...data.africa.by_country];
  const top = africa.slice(0, 8);
  if (!top.some((row) => row.iso2 === "ZM")) {
    const zambia = africa.find((row) => row.iso2 === "ZM");
    if (zambia) top.push(zambia);
  }
  const labels = new Map(state.snapshot.countries.map((row) => [row.iso2, row.label]));
  renderBars($("africa-chart"), top, {
    label: (row) => labels.get(row.iso2) || row.iso2,
    value: (row) => row.count,
    caption: "Disclosed ransomware victims in African countries",
  });
  $("africa-kicker").textContent = `${formatInt(data.africa.total)} African records. Financial Services is the largest sector tag at ${formatInt(data.africa.finance)}. ${formatInt(data.unknown_country)} records worldwide have no country tag.`;
}

function renderFeodo() {
  const feodo = state.snapshot.sources.feodo;
  if (!feodo.ok) {
    $("feodo-note").textContent = feodo.error || "Feodo Tracker was not available.";
    $("feodo-chart").replaceChildren();
  } else {
    const data = feodo.data;
    $("feodo-note").textContent = `${formatInt(data.total)} addresses, ${formatInt(data.online)} online and ${formatInt(data.offline)} offline. Feed last updated ${data.feed_updated || "at an unpublished time"}. Newest last_online in the file: ${formatDay(data.newest_last_online)}. Zambia: ${formatInt(data.zambia)}.`;
    renderBars($("feodo-chart"), data.by_malware, {
      label: (row) => row.name,
      value: (row) => row.count,
      caption: "Malware families on the Feodo Tracker blocklist",
    });
  }
  const threatfox = state.snapshot.sources.threatfox;
  const urlhaus = state.snapshot.sources.urlhaus;
  const note = $("abuse-note");
  if (threatfox.ok || urlhaus.ok) {
    const bits = [];
    if (threatfox.ok) bits.push(`ThreatFox: ${formatInt(threatfox.data.rows)} indicators.`);
    if (urlhaus.ok) bits.push(`URLhaus: ${formatInt(urlhaus.data.rows)} URLs.`);
    const geoError = threatfox.data?.geo_error || urlhaus.data?.geo_error;
    note.textContent = `${bits.join(" ")}${geoError ? ` Geolocation note: ${geoError}` : ""}`;
    if (threatfox.ok && threatfox.data.malware.rows.length) {
      const extra = document.createElement("div");
      note.append(extra);
      renderBars(extra, threatfox.data.malware.rows.slice(0, 8), {
        label: (row) => row.name,
        value: (row) => row.count,
        caption: "ThreatFox malware families in the recent export",
      });
    }
  } else {
    note.textContent =
      "URLhaus and ThreatFox are not in this snapshot. abuse.ch requires a free Auth-Key before those downloads will run. Add it as the GitHub Actions secret ABUSECH_AUTH_KEY and the next refresh will add malware-family counts and geolocated IP indicators. Until then this block stays empty on purpose.";
  }
}

function renderInsights() {
  const root = $("insights");
  root.replaceChildren();
  buildInsights(state.snapshot).forEach((item, index) => {
    const li = document.createElement("li");
    const num = document.createElement("span");
    num.className = "num";
    num.textContent = String(index + 1).padStart(2, "0");
    const body = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = item.title;
    const paragraph = document.createElement("p");
    text(paragraph, item.parts);
    body.append(title, paragraph);
    li.append(num, body);
    root.append(li);
  });
}

function renderRecent() {
  const body = $("recent-body");
  body.replaceChildren();
  const recent = state.snapshot.sources.kev.ok ? state.snapshot.sources.kev.data.recent : [];
  if (!recent.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.textContent = "No recent catalog entries in this snapshot.";
    row.append(cell);
    body.append(row);
    return;
  }
  for (const item of recent) {
    const row = document.createElement("tr");
    row.append(cell(formatDay(item.date_added), true));
    row.append(cveCell(item.cve));
    row.append(cell(item.vendor));
    row.append(cell(item.product));
    const flag = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `flag ${item.ransomware === "Known" ? "known" : "other"}`;
    badge.textContent = item.ransomware;
    flag.append(badge);
    row.append(flag);
    const name = cell(item.name);
    if (item.description) name.title = item.description;
    row.append(name);
    body.append(row);
  }
}

function cell(value, mono = false) {
  const td = document.createElement("td");
  if (mono) td.className = "mono";
  td.textContent = value || "—";
  return td;
}

function cveCell(cve) {
  const td = document.createElement("td");
  td.className = "mono";
  if (/^CVE-\d{4}-\d+$/.test(cve)) {
    const link = document.createElement("a");
    link.href = `https://nvd.nist.gov/vuln/detail/${cve}`;
    link.textContent = cve;
    link.rel = "noreferrer";
    link.target = "_blank";
    td.append(link);
  } else {
    td.textContent = cve || "—";
  }
  return td;
}

function renderMethod() {
  const kev = state.snapshot.sources.kev.ok ? state.snapshot.sources.kev.data : null;
  const root = $("method-body");
  root.replaceChildren();
  const paragraphs = [
    "The pipeline downloads each feed, checks that the payload has the expected shape, and writes counts. Raw ransomware victim records and IP addresses are not stored in this repository.",
    "A country absent from a feed that succeeded is a zero. A feed that failed is left blank, or the previous good copy is kept and marked stale. Zeros are not used to fill a gap.",
    "Months with no new KEV entries are still listed, with a count of zero. The line between months is visual only.",
    "DShield fields are the source, report, and target counts published by SANS ISC. Their country endpoint does not name its time window, so this page does not invent one. Source country is not attacker nationality.",
    "ransomware.live records are counted once each, as published. This project does not merge possible duplicates. Sector and group tags are the file’s own labels. Victim organization names are not shown.",
    "Map color uses a square-root scale. Bar length is linear against the largest bar in that chart. Both print the raw count.",
  ];
  for (const copy of paragraphs) {
    const p = document.createElement("p");
    p.textContent = copy;
    root.append(p);
  }
  if (!kev) return;
  const edge = document.createElement("p");
  edge.textContent = `Edge and remote-access vendors, matched exactly on vendorProject: ${kev.edge.vendors.join(", ")}.`;
  const banking = document.createElement("p");
  banking.textContent = `Broader banking lens, also an exact vendorProject match, used for context in the data files: ${kev.banking.vendors.join(", ")}. Microsoft dominates that total, so the page treats the edge list as the tighter claim.`;
  const exchange = document.createElement("p");
  exchange.textContent = `Exchange count: ${kev.microsoft.exchange_rule} Result in this snapshot: ${formatInt(kev.microsoft.exchange)}.`;
  root.append(edge, banking, exchange);
}

function renderSources() {
  const root = $("sources");
  root.replaceChildren();
  for (const source of Object.values(state.snapshot.sources)) {
    const article = document.createElement("article");
    article.className = "source";
    const title = document.createElement("strong");
    title.textContent = source.name;
    const badge = document.createElement("span");
    if (source.stale) {
      badge.className = "badge";
      badge.textContent = "Stale";
    } else if (source.skipped) {
      badge.className = "badge quiet";
      badge.textContent = "Not configured";
    } else if (!source.ok) {
      badge.className = "badge quiet";
      badge.textContent = "Unavailable";
    } else {
      badge.className = "badge quiet";
      badge.textContent = "Included";
    }
    title.append(badge);
    const meta = document.createElement("p");
    const link = document.createElement("a");
    link.href = source.url.includes("<") ? "https://auth.abuse.ch/" : source.url;
    link.textContent = source.url.includes("<") ? "abuse.ch Auth-Key required" : "Source";
    link.rel = "noreferrer";
    link.target = "_blank";
    meta.append(link, document.createTextNode(` · Retrieved ${formatStamp(source.retrieved_at)}`));
    const license = document.createElement("p");
    license.textContent = source.license;
    if (source.stale_reason || source.error || source.reason) {
      const extra = document.createElement("p");
      extra.textContent = source.stale_reason || source.error || source.reason;
      article.append(title, meta, license, extra);
    } else {
      article.append(title, meta, license);
    }
    root.append(article);
  }
}

function redrawGraphics() {
  if (!state.snapshot) return;
  renderMap();
  if (state.snapshot.sources.kev.ok) renderTimeline($("timeline"), state.snapshot.sources.kev.data.by_month);
}

load().catch((error) => {
  const loading = $("loading");
  loading.hidden = false;
  loading.textContent = `The snapshot could not be loaded. ${error.message}`;
});
