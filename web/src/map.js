import { max } from "d3-array";
import { geoEqualEarth, geoMercator, geoPath } from "d3-geo";
import { scaleSqrt } from "d3-scale";
import { select } from "d3-selection";
import { feature } from "topojson-client";
import atlas from "./geo/countries-50m.json";
import { formatInt } from "./format.js";

const world = feature(atlas, atlas.objects.countries);
const REGION = new Set(["ZM", "ZW", "MW", "MZ", "TZ", "CD", "AO", "NA", "BW", "ZA", "BI", "RW", "UG"]);

const METRIC_LABEL = {
  dshield_sources: "DShield source IPs",
  ransomware_victims: "disclosed ransomware victims",
  feodo_c2: "Feodo C2 addresses",
  abusech_ips: "geolocated abuse.ch IP indicators",
};

function recordFor(featureItem, byNumeric) {
  if (featureItem.id === undefined || featureItem.id === null) return null;
  return byNumeric.get(Number(featureItem.id)) || null;
}

export function metricAvailable(countries, key) {
  return countries.some((country) => typeof country[key] === "number");
}

export function drawMap(canvas, tooltip, { countries, metric, view, selected }) {
  const byNumeric = new Map(
    countries.filter((country) => country.numeric !== "").map((country) => [Number(country.numeric), country])
  );
  const decorated = world.features.map((item) => ({
    ...item,
    record: recordFor(item, byNumeric),
  }));
  let shown = decorated;
  if (view === "africa") {
    shown = decorated.filter((item) => item.record?.region === "Africa");
  } else if (view === "region") {
    shown = decorated.filter((item) => item.record && REGION.has(item.record.iso2));
  }

  const width = Math.max(canvas.clientWidth || 640, 320);
  const height = width < 720 ? 420 : 560;
  canvas.replaceChildren();
  const svg = select(canvas)
    .append("svg")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .attr("role", "img")
    .attr(
      "aria-label",
      `Choropleth of ${METRIC_LABEL[metric] || metric}. Zambia is outlined. Exact counts are in the country list.`
    );

  const projection = view === "world" ? geoEqualEarth() : geoMercator();
  const subject = view === "world" ? { type: "Sphere" } : { type: "FeatureCollection", features: shown };
  projection.fitExtent(
    [
      [12, 12],
      [width - 12, height - 12],
    ],
    subject
  );
  const path = geoPath(projection);
  const values = shown.map((item) => item.record?.[metric]).filter((value) => typeof value === "number");
  const peak = max(values) || 1;
  const color = scaleSqrt().domain([0, peak]).range(["#1a2942", "#e7b34a"]);

  if (view === "world") {
    svg
      .append("path")
      .datum({ type: "Sphere" })
      .attr("class", "sphere")
      .attr("d", path);
  }

  svg
    .selectAll("path.country")
    .data(shown)
    .join("path")
    .attr("class", "country")
    .attr("d", path)
    .attr("fill", (item) => {
      const value = item.record?.[metric];
      return typeof value === "number" ? color(value) : "#121a28";
    })
    .attr("stroke", (item) => {
      if (item.record?.iso2 === "ZM") return "#5ee0c3";
      if (item.record?.iso2 === selected) return "#f4f7fb";
      return "rgba(8, 12, 20, 0.9)";
    })
    .attr("stroke-width", (item) => {
      if (item.record?.iso2 === "ZM") return item.record.iso2 === selected ? 2.4 : 1.7;
      if (item.record?.iso2 === selected) return 1.4;
      return 0.45;
    })
    .style("cursor", (item) => (item.record ? "pointer" : "default"))
    .on("mousemove", (event, item) => {
      if (!item.record) {
        tooltip.hidden = true;
        return;
      }
      const value = item.record[metric];
      tooltip.hidden = false;
      tooltip.replaceChildren();
      const title = document.createElement("strong");
      title.textContent = item.record.label;
      const detail = document.createElement("span");
      detail.textContent =
        typeof value === "number"
          ? `${formatInt(value)} ${METRIC_LABEL[metric] || ""}`.trim()
          : "No figure for this metric";
      tooltip.append(title, detail);
      const bounds = canvas.getBoundingClientRect();
      const tipWidth = tooltip.offsetWidth || 160;
      let x = event.clientX - bounds.left + 14;
      let y = event.clientY - bounds.top + 14;
      if (x + tipWidth > bounds.width) x = event.clientX - bounds.left - tipWidth - 10;
      if (y + 64 > bounds.height) y = event.clientY - bounds.top - 64;
      tooltip.style.left = `${Math.max(8, x)}px`;
      tooltip.style.top = `${Math.max(8, y)}px`;
    })
    .on("mouseleave", () => {
      tooltip.hidden = true;
    })
    .on("click", (_event, item) => {
      if (item.record) canvas.dispatchEvent(new CustomEvent("country", { detail: item.record.iso2 }));
    });

  return peak;
}
