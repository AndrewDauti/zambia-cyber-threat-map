import { max } from "d3-array";
import { axisBottom, axisLeft } from "d3-axis";
import { scaleLinear, scalePoint } from "d3-scale";
import { select } from "d3-selection";
import { area, curveMonotoneX, line } from "d3-shape";
import { arc as arcShape, pie as pieShape } from "d3-shape";
import { formatInt } from "./format.js";

function hiddenTable(container, caption, headers, rows) {
  const table = document.createElement("table");
  const cap = document.createElement("caption");
  cap.textContent = caption;
  table.append(cap);
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const header of headers) {
    const cell = document.createElement("th");
    cell.scope = "col";
    cell.textContent = header;
    headRow.append(cell);
  }
  thead.append(headRow);
  const body = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const value of row) {
      const cell = document.createElement("td");
      cell.textContent = value;
      tr.append(cell);
    }
    body.append(tr);
  }
  table.append(thead, body);
  const hidden = document.createElement("div");
  hidden.className = "sr-only";
  hidden.append(table);
  container.append(hidden);
}

export function renderBars(container, rows, { label, value, caption, empty }) {
  container.replaceChildren();
  if (!rows?.length) {
    const note = document.createElement("p");
    note.className = "empty";
    note.textContent = empty || "No rows in this snapshot.";
    container.append(note);
    return;
  }
  const peak = Math.max(...rows.map((row) => value(row)));
  const list = document.createElement("div");
  list.className = "bars";
  for (const row of rows) {
    const amount = value(row);
    const item = document.createElement("div");
    item.className = "bar-row";
    const name = document.createElement("span");
    name.className = "bar-label";
    name.textContent = label(row);
    name.title = label(row);
    const track = document.createElement("span");
    track.className = "bar-track";
    const fill = document.createElement("span");
    fill.className = "bar-fill";
    fill.style.width = `${peak ? (amount / peak) * 100 : 0}%`;
    track.append(fill);
    const figure = document.createElement("span");
    figure.className = "bar-value";
    figure.textContent = formatInt(amount);
    item.append(name, track, figure);
    list.append(item);
  }
  container.append(list);
  hiddenTable(
    container,
    caption,
    ["Name", "Count"],
    rows.map((row) => [label(row), formatInt(value(row))])
  );
}

export function renderTimeline(container, rows) {
  container.replaceChildren();
  const width = Math.max(container.clientWidth || 320, 280);
  const height = width < 640 ? 240 : 280;
  const margin = { top: 16, right: 8, bottom: 36, left: 44 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const svg = select(container)
    .append("svg")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .attr("role", "img")
    .attr("aria-label", "Known exploited vulnerabilities added each month");

  const defs = svg.append("defs");
  const gradient = defs
    .append("linearGradient")
    .attr("id", "kev-area")
    .attr("x1", "0")
    .attr("x2", "0")
    .attr("y1", "0")
    .attr("y2", "1");
  gradient.append("stop").attr("offset", "0%").attr("stop-color", "#5ee0c3").attr("stop-opacity", 0.45);
  gradient.append("stop").attr("offset", "100%").attr("stop-color", "#5ee0c3").attr("stop-opacity", 0.02);

  const root = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);
  const x = scalePoint()
    .domain(rows.map((row) => row.month))
    .range([0, innerWidth])
    .padding(0.2);
  const y = scaleLinear()
    .domain([0, max(rows, (row) => row.count) || 1])
    .nice()
    .range([innerHeight, 0]);

  const areaPath = area()
    .x((row) => x(row.month))
    .y0(innerHeight)
    .y1((row) => y(row.count))
    .curve(curveMonotoneX);
  const linePath = line()
    .x((row) => x(row.month))
    .y((row) => y(row.count))
    .curve(curveMonotoneX);

  root.append("path").datum(rows).attr("class", "area").attr("d", areaPath).attr("fill", "url(#kev-area)");
  root.append("path").datum(rows).attr("class", "line").attr("d", linePath);
  root
    .selectAll("circle")
    .data(rows)
    .join("circle")
    .attr("cx", (row) => x(row.month))
    .attr("cy", (row) => y(row.count))
    .attr("r", width < 640 ? 1.5 : 2.2);

  const yearMonths = rows.map((row) => row.month).filter((month) => month.endsWith("-01"));
  root
    .append("g")
    .attr("class", "axis")
    .attr("transform", `translate(0,${innerHeight})`)
    .call(
      axisBottom(x)
        .tickValues(yearMonths.length ? yearMonths : rows.map((row) => row.month))
        .tickFormat((month) => month.slice(0, 4))
    );
  root.append("g").attr("class", "axis").call(axisLeft(y).ticks(4).tickFormat((value) => formatInt(value)));

  hiddenTable(
    container,
    "Known exploited vulnerabilities added by month. The line only connects these monthly counts.",
    ["Month", "Added"],
    rows.map((row) => [row.month, formatInt(row.count)])
  );
}

const DONUT_COLORS = {
  Known: "#ff6b6b",
  Unknown: "#31445f",
};

export function renderDonut(container, center, rows, pctLabel) {
  container.replaceChildren();
  const size = 220;
  const radius = size / 2;
  const svg = select(container)
    .append("svg")
    .attr("viewBox", `0 0 ${size} ${size}`)
    .attr("role", "img")
    .attr("aria-label", "Share of the catalog marked known for ransomware use");
  const root = svg.append("g").attr("transform", `translate(${radius},${radius})`);
  const arcs = pieShape()
    .value((row) => row.count)
    .sort(null)(rows);
  root
    .selectAll("path")
    .data(arcs)
    .join("path")
    .attr("d", arcShape().innerRadius(radius * 0.64).outerRadius(radius - 2))
    .attr("fill", (item) => DONUT_COLORS[item.data.flag] || "#d7b15a");

  center.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = pctLabel;
  const span = document.createElement("span");
  span.textContent = "Known";
  center.append(strong, span);

  hiddenTable(
    container,
    "Ransomware campaign flag on CISA KEV entries",
    ["Flag", "Entries"],
    rows.map((row) => [row.flag, formatInt(row.count)])
  );
}

export function renderLegend(container, rows) {
  container.replaceChildren();
  for (const row of rows) {
    const item = document.createElement("div");
    item.className = "legend-item";
    const swatch = document.createElement("span");
    swatch.className = "swatch";
    swatch.style.background = DONUT_COLORS[row.flag] || "#d7b15a";
    const label = document.createElement("span");
    label.textContent = row.flag;
    const count = document.createElement("span");
    count.className = "legend-count";
    count.textContent = formatInt(row.count);
    item.append(swatch, label, count);
    container.append(item);
  }
}
