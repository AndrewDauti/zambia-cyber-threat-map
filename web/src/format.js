const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function formatInt(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatStoredPct(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${Number.isInteger(value) ? value : value.toFixed(1)}%`;
}

export function formatShare(part, total) {
  if (part === null || part === undefined || !total) return null;
  const pct = (part / total) * 100;
  if (pct >= 10) return `${pct.toFixed(1)}%`;
  if (pct >= 1) return `${pct.toFixed(2)}%`;
  return `${pct.toFixed(3)}%`;
}

export function formatDay(value) {
  if (!value) return "unknown date";
  const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!match) return String(value);
  return `${Number(match[3])} ${MONTHS[Number(match[2]) - 1]} ${match[1]}`;
}

export function formatStamp(value) {
  if (!value) return "unknown time";
  const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/);
  if (!match) return formatDay(value);
  return `${formatDay(value)}, ${match[4]}:${match[5]} UTC`;
}

export function higherThan(rows, key, iso2) {
  const mine = rows.find((row) => row.iso2 === iso2);
  if (!mine || mine[key] === null || mine[key] === undefined) return null;
  return rows.filter((row) => row[key] !== null && row[key] !== undefined && row[key] > mine[key]).length;
}

export function text(parent, parts) {
  parent.replaceChildren();
  for (const part of parts) {
    if (part.em) {
      const strong = document.createElement("strong");
      strong.textContent = part.text;
      parent.append(strong);
    } else {
      parent.append(document.createTextNode(part.text));
    }
  }
}
