import { formatDay, formatInt, formatShare, formatStamp, formatStoredPct, higherThan } from "./format.js";

function usable(section) {
  return Boolean(section && section.ok && section.data);
}

function listCounts(rows, labelKey) {
  return rows.map((row) => `${row[labelKey]} (${formatInt(row.count)})`).join(", ");
}

function countryPhrase(rows, lookup, limit = 3) {
  return rows
    .slice(0, limit)
    .map((row) => `${lookup(row.iso2)} (${formatInt(row.count)})`)
    .join(", ");
}

function stalePrefix(section) {
  if (!section?.stale) return [];
  return [
    {
      text: `Kept from ${formatStamp(section.retrieved_at)} because a later download failed (${section.stale_reason || "feed unavailable"}). `,
    },
  ];
}

export function buildInsights(snapshot) {
  const kev = snapshot.sources.kev;
  const dshield = snapshot.sources.dshield;
  const ransomware = snapshot.sources.ransomware;
  const feodo = snapshot.sources.feodo;
  const threatfox = snapshot.sources.threatfox;
  const urlhaus = snapshot.sources.urlhaus;
  const lookup = new Map(snapshot.countries.map((row) => [row.iso2, row]));
  const nameOf = (iso2) => lookup.get(iso2)?.label || iso2;
  const zambia = lookup.get("ZM");
  const notes = [];

  if (usable(kev)) {
    const data = kev.data;
    notes.push({
      title: "Patch from the catalog, not from headlines",
      parts: [
        ...stalePrefix(kev),
        { text: "The CISA Known Exploited Vulnerabilities catalog in this snapshot lists " },
        { em: true, text: formatInt(data.total) },
        { text: " entries (catalog " },
        { em: true, text: String(data.catalog_version || "unlabeled") },
        { text: ", released " },
        { em: true, text: formatStamp(data.date_released) },
        { text: "). " },
        { em: true, text: formatInt(data.ransomware_known) },
        { text: " (" },
        { em: true, text: formatStoredPct(data.ransomware_pct) },
        { text: ") are marked Known for use in ransomware campaigns. " },
        { em: true, text: formatInt(data.added_last_90_days) },
        { text: " were added in the 90 days up to " },
        { em: true, text: formatDay(data.as_of) },
        { text: "." },
      ],
    });

    const leaders = data.edge.ransomware_by_vendor.slice(0, 3);
    const quiet = data.edge.by_vendor.filter((row) => row.count > 0 && row.ransomware_known === 0);
    const edgeParts = [
      ...stalePrefix(kev),
      { text: "A fixed list of edge and remote-access vendors, named in the method note, accounts for " },
      { em: true, text: formatInt(data.edge.total) },
      { text: " catalog entries. " },
      { em: true, text: formatInt(data.edge.ransomware_known) },
      { text: " of those are marked Known for ransomware use. " },
    ];
    if (leaders.length) {
      edgeParts.push({
        text: "The highest Known counts in that set are ",
      });
      edgeParts.push({
        em: true,
        text: leaders.map((row) => `${row.name} (${formatInt(row.ransomware_known)})`).join(", "),
      });
      edgeParts.push({
        text: ". These are firewall, VPN, and gateway vendors: the usual front door when an appliance is still exposed to the internet. ",
      });
    }
    if (quiet.length) {
      edgeParts.push({
        text: `${quiet.map((row) => row.name).join(", ")} ${quiet.length === 1 ? "is" : "are"} on the same list and ${quiet.length === 1 ? "has" : "have"} catalog entries, but none flagged Known for ransomware in this snapshot.`,
      });
    }
    notes.push({ title: "Perimeter equipment is already on the list", parts: edgeParts });

    const top = data.top_vendors.slice(0, 3).map((row) => row.name);
    notes.push({
      title: "Microsoft is the largest share, and Exchange is in it",
      parts: [
        ...stalePrefix(kev),
        { text: "Microsoft accounts for " },
        { em: true, text: formatInt(data.microsoft.total) },
        { text: " entries, " },
        { em: true, text: formatInt(data.microsoft.ransomware_known) },
        { text: " marked Known for ransomware use. " },
        { em: true, text: formatInt(data.microsoft.exchange) },
        { text: " of the Microsoft entries are Exchange mail products under the rule on this page. That is not every Microsoft bug, and it is not a count of Zambian incidents. It is the part of the global catalog that lines up with mail systems still common in institutions here. The largest vendors overall are " },
        { em: true, text: top.join(", ") },
        { text: "." },
      ],
    });
  } else {
    notes.push({
      title: "The vulnerability catalog did not load",
      parts: [{ text: kev?.error || "CISA KEV was unavailable for this snapshot, so the patching takeaways are withheld rather than filled with zeros." }],
    });
  }

  const placeParts = [];
  if (usable(dshield) && zambia) {
    const data = dshield.data;
    const share = formatShare(zambia.dshield_sources, data.total_sources);
    const higher = higherThan(snapshot.countries, "dshield_sources", "ZM");
    placeParts.push(...stalePrefix(dshield));
    placeParts.push({ text: "In the DShield country summary retrieved " });
    placeParts.push({ em: true, text: formatStamp(dshield.retrieved_at) });
    placeParts.push({ text: ", Zambia has " });
    placeParts.push({ em: true, text: formatInt(zambia.dshield_sources) });
    placeParts.push({ text: " source IPs, " });
    placeParts.push({ em: true, text: formatInt(zambia.dshield_reports) });
    placeParts.push({ text: " reports, and " });
    placeParts.push({ em: true, text: formatInt(zambia.dshield_targets) });
    placeParts.push({ text: " targets" });
    if (share) {
      placeParts.push({ text: " (" });
      placeParts.push({ em: true, text: share });
      placeParts.push({ text: " of source IPs in the summary)" });
    }
    placeParts.push({ text: ". " });
    if (higher !== null) {
      placeParts.push({ em: true, text: formatInt(higher) });
      placeParts.push({ text: " countries have more source IPs. Source country is the network the packet came from, not the operator’s nationality. " });
    }
  } else {
    placeParts.push({ text: "The DShield country summary was unavailable, so this note does not invent a Zambia source-IP count. " });
  }

  if (usable(ransomware) && zambia) {
    const data = ransomware.data;
    placeParts.push(...stalePrefix(ransomware));
    placeParts.push({ text: "ransomware.live, retrieved " });
    placeParts.push({ em: true, text: formatStamp(ransomware.retrieved_at) });
    placeParts.push({ text: ", has " });
    placeParts.push({ em: true, text: formatInt(data.zambia.total) });
    placeParts.push({ text: ` disclosed victim record${data.zambia.total === 1 ? "" : "s"} tagged Zambia. ` });
    if (data.zambia.by_sector.length) {
      placeParts.push({ text: "Sector tags: " });
      placeParts.push({ em: true, text: listCounts(data.zambia.by_sector, "sector") });
      placeParts.push({ text: ". " });
    }
    if (data.zambia.by_group.length) {
      placeParts.push({ text: "Group tags: " });
      placeParts.push({ em: true, text: listCounts(data.zambia.by_group, "name") });
      placeParts.push({ text: ". " });
    }
    placeParts.push({ text: "Across Africa the same file has " });
    placeParts.push({ em: true, text: formatInt(data.africa.total) });
    placeParts.push({ text: " victims, and Financial Services is the largest African sector tag at " });
    placeParts.push({ em: true, text: formatInt(data.africa.finance) });
    placeParts.push({ text: ". The largest African country tags are " });
    placeParts.push({ em: true, text: countryPhrase(data.africa.by_country, nameOf) });
    placeParts.push({ text: ". " });
    placeParts.push({ em: true, text: formatInt(data.unknown_country) });
    placeParts.push({ text: " records have no country tag, so a country map undercounts. Leak sites are not a census of attacks, and victim names are not republished here." });
  } else {
    placeParts.push({ text: "The ransomware.live dataset was unavailable, so victim counts are withheld." });
  }
  notes.push({
    title: "Zambia is a small share of the sensor map. The regional leak-site tags are more direct.",
    parts: placeParts,
  });

  const closing = [];
  if (usable(feodo)) {
    const data = feodo.data;
    const families = data.by_malware.map((row) => `${row.name} (${formatInt(row.count)})`).join(", ");
    closing.push(...stalePrefix(feodo));
    closing.push({ text: "The public Feodo Tracker blocklist has " });
    closing.push({ em: true, text: formatInt(data.total) });
    closing.push({ text: " command-and-control addresses (" });
    closing.push({ em: true, text: `${formatInt(data.online)} online` });
    closing.push({ text: ", " });
    closing.push({ em: true, text: `${formatInt(data.offline)} offline` });
    closing.push({ text: "). " });
    if (data.feed_updated) {
      closing.push({ text: "The feed’s own last-updated line is " });
      closing.push({ em: true, text: data.feed_updated });
      closing.push({ text: ". " });
    }
    closing.push({ text: "Zambia has " });
    closing.push({ em: true, text: formatInt(data.zambia) });
    closing.push({ text: ` of them. Families in the file: ${families || "none named"}. ` });
  } else {
    closing.push({ text: "Feodo Tracker was unavailable for this snapshot. " });
  }

  if (usable(threatfox) || usable(urlhaus)) {
    const bits = [];
    if (usable(threatfox)) {
      const top = threatfox.data.malware.rows[0];
      bits.push(
        `ThreatFox contributed ${formatInt(threatfox.data.rows)} recent indicators` +
          (top ? `, led by ${top.name} (${formatInt(top.count)})` : "")
      );
    }
    if (usable(urlhaus)) {
      bits.push(`URLhaus contributed ${formatInt(urlhaus.data.rows)} recent URLs`);
    }
    const infra = zambia?.abusech_ips;
    closing.push({ text: `${bits.join(". ")}. ` });
    if (infra === null || infra === undefined) {
      closing.push({
        text: "IP indicators could not be geolocated for this run, so they are not drawn on the map.",
      });
    } else {
      closing.push({ text: "Geolocated abuse.ch IP indicators tagged to Zambia: " });
      closing.push({ em: true, text: formatInt(infra) });
      closing.push({
        text: ". Only indicators that were already IP addresses were placed. Domain names were not resolved.",
      });
    }
  } else {
    const reason = threatfox?.reason || urlhaus?.reason || "the abuse.ch Auth-Key was not available";
    closing.push({
      text: `URLhaus and ThreatFox are not in this snapshot (${reason}). abuse.ch now requires a free Auth-Key for those downloads. A five-row botnet list, last touched months ago, is not a map of malware hosting, and a zero for Zambia on that list is not a clean bill of health.`,
    });
  }
  notes.push({ title: "A short botnet list is not a clean bill of health", parts: closing });
  return notes;
}
