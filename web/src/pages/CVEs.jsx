import { useState, useEffect, useCallback } from "react";
import { apiCall } from "../api.js";
import { formatDate, severityStyle } from "../format.js";

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];

function SeverityBadge({ severity }) {
  const s = severityStyle(severity);
  return (
    <span style={{
      background: s.bg,
      color: s.text,
      border: `1px solid ${s.border}`,
      borderRadius: "999px",
      padding: "0.1rem 0.5rem",
      fontSize: "11px",
      fontWeight: 600,
      letterSpacing: "0.02em",
      fontFamily: "var(--font-mono)",
      whiteSpace: "nowrap",
    }}>
      {severity}
    </span>
  );
}

export default function CVEs() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [vendor, setVendor] = useState("");
  const [items, setItems] = useState([]);
  const [cursor, setCursor] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [total, setTotal] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback((reset, currentCursor) => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: "50" });
    if (q) params.set("q", q);
    if (severity !== "ALL") params.set("severity", severity);
    if (vendor) params.set("vendor", vendor);
    if (!reset && currentCursor) params.set("cursor", currentCursor);
    apiCall("/cves?" + params)
      .then((data) => {
        setItems((prev) => reset ? data.cves : [...prev, ...data.cves]);
        setCursor(data.next_cursor || "");
        setHasMore(!!data.next_cursor);
        if (reset) setTotal(data.total);
      })
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [q, severity, vendor]);

  useEffect(() => {
    setCursor("");
    setItems([]);
    setHasMore(false);
    load(true, "");
  }, [q, severity, vendor]);

  const nvdURL = (id) => `https://nvd.nist.gov/vuln/detail/${id}`;

  return (
    <main>
      <div className="page-header">
        <h2 className="section-title">CVEs</h2>
        {total !== null && <span className="count">{total.toLocaleString()} total</span>}
      </div>
      <div className="filter-bar">
        <input
          className="grow"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search description…"
          aria-label="Search"
        />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input
          value={vendor}
          onChange={(e) => setVendor(e.target.value)}
          placeholder="Vendor / product"
          aria-label="Vendor"
          style={{ width: "160px" }}
        />
      </div>
      {error && <div className="callout">{error}</div>}
      <div className="call-list">
        {items.map((cve) => (
          <div
            className="call-row"
            key={cve.id}
            style={{ display: "grid", gridTemplateColumns: "9rem 6rem 4rem 7rem 1fr", gap: "0 0.75rem", alignItems: "center" }}
          >
            <a
              href={nvdURL(cve.id)}
              target="_blank"
              rel="noreferrer"
              className="metric"
              style={{ color: "var(--credential)", textDecoration: "none", fontFamily: "var(--font-mono)", fontSize: "12px" }}
            >
              {cve.id}
            </a>
            <SeverityBadge severity={cve.severity} />
            <span className="metric" style={{ textAlign: "right" }}>
              {cve.cvss_score > 0 ? cve.cvss_score.toFixed(1) : "—"}
            </span>
            <span className="metric">{formatDate(cve.published)}</span>
            <span
              style={{ fontSize: "13px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
              title={cve.description}
            >
              {cve.description}
            </span>
          </div>
        ))}
        {items.length === 0 && !loading && (
          <div className="empty-state">No CVEs match the current filters.</div>
        )}
        {loading && items.length === 0 && (
          <div className="empty-state">Loading…</div>
        )}
      </div>
      {hasMore && (
        <button className="load-more" onClick={() => load(false, cursor)} disabled={loading}>
          {loading ? "Loading…" : "Load more"}
        </button>
      )}
    </main>
  );
}
