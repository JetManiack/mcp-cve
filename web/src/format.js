export function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const now = new Date();
  const diff = now - d;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return Math.floor(diff / 60_000) + "m ago";
  if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + "h ago";
  if (diff < 7 * 86_400_000) return Math.floor(diff / 86_400_000) + "d ago";
  return d.toLocaleDateString();
}

export function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString();
}

const SEVERITY_COLOR = {
  CRITICAL: { bg: "#2a1414", text: "#f2a6a6", border: "#5a2a2a" },
  HIGH:     { bg: "#2a1f10", text: "#ffb454", border: "#5a3a10" },
  MEDIUM:   { bg: "#1a1f10", text: "#b8d454", border: "#3a4a10" },
  LOW:      { bg: "#0f1a1f", text: "#6bd68a", border: "#1a3a2a" },
  NONE:     { bg: "#1a1b1e", text: "#8891a8", border: "#3a3b3e" },
};

export function severityStyle(severity) {
  return SEVERITY_COLOR[severity] || SEVERITY_COLOR.NONE;
}
