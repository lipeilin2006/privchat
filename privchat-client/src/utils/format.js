export const AVATAR_COLORS = ["#54b85a", "#3390ec", "#ef8f36", "#8e5bd0", "#e05a72", "#3fb6b6"];

export function initials(name) {
  const s = (name || "?").trim();
  return s.slice(0, 1).toUpperCase();
}

export function avatarColor(name) {
  const s = name || "?";
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

export function fmtTime(ms) {
  if (!ms) return "";
  const d = new Date(ms);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return `${d.getMonth() + 1}/${d.getDate()}`;
}
