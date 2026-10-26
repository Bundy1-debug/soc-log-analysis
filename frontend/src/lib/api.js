// API helpers. In dev, Vite proxies these to Flask on :5000.
// In prod, Flask serves this app and the same routes.
const base = "";

async function post(path, options) {
  const res = await fetch(base + path, { method: "POST", ...options });
  const data = await res.json().catch(() => ({ error: `Server returned ${res.status}` }));
  if (!res.ok || data.error) throw new Error(data.error || `Server returned ${res.status}`);
  return data;
}

export function analyzeFiles(files) {
  const form = new FormData();
  for (const f of files) form.append("logfile", f);
  return post("/analyze", { body: form });
}

export function analyzeSample() {
  return post("/analyze-sample", {});
}

export async function geoip(ip) {
  const res = await fetch(`${base}/geoip/${encodeURIComponent(ip)}`);
  return res.json();
}
