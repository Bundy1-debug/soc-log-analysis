/*
 * SOC Log Analyzer — dashboard
 *
 * SECURITY RULE: everything in a report comes from log lines, and log lines are written by attackers
 * (usernames, URLs, user agents, domains). This file never puts data into innerHTML: all values go
 * through textContent via el(), so "<script>" in a log is displayed as text, never executed.
 */
'use strict';

const $ = id => document.getElementById(id);
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SOURCE_OF = {
  SSH_BRUTE_FORCE: 'ssh', SSH_LOGIN_AFTER_BRUTE_FORCE: 'ssh', HTTP_SCAN: 'http',
  SUSPICIOUS_DNS: 'dns', DNS_TUNNELING: 'dns', DNS_BEACONING: 'dns',
  WEB_LOGIN_BRUTE_FORCE: 'http', WEB_DIRECTORY_BRUTE_FORCE: 'http', WEBSHELL: 'http', WEB_LARGE_TRANSFER: 'http',
  SUDO_ABUSE: 'host', SU_BRUTE_FORCE: 'host', USER_CREATED: 'host', PRIV_GROUP_ADD: 'host',
};
const sourceOf = type => SOURCE_OF[type]
  || (type.startsWith('EDR_') ? 'host' : null)       // 9 EDR rule types → Host tab
  || (type.startsWith('ANOMALY_') ? 'anom' : null);  // statistical alerts → Anomaly tab
const mb = n => `${(n / 1048576).toFixed(0)} MB`;
const charts = {};
let lastReport = null;

/** Build a DOM element safely. Strings become text nodes, never HTML. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children.flat(Infinity)) {    // detail cells nest arrays of tags
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const sevColor = s => ({ CRITICAL: css('--red'), HIGH: css('--orange'), MEDIUM: css('--yellow'), LOW: css('--green') })[s];
const sevBadge = s => el('span', { class: `sev sev-${SEVERITIES.includes(s) ? s : 'LOW'}` }, s);
const time = ts => (ts || '').slice(5);   // "2024-03-20 10:01:22" → "03-20 10:01:22"
const mitreLink = m => el('a', { class: 'mitre-link', href: m.url, target: '_blank', rel: 'noopener noreferrer', title: `${m.tactic} · ${m.technique}` }, m.technique_id);

// ── Clock ────────────────────────────────────────────────────────
function tick() { $('clock').textContent = new Date().toLocaleTimeString(); }
tick();
setInterval(tick, 1000);

// ── Upload / sample ──────────────────────────────────────────────
const dropzone = $('dropzone');
dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('over'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('over'));
dropzone.addEventListener('drop', e => {
  e.preventDefault();
  dropzone.classList.remove('over');
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files);
});
$('file-input').addEventListener('change', e => { if (e.target.files.length) upload(e.target.files); });
$('btn-sample').addEventListener('click', () => request('/analyze-sample', { method: 'POST' }));

function upload(files) {
  const form = new FormData();
  for (const f of files) form.append('logfile', f);
  request('/analyze', { method: 'POST', body: form });
}

async function request(url, options) {
  setState('loading');
  try {
    const resp = await fetch(url, options);
    const data = await resp.json().catch(() => ({ error: `Server returned ${resp.status}` }));
    if (!resp.ok || data.error) throw new Error(data.error || `Server returned ${resp.status}`);
    render(data);
    setState('results');
  } catch (err) {
    $('error-box').textContent = `⚠ ${err.message}`;
    setState('error');
  }
}

function setState(state) {
  $('loading').style.display = state === 'loading' ? 'block' : 'none';
  $('error-box').style.display = state === 'error' ? 'block' : 'none';
  $('results').style.display = state === 'results' ? 'block' : (state === 'loading' ? 'none' : $('results').style.display);
  $('status-text').textContent = { loading: 'Analyzing…', error: 'Error', results: 'Report ready' }[state];
}

// ── Render ───────────────────────────────────────────────────────
function render(r) {
  lastReport = r;
  const s = r.summary;
  const techniques = new Set(r.alerts.map(a => a.mitre.technique_id));

  $('k-incidents').textContent = s.incidents;
  $('k-alerts').textContent = s.alerts;
  $('k-alerts-sub').textContent = `${s.by_severity.CRITICAL} critical · ${s.by_severity.HIGH} high`;
  $('k-breaches').textContent = s.breaches;
  $('k-flagged').textContent = s.flagged_ips;
  $('k-flagged-sub').textContent = `of ${s.unique_ips} unique IPs`;
  $('k-fails').textContent = s.ssh_failures;
  $('k-success').textContent = s.ssh_successes;
  $('k-events').textContent = s.events_parsed;
  $('k-events-sub').textContent = Object.entries(s.events_by_source).map(([k, v]) => `${k} ${v}`).join(' · ') || 'no recognized lines';
  $('k-techniques').textContent = techniques.size;
  $('k-techniques-sub').textContent = [...techniques].join(' ');
  $('nav-incidents').textContent = s.incidents;
  $('nav-alerts').textContent = s.alerts;

  const worst = SEVERITIES.find(sev => s.by_severity[sev] > 0);
  const badge = $('threat-level');
  badge.classList.toggle('hidden', !worst);
  if (worst) {
    badge.textContent = `● THREAT LEVEL: ${worst}`;
    badge.style.color = sevColor(worst);
    badge.style.borderColor = sevColor(worst);
  }

  renderCharts(s);
  renderIncidents(r);
  renderAlerts(r.alerts);
  renderJSON(r);
}

function renderCharts(s) {
  if (!window.Chart) return;                 // CDN blocked: the rest of the dashboard still works
  Chart.defaults.color = css('--text2');
  Chart.defaults.borderColor = css('--border');
  Chart.defaults.font.family = css('--sans');
  const draw = (id, config) => { charts[id]?.destroy(); charts[id] = new Chart($(id), config); };
  const doughnut = { responsive: true, maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } } };

  draw('chart-ips', {
    type: 'bar',
    data: {
      labels: s.top_ips.map(t => t.ip),
      datasets: [{ data: s.top_ips.map(t => t.events), borderRadius: 3,
                   backgroundColor: s.top_ips.map(t => t.flagged ? css('--red') : css('--accent')) }],
    },
    options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y',
               plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } },
  });

  const sev = SEVERITIES.filter(k => s.by_severity[k] > 0);
  draw('chart-sev', {
    type: 'doughnut',
    data: { labels: sev, datasets: [{ data: sev.map(k => s.by_severity[k]), backgroundColor: sev.map(sevColor), borderWidth: 0 }] },
    options: doughnut,
  });

  const tactics = Object.keys(s.by_tactic);
  const palette = ['--purple', '--orange', '--cyan', '--accent', '--red', '--green'].map(css);
  draw('chart-tactics', {
    type: 'doughnut',
    data: { labels: tactics, datasets: [{ data: tactics.map(t => s.by_tactic[t]), backgroundColor: palette, borderWidth: 0 }] },
    options: doughnut,
  });
}

function renderIncidents(r) {
  const list = $('incident-list');
  const byId = Object.fromEntries(r.alerts.map(a => [a.id, a]));
  list.replaceChildren();
  if (!r.incidents.length) {
    list.append(el('div', { class: 'empty-state' }, el('div', { class: 'empty-icon' }, '✓'), 'No threats detected above threshold'));
    return;
  }

  for (const inc of r.incidents) {
    const alerts = inc.alert_ids.map(id => byId[id]);
    const card = el('article', { class: `inc ${inc.severity}${inc.breach ? ' open' : ''}` });

    const stages = [];
    alerts.forEach((a, i) => {
      if (i) stages.push(el('span', { class: 'stage-arrow' }, '→'));
      stages.push(el('span', { class: 'stage' }, el('b', {}, a.mitre.tactic), ` · ${a.title}`));
    });

    card.append(
      el('button', { class: 'inc-head', type: 'button', 'aria-expanded': String(inc.breach), onclick: e => {
          const open = card.classList.toggle('open');
          e.currentTarget.setAttribute('aria-expanded', String(open));
        } },
        el('span', { class: 'inc-toggle' }, '▶'),
        el('span', { class: 'inc-id' }, inc.id),
        el('span', { class: 'inc-ip' }, inc.ip),
        sevBadge(inc.severity),
        inc.breach && el('span', { class: 'breach-tag' }, '⚠ BREACH'),
        el('span', { class: 'inc-when' }, `${time(inc.first_seen)} → ${time(inc.last_seen)}`),
      ),
      el('div', { class: 'inc-chain' }, stages),
      el('div', { class: 'inc-body' },
        el('div', {},
          el('h3', { class: 'sub-title' }, `Timeline · ${inc.timeline.length} events`),
          el('ul', { class: 'timeline' }, inc.timeline.map(ev =>
            el('li', { class: ev.source },
              el('span', { class: 'tl-ts' }, time(ev.ts)),
              el('span', { class: 'tl-alert' }, ev.alert),
              el('span', { class: 'tl-text' }, ev.text)))),
        ),
        el('div', {},
          el('h3', { class: 'sub-title' }, 'Recommended response'),
          el('ol', { class: 'response' }, inc.response.map(step => el('li', {}, step))),
          el('h3', { class: 'sub-title' }, 'Alerts'),
          el('ul', { class: 'response' }, alerts.map(a =>
            el('li', {}, sevBadge(a.severity), ' ', a.summary, ' ', mitreLink(a.mitre)))),
        ),
      ),
    );
    list.append(card);
  }
}

function detailsCell(a) {
  const d = a.details;
  const tags = (items, danger) => items.map(t => el('span', { class: `tag${danger ? ' danger' : ''}` }, t));
  switch (a.type) {
    case 'SSH_BRUTE_FORCE':
      return [el('div', { class: 'muted' }, `peak ${d.peak_in_window} in ${d.window_seconds}s`),
              tags(d.users_targeted.slice(0, 6).map(u => `${u.user}×${u.attempts}${u.exists ? '' : ' (invalid)'}`))];
    case 'SSH_LOGIN_AFTER_BRUTE_FORCE':
      return [el('span', { class: 'breach-tag' }, '⚠ BREACH'), ' ',
              tags(d.compromised_users, true), el('div', { class: 'muted' }, `via ${d.auth_method} after ${d.failures_before} failures`)];
    case 'HTTP_SCAN':
      return [tags(d.payloads.map(p => p.replace(/_/g, ' ')), true), tags(d.exposed_paths.map(p => `2xx ${p}`), true),
              tags(d.top_paths.slice(0, 3)), el('div', { class: 'muted' }, d.agents.join(', '))];
    case 'SUSPICIOUS_DNS':
      return [tags(d.domains, d.indicators.threat_intel), el('div', { class: 'muted' }, Object.keys(d.indicators).join(', ').replace(/_/g, ' '))];
    case 'WEB_LOGIN_BRUTE_FORCE':
      return [d.successful_logins ? el('span', { class: 'breach-tag' }, '⚠ LOGIN SUCCEEDED') : null, tags(d.login_paths),
              el('div', { class: 'muted' }, `${d.failed_attempts} failures · peak ${d.peak_in_window}/min`)];
    case 'WEB_DIRECTORY_BRUTE_FORCE':
      return [tags(d.discovered_paths.slice(0, 4), true),
              el('div', { class: 'muted' }, `${d.not_found} × 404 · ${d.agents.join(', ') || 'unknown agent'}`)];
    case 'WEBSHELL':
      return [tags(d.scripts, true), el('div', { class: 'muted' }, `${d.command_requests} command request(s) · ${d.upload_dir_posts} upload-dir POST(s)`)];
    case 'WEB_LARGE_TRANSFER':
      return [tags(d.sensitive_files, true), el('div', { class: 'muted' }, `${mb(d.total_bytes)} served`)];
    case 'DNS_TUNNELING':
      return [tags([d.parent_domain], true), tags(Object.keys(d.signals).map(s => s.replace(/_/g, ' '))),
              el('div', { class: 'muted' }, `${d.unique_subdomains} unique subdomains · ~${(d.encoded_bytes_estimate / 1024).toFixed(1)} KB encoded`)];
    case 'DNS_BEACONING':
      return [tags([d.parent_domain], true),
              el('div', { class: 'muted' }, `every ~${d.interval_seconds}s · jitter ${(d.jitter * 100).toFixed(1)}%`)];
    case 'SUDO_ABUSE':
      return [tags(d.reasons, d.not_in_sudoers)];
    case 'SU_BRUTE_FORCE':
      return [el('span', { class: 'muted' }, `targeting ${d.targets.join(', ')}`)];
    case 'USER_CREATED':
      return [tags([`created by ${d.tool}`])];
    case 'PRIV_GROUP_ADD':
      return [tags(d.groups, true)];
    case 'ANOMALY_VOLUME':
      return [el('div', { class: 'muted' }, `${d.event_count} events vs ${d.peer_average} avg · z=${d.zscore}`)];
    case 'ANOMALY_NEW_SOURCE':
      return [el('div', { class: 'muted' }, `not in baseline of ${d.baseline_sources} sources`)];
    case 'ANOMALY_NEW_DOMAIN':
      return [tags(d.domains), el('div', { class: 'muted' }, `vs ${d.baseline_domains} baseline domains`)];
    default:
      if (a.type.startsWith('EDR_')) {                 // command-execution alerts from auditd
        return [el('div', { class: 'summary-cell', style: 'font-family:var(--mono);font-size:.7rem' },
                   (d.commands || []).join(' ; '))];
      }
      return [];
  }
}

function renderAlerts(alerts) {
  for (const source of ['ssh', 'http', 'dns', 'host', 'anom']) {
    const rows = alerts.filter(a => sourceOf(a.type) === source);
    $(`tc-${source}`).textContent = rows.length;
    const panel = $(`tab-${source}`);
    panel.replaceChildren();
    if (!rows.length) {
      panel.append(el('div', { class: 'empty-state' }, el('div', { class: 'empty-icon' }, '✓'), `No ${source.toUpperCase()} alerts`));
      continue;
    }
    panel.append(el('div', { class: 'tbl-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, ['IP', 'Detection', 'Severity', 'Count', 'Details', 'Window', 'ATT&CK'].map(h => el('th', {}, h)))),
      el('tbody', {}, rows.map(a => el('tr', {},
        el('td', {}, el('button', { class: 'ip-btn', type: 'button', onclick: () => showGeo(a) }, a.ip),
                     el('div', { class: 'muted' }, a.ip_role + (a.intel_match ? ' · on blocklist' : ''))),
        el('td', {}, a.title, el('div', { class: 'summary-cell' }, a.summary)),
        el('td', {}, sevBadge(a.severity)),
        el('td', {}, a.count),
        el('td', {}, detailsCell(a)),
        el('td', { class: 'muted' }, time(a.first_seen), el('br'), time(a.last_seen)),
        el('td', {}, mitreLink(a.mitre), el('div', { class: 'muted' }, a.mitre.tactic)),
      ))),
    )));
  }
}

document.querySelectorAll('.tab-btn').forEach(btn => btn.addEventListener('click', () => {
  document.querySelectorAll('.tab-btn, .tab-panel').forEach(n => n.classList.remove('active'));
  btn.classList.add('active');
  $(`tab-${btn.dataset.tab}`).classList.add('active');
}));

// ── Raw JSON (syntax highlighted with text nodes, not HTML) ─────
function renderJSON(r) {
  const text = JSON.stringify(r, null, 2);
  const out = $('json-out');
  out.replaceChildren();
  const token = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let last = 0;
  for (const m of text.matchAll(token)) {
    out.append(text.slice(last, m.index));
    const cls = m[1] ? (m[2] ? 'jk' : 'js') : (m[3] ? 'jb' : 'jn');
    out.append(el('span', { class: cls }, m[1] || m[0]));
    if (m[2]) out.append(m[2]);
    last = m.index + m[0].length;
  }
  out.append(text.slice(last));
}

$('btn-copy').addEventListener('click', e => {
  navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2)).then(() => {
    e.target.textContent = 'Copied ✓';
    setTimeout(() => { e.target.textContent = 'Copy'; }, 1500);
  });
});
$('btn-download').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const link = el('a', { href: URL.createObjectURL(blob), download: 'soc_report.json' });
  link.click();
  URL.revokeObjectURL(link.href);
});

// ── IP intelligence modal ────────────────────────────────────────
async function showGeo(alert) {
  const body = $('geo-body');
  $('geo-modal').classList.add('open');
  body.replaceChildren(el('div', { class: 'modal-ip' }, alert.ip), el('div', { id: 'geo-loading' }, 'Looking up…'));

  let geo = alert.geo;
  if (!geo || !Object.keys(geo).length) {
    try {
      const resp = await fetch(`/geoip/${encodeURIComponent(alert.ip)}`);
      geo = await resp.json();
    } catch { geo = { error: 'Lookup failed' }; }
  }

  const rows = [
    ['Role', alert.ip_role],
    ['Threat intel', alert.intel_match ? 'On blocklist' : 'No match'],
  ];
  if (geo.private) rows.push(['Network', 'Private / reserved range — no public location']);
  else if (geo.error) rows.push(['Location', geo.error]);
  else rows.push(['Country', `${geo.country || '—'} (${geo.countryCode || '??'})`], ['City', geo.city || '—'],
                 ['ISP', geo.isp || '—'], ['ASN', geo.as || '—']);

  body.replaceChildren(
    el('div', { class: 'modal-ip' }, alert.ip),
    el('div', { class: 'geo-grid' }, rows.map(([k, v]) =>
      el('div', { class: 'geo-row' }, el('span', { class: 'geo-key' }, k), el('span', { class: 'geo-val' }, v)))),
  );
}

const closeGeo = () => $('geo-modal').classList.remove('open');
$('geo-close').addEventListener('click', closeGeo);
$('geo-modal').addEventListener('click', e => { if (e.target.id === 'geo-modal') closeGeo(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeGeo(); });
