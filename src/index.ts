interface ProxyCapture {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  response_status: number | null;
  response_body: string | null;
  request_body: string | null;
  response_headers: string | null;
  duration_ms: number | null;
}

interface RepeatedHostFinding { host: string; count: number; urls: string[]; severity: 'medium' }
interface ErrorClusterFinding { host: string; count: number; statusCodes: number[]; severity: 'low' }
interface AnomalousResponseFinding { url: string; size: number; mean: number; stdDev: number; severity: 'high' }

interface MezoState {
  captures: ProxyCapture[];
  results: {
    repeatedHosts: RepeatedHostFinding[];
    errorClusters: ErrorClusterFinding[];
    anomalousResponses: AnomalousResponseFinding[];
  };
  lastUpdated: number | null;
}

function getHost(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

function analyze(captures: ProxyCapture[]): MezoState['results'] {
  // Pass 1: Repeated Host Probing
  const hostMap = new Map<string, string[]>();
  for (const c of captures) {
    const host = getHost(c.url);
    if (!hostMap.has(host)) hostMap.set(host, []);
    hostMap.get(host)!.push(c.url);
  }
  const repeatedHosts: RepeatedHostFinding[] = [...hostMap.entries()]
    .filter(([, urls]) => urls.length >= 5)
    .map(([host, urls]) => ({ host, count: urls.length, urls: [...new Set(urls)].slice(0, 3), severity: 'medium' }))
    .sort((a, b) => b.count - a.count);

  // Pass 2: Error Response Clustering
  const errorMap = new Map<string, Set<number>>();
  for (const c of captures) {
    if ((c.response_status || 0) >= 400) {
      const host = getHost(c.url);
      if (!errorMap.has(host)) errorMap.set(host, new Set());
      errorMap.get(host)!.add(c.response_status!);
    }
  }
  const errorClusters: ErrorClusterFinding[] = [];
  for (const [host, codes] of errorMap) {
    const count = captures.filter(c => getHost(c.url) === host && (c.response_status || 0) >= 400).length;
    if (count >= 3) errorClusters.push({ host, count, statusCodes: [...codes].sort(), severity: 'low' });
  }
  errorClusters.sort((a, b) => b.count - a.count);

  // Pass 3: Anomalous Response Size
  const sizes: { url: string; size: number }[] = [];
  for (const c of captures) {
    let size = 0;
    if (c.response_body) size = c.response_body.length;
    else if (c.response_headers) {
      const m = c.response_headers.match(/content-length['":\s]+(\d+)/i);
      if (m) size = parseInt(m[1]);
    }
    if (size > 0) sizes.push({ url: c.url, size });
  }

  const anomalousResponses: AnomalousResponseFinding[] = [];
  if (sizes.length >= 3) {
    const mean = sizes.reduce((s, x) => s + x.size, 0) / sizes.length;
    const stdDev = Math.sqrt(sizes.reduce((s, x) => s + (x.size - mean) ** 2, 0) / sizes.length);
    if (stdDev > 0) {
      for (const s of sizes) {
        if (s.size > mean + 2 * stdDev) {
          anomalousResponses.push({ url: s.url, size: s.size, mean: Math.round(mean), stdDev: Math.round(stdDev), severity: 'high' });
        }
      }
    }
  }
  anomalousResponses.sort((a, b) => b.size - a.size);

  return { repeatedHosts, errorClusters, anomalousResponses };
}

function formatSize(bytes: number): string {
  return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} bytes`;
}

function render(container: HTMLElement, state: MezoState) {
  const uniqueHosts = new Set(state.captures.map(c => getHost(c.url))).size;
  const totalFindings = state.results.repeatedHosts.length + state.results.errorClusters.length + state.results.anomalousResponses.length;

  container.innerHTML = `
    <div style="padding:20px;color:#fff;font-family:system-ui,-apple-system,sans-serif;font-size:13px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <div>
          <h2 style="margin:0;font-size:18px;color:#fff;font-weight:700">Mezo</h2>
          <p style="margin:2px 0 0;color:#9CA3AF;font-size:11px">Scan history forensics</p>
        </div>
        <div style="text-align:right">
          <span id="mezo-updated" style="color:#9CA3AF;font-size:10px">${state.lastUpdated ? 'Updated just now' : ''}</span>
          <button id="mezo-refresh" style="display:block;margin-top:4px;padding:4px 10px;background:#1F2937;border:1px solid #374151;border-radius:4px;color:#9CA3AF;font-size:10px;cursor:pointer">Refresh</button>
        </div>
      </div>

      ${state.captures.length === 0
        ? '<p style="color:#9CA3AF;font-size:12px;padding:24px;text-align:center;background:#111;border-radius:6px">No proxy captures yet. Start the proxy and send requests to begin analysis.</p>'
        : `<p style="color:#10B981;font-size:11px;margin:0 0 16px">Analyzing ${state.captures.length} captures across ${uniqueHosts} hosts · ${totalFindings} findings</p>`}

      ${renderSection('Repeated Host Activity', '#F59E0B', state.results.repeatedHosts, (f: RepeatedHostFinding) =>
        `<div style="display:flex;justify-content:space-between;padding:8px;font-size:11px"><span style="color:#fff">${f.host}</span><span style="color:#F59E0B">${f.count} requests</span></div>`
      , 'No repeated host patterns detected.')}

      ${renderSection('Error Clusters', '#3B82F6', state.results.errorClusters, (f: ErrorClusterFinding) =>
        `<div style="display:flex;justify-content:space-between;padding:8px;font-size:11px"><span style="color:#fff">${f.host}</span><span style="color:#3B82F6">${f.count} errors (${f.statusCodes.join(', ')})</span></div>`
      , 'No error clusters detected.')}

      ${renderSection('Anomalous Response Sizes', '#EF4444', state.results.anomalousResponses, (f: AnomalousResponseFinding) =>
        `<div style="display:flex;justify-content:space-between;padding:8px;font-size:11px"><span style="color:#fff;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.url}</span><span style="color:#EF4444">${formatSize(f.size)} (mean: ${formatSize(f.mean)})</span></div>`
      , 'No anomalous response sizes detected.')}

      <p style="color:#4B5563;font-size:10px;margin:24px 0 0;text-align:center">Mezo v0.2.0 · by AnishKajan · <a href="https://github.com/AnishKajan/Mezo-Xtension" target="_blank" style="color:#6B7280;text-decoration:underline">View Source</a></p>
    </div>`;
}

function renderSection(title: string, color: string, items: any[], rowFn: (f: any) => string, emptyMsg: string): string {
  return `
    <div style="margin-bottom:12px;background:#111;border:1px solid #1F2937;border-radius:6px;overflow:hidden">
      <div style="padding:10px 12px;border-bottom:1px solid #1F2937;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
        <span style="font-size:11px;text-transform:uppercase;letter-spacing:0.05em;color:${color}">${title}</span>
        <span style="float:right;color:#6B7280;font-size:10px">${items.length}</span>
      </div>
      <div style="padding:${items.length ? '4px' : '12px'}">
        ${items.length ? items.map(rowFn).join('') : `<p style="color:#6B7280;font-size:11px;margin:0">${emptyMsg}</p>`}
      </div>
    </div>`;
}

export function register(api: any) {
  try {
    const state: MezoState = { captures: [], results: { repeatedHosts: [], errorClusters: [], anomalousResponses: [] }, lastUpdated: null };

    api.ui.registerTab('mezo', 'Mezo', (container: HTMLElement) => {
      let debounceTimer: any = null;

      function runAnalysis() {
        state.results = analyze(state.captures);
        state.lastUpdated = Date.now();
        render(container, state);
        container.querySelector('#mezo-refresh')?.addEventListener('click', () => runAnalysis());
      }

      // Initial load
      api.proxy.getCaptures().then((captures: ProxyCapture[]) => {
        state.captures = captures || [];
        runAnalysis();
      }).catch(() => {
        container.innerHTML = '<p style="color:#EF4444;padding:24px;font-size:12px">[Mezo v0.2.0] Could not load proxy captures. Is the proxy running?</p>';
      });

      // Live updates
      api.proxy.onCapture((capture: ProxyCapture) => {
        state.captures.push(capture);
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => runAnalysis(), 1500);
      });

      // "Updated Xs ago" display refresh
      setInterval(() => {
        const el = container.querySelector('#mezo-updated');
        if (el && state.lastUpdated) {
          const secs = Math.round((Date.now() - state.lastUpdated) / 1000);
          el.textContent = secs < 5 ? 'Updated just now' : `Updated ${secs}s ago`;
        }
      }, 5000);
    });
  } catch (e) {
    console.error('[Mezo v0.2.0]', e);
  }
}
