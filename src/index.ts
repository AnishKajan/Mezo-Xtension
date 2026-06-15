interface Capture {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  response_status: number | null;
  response_body: string | null;
  request_body: string | null;
  duration_ms: number | null;
}

interface Finding {
  category: string;
  severity: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  evidence: string;
}

export function register(api: any) {
  api.ui.registerTab('mezo', 'Mezo', (container: HTMLElement) => {
    container.innerHTML = `
      <div style="padding:24px;color:#e2e8f0;font-family:system-ui">
        <h2 style="color:#7C3AED;margin:0 0 4px;font-size:18px">Mezo</h2>
        <p style="color:#94a3b8;font-size:12px;margin:0 0 20px">Scan History Forensics</p>
        <button id="mz-analyze" style="padding:8px 16px;background:#7C3AED;border:none;border-radius:6px;color:white;font-size:13px;cursor:pointer;margin-bottom:16px">Analyze Session History</button>
        <div id="mz-results" style="border:1px solid #334155;border-radius:8px;padding:16px;min-height:250px">
          <p style="color:#64748b;font-size:12px;margin:0">Click Analyze to run three forensic passes across your captured traffic: repeated probing detection, error clustering, and response size anomalies.</p>
        </div>
      </div>`;

    const analyzeBtn = container.querySelector('#mz-analyze') as HTMLButtonElement;
    const results = container.querySelector('#mz-results') as HTMLDivElement;

    analyzeBtn.addEventListener('click', async () => {
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = 'Analyzing...';
      results.innerHTML = '';

      const captures: Capture[] = await api.proxy.getCaptures();
      if (captures.length === 0) {
        results.innerHTML = '<p style="color:#64748b;font-size:12px;margin:0">No captures in session. Use the Proxy tab to capture traffic first.</p>';
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Analyze Session History';
        return;
      }

      const findings: Finding[] = [];
      const sections: string[] = [];

      // Pass 1: Repeated Host Probing
      const hostCounts = new Map<string, number>();
      for (const c of captures) {
        try {
          const host = new URL(c.url).hostname;
          hostCounts.set(host, (hostCounts.get(host) || 0) + 1);
        } catch {}
      }
      const repeatedHosts = [...hostCounts.entries()].filter(([, count]) => count >= 5).sort((a, b) => b[1] - a[1]);

      if (repeatedHosts.length > 0) {
        sections.push(`
          <div style="margin-bottom:16px">
            <h3 style="color:#7C3AED;font-size:13px;margin:0 0 8px">Repeated Host Probing</h3>
            ${repeatedHosts.map(([host, count]) => `
              <div style="padding:8px;background:#0f172a;border-radius:4px;margin-bottom:4px;font-size:11px">
                <span style="color:#e2e8f0">${host}</span>
                <span style="color:#7C3AED;float:right">${count} requests</span>
              </div>`).join('')}
          </div>`);
        for (const [host, count] of repeatedHosts) {
          findings.push({ category: 'Behavioral Pattern', severity: 'low', title: `Repeated probing: ${host} (${count}x)`, description: `Host received ${count} requests in this session — may indicate automated enumeration.`, evidence: `${count} requests to ${host}` });
        }
      }

      // Pass 2: Error Response Clustering
      const errorCaptures = captures.filter(c => (c.response_status || 0) >= 400);
      const errorsByUrl = new Map<string, number>();
      for (const c of errorCaptures) {
        errorsByUrl.set(c.url, (errorsByUrl.get(c.url) || 0) + 1);
      }
      const errorClusters = [...errorsByUrl.entries()].filter(([, count]) => count >= 2).sort((a, b) => b[1] - a[1]);

      if (errorClusters.length > 0) {
        sections.push(`
          <div style="margin-bottom:16px">
            <h3 style="color:#f87171;font-size:13px;margin:0 0 8px">Error Response Clustering</h3>
            ${errorClusters.map(([url, count]) => `
              <div style="padding:8px;background:#0f172a;border-radius:4px;margin-bottom:4px;font-size:11px">
                <span style="color:#e2e8f0;word-break:break-all">${url}</span>
                <span style="color:#f87171;float:right">${count} errors</span>
              </div>`).join('')}
          </div>`);
        for (const [url, count] of errorClusters) {
          findings.push({ category: 'Error Cluster', severity: 'medium', title: `Error cluster: ${url} (${count} errors)`, description: `Endpoint returned errors ${count} times — may indicate broken tool calls or hallucinated endpoints.`, evidence: `${count} error responses from ${url}` });
        }
      }

      // Pass 3: Anomalous Response Size
      const sizes = captures.filter(c => c.response_body).map(c => ({ url: c.url, size: (c.response_body || '').length }));
      if (sizes.length >= 3) {
        const mean = sizes.reduce((s, x) => s + x.size, 0) / sizes.length;
        const stddev = Math.sqrt(sizes.reduce((s, x) => s + (x.size - mean) ** 2, 0) / sizes.length);
        const outliers = sizes.filter(x => Math.abs(x.size - mean) > 2 * stddev);

        if (outliers.length > 0) {
          sections.push(`
            <div style="margin-bottom:16px">
              <h3 style="color:#FFEF00;font-size:13px;margin:0 0 8px">Anomalous Response Size</h3>
              <p style="color:#64748b;font-size:10px;margin:0 0 6px">Mean: ${Math.round(mean)} bytes, StdDev: ${Math.round(stddev)} bytes</p>
              ${outliers.slice(0, 5).map(o => `
                <div style="padding:8px;background:#0f172a;border-radius:4px;margin-bottom:4px;font-size:11px">
                  <span style="color:#e2e8f0;word-break:break-all">${o.url}</span>
                  <span style="color:#FFEF00;float:right">${o.size} bytes</span>
                </div>`).join('')}
            </div>`);
          for (const o of outliers.slice(0, 5)) {
            findings.push({ category: 'Size Anomaly', severity: 'medium', title: `Anomalous response: ${o.url} (${o.size} bytes)`, description: `Response size is ${Math.round(Math.abs(o.size - mean) / stddev)}x standard deviations from mean — may indicate data exfiltration or prompt injection output.`, evidence: `${o.size} bytes (mean: ${Math.round(mean)}, stddev: ${Math.round(stddev)})` });
          }
        }
      }

      // Write findings
      for (const f of findings) {
        api.scanner.addFinding(f);
      }

      // Render
      if (sections.length === 0) {
        results.innerHTML = `<p style="color:#64748b;font-size:12px;margin:0">No patterns detected across ${captures.length} captures. Session traffic appears normal.</p>`;
      } else {
        results.innerHTML = `
          <p style="color:#94a3b8;font-size:11px;margin:0 0 12px">Analyzed ${captures.length} captures · ${findings.length} findings</p>
          ${sections.join('')}`;
      }

      analyzeBtn.disabled = false;
      analyzeBtn.textContent = 'Analyze Session History';
    });
  });
}
