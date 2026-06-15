export interface VaastXtensionApi {
  proxy: {
    getCaptures: () => Promise<any[]>;
    sendRequest: (url: string, method: string, headers: Record<string, string>, body?: string) => Promise<any>;
  };
  scanner: {
    addFinding: (finding: { category: string; severity: string; title: string; description: string; evidence: string }) => Promise<void>;
    getFindings: () => Promise<any[]>;
  };
  ui: {
    registerTab: (id: string, label: string, renderFn?: (container: HTMLElement) => void) => void;
  };
  session: {
    getMeta: () => Promise<{ xtensionId: string }>;
    getVerifiedDomains: () => Promise<string[]>;
  };
}
