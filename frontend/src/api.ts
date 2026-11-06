import type {
  CheckResult, Health, Investigation, InvestigationListItem, PacketDetail, PacketFilters, PacketPage, Report,
  RuleInfo, SampleInfo, Symptom,
} from "./types";

const API_ORIGIN = (import.meta.env.VITE_API_URL || "").replace(/\/+$/, "");
const BASE = API_ORIGIN ? `${API_ORIGIN}/api` : "/api";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public fields?: { field: string; problem: string }[]) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, init);
  } catch {
    throw new ApiError(0, "network", "Cannot reach the LinkGuard backend. Is it running on port 8000?");
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
  if (!res.ok) {
    const err = body?.error;
    if (err) throw new ApiError(res.status, err.code, err.message, err.details);
    throw new ApiError(res.status, "http_" + res.status,
      res.status >= 500 && !body ? "The backend is not responding correctly (is it running?)." : `Request failed (${res.status}).`);
  }
  return body as T;
}

const json = (method: string, body: unknown): RequestInit => ({
  method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
});

export interface CreatePayload {
  title?: string; symptom: Symptom; target?: string; source: "live" | "pcap" | "both";
  live: { dns: boolean; tcp_ports: number[]; http: boolean; http_scheme: "http" | "https"; timeout: number };
}

export const api = {
  health: () => request<Health>("/health"),
  samples: () => request<SampleInfo[]>("/samples"),
  loadSample: (id: string) => request<Investigation>(`/samples/${id}/load`, { method: "POST" }),
  rules: () => request<RuleInfo[]>("/rules"),
  list: () => request<InvestigationListItem[]>("/investigations"),
  get: (id: string) => request<Investigation>(`/investigations/${id}`),
  resolve: (id: string) => request<Investigation>(`/investigations/${id}/resolve`, { method: "POST" }),
  create: (p: CreatePayload) => request<Investigation>("/investigations", json("POST", p)),
  remove: (id: string) => request<void>(`/investigations/${id}`, { method: "DELETE" }),
  upload: (id: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<Investigation>(`/investigations/${id}/capture`, { method: "POST", body: form });
  },
  packets: (id: string, offset: number, limit: number, f: PacketFilters) => {
    const qs = new URLSearchParams({ offset: String(offset), limit: String(limit) });
    (Object.entries(f) as [string, string | undefined][]).forEach(([k, v]) => { if (v) qs.set(k, v); });
    return request<PacketPage>(`/investigations/${id}/packets?${qs}`);
  },
  packet: (id: string, index: number) => request<PacketDetail>(`/investigations/${id}/packets/${index}`),
  report: (id: string) => request<Report>(`/investigations/${id}/report`),
  reportUrl: (id: string, fmt: "json" | "csv") => `${BASE}/investigations/${id}/report.${fmt}`,
  checkDns: (target: string, record_type: string, timeout: number) => request<CheckResult>("/checks/dns", json("POST", { target, record_type, timeout })),
  checkTcp: (target: string, port: number, timeout: number) => request<CheckResult>("/checks/tcp", json("POST", { target, port, timeout })),
  checkHttp: (url: string, method: string, timeout: number) => request<CheckResult>("/checks/http", json("POST", { url, method, timeout })),
};
