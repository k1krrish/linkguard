import { useCallback, useEffect, useRef, useState } from "react";
import type { CheckStatus, FindingStatus, Symptom } from "./types";

export const SYMPTOMS: { value: Symptom; label: string; hint: string }[] = [
  {
    value: "dns_resolution_failure",
    label: "DNS Resolution Failure",
    hint: "Name lookup timeout or NXDOMAIN / SERVFAIL response",
  },
  {
    value: "connection_failure",
    label: "TCP Refused / Timeout",
    hint: "SYN unacknowledged or active RST reset received",
  },
  {
    value: "http_error",
    label: "HTTP Service Error",
    hint: "Server reachable but returns 4xx or 5xx status codes",
  },
  {
    value: "slow_or_intermittent",
    label: "Latency / Retransmission",
    hint: "Elevated RTT, packet drops, or repeated segments",
  },
  {
    value: "unknown",
    label: "Uncategorized Traffic",
    hint: "General diagnostic analysis across captured frames",
  },
];

export const symptomLabel = (s: Symptom) => SYMPTOMS.find((x) => x.value === s)?.label ?? s;

export const fmtTime = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

export const fmtClock = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour12: false });

export const fmtMs = (ms: number | null | undefined) =>
  ms == null ? "-" : ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;

export const fmtBytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1048576
    ? `${(n / 1024).toFixed(1)} KB`
    : `${(n / 1048576).toFixed(1)} MB`;

export const fmtRel = (s: number) => s.toFixed(3);

export function errMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return "An unexpected diagnostic error occurred.";
}

export const findingTone: Record<FindingStatus, string> = {
  issue: "text-rose-300 bg-rose-500/10 border-rose-500/25 shadow-sm shadow-rose-950/40",
  inconclusive: "text-amber-300 bg-amber-500/10 border-amber-500/25 shadow-sm shadow-amber-950/40",
  ok: "text-emerald-300 bg-emerald-500/10 border-emerald-500/25 shadow-sm shadow-emerald-950/40",
};

export const checkTone: Record<CheckStatus, string> = {
  success: "text-emerald-300 bg-emerald-500/10 border-emerald-500/25",
  failure: "text-rose-300 bg-rose-500/10 border-rose-500/25",
  inconclusive: "text-amber-300 bg-amber-500/10 border-amber-500/25",
  unavailable: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

/** Lightweight hash router: #/path?query */
export function parseHash(): { path: string[]; query: URLSearchParams } {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [p, q = ""] = raw.split("?");
  return { path: p.split("/").filter(Boolean), query: new URLSearchParams(q) };
}

export function useRoute() {
  const [route, setRoute] = useState(parseHash);
  useEffect(() => {
    const on = () => setRoute(parseHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export const go = (path: string) => {
  window.location.hash = path;
};

/** Fetch helper with loading / error / reload and stale-response protection. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, set] = useState<{ data: T | null; error: string | null; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const tick = useRef(0);
  const run = useCallback(() => {
    const mine = ++tick.current;
    set((s) => ({ ...s, loading: true, error: null }));
    fn().then(
      (data) => {
        if (mine === tick.current) set({ data, error: null, loading: false });
      },
      (e) => {
        if (mine === tick.current) set({ data: null, error: errMessage(e), loading: false });
      }
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(run, [run]);
  return { ...state, reload: run };
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}
