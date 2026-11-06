import { createContext, useContext, useState, type ReactNode } from "react";
import { api } from "./api";
import { errMessage, go, useAsync } from "./lib";
import type { Health, InvestigationListItem } from "./types";

interface Ctx {
  list: InvestigationListItem[];
  listLoading: boolean;
  listError: string | null;
  refresh: () => void;
  health: Health | null;
  healthError: string | null;
  loadSample: (id: string, navigate?: boolean) => Promise<any>;
  loadNextSample: (navigate?: boolean) => Promise<any>;
  sampleBusy: string | null;
  sampleError: string | null;
  lastSimulatedTitle: string | null;
  clearSimulatedNotice: () => void;
}
const AppCtx = createContext<Ctx | null>(null);
export const useApp = () => {
  const c = useContext(AppCtx);
  if (!c) throw new Error("AppProvider missing");
  return c;
};

const ALL_SAMPLES = [
  "dns-unanswered",
  "tcp-refused",
  "http-503",
  "dns-servfail",
  "tls-cert-expired",
  "http-504",
  "tcp-syn-blackhole",
  "http-403-waf",
  "http-502",
  "icmp-unreachable",
  "high-jitter",
  "mtu-blackhole",
  "ipv6-unanswered",
  "dns-nxdomain",
  "tcp-retrans",
  "insufficient",
];
let sampleIdx = 0;

export function AppProvider({ children }: { children: ReactNode }) {
  const inv = useAsync(() => api.list(), []);
  const health = useAsync(() => api.health(), []);
  const [sampleBusy, setBusy] = useState<string | null>(null);
  const [sampleError, setErr] = useState<string | null>(null);
  const [lastSimulatedTitle, setLastSimulatedTitle] = useState<string | null>(null);

  const loadSample = async (id: string, navigate: boolean = true) => {
    setBusy(id);
    setErr(null);
    try {
      const created = await api.loadSample(id);
      setLastSimulatedTitle(created.title);
      inv.reload();
      if (navigate) {
        go(`/investigations/${created.id}`);
      }
      return created;
    } catch (e) {
      setErr(errMessage(e));
      return null;
    } finally {
      setBusy(null);
    }
  };

  const loadNextSample = async (navigate: boolean = false) => {
    // Collect sample_ids currently in the investigations list
    const currentSampleIds = new Set(
      inv.data?.map((i) => i.sample_id).filter(Boolean) ?? []
    );

    // Pick from scenarios that are NOT already in the active investigations list
    const candidates = ALL_SAMPLES.filter((id) => !currentSampleIds.has(id));

    let nextId: string;
    if (candidates.length > 0) {
      nextId = candidates[0];
    } else {
      nextId = ALL_SAMPLES[sampleIdx % ALL_SAMPLES.length];
      sampleIdx++;
    }

    return await loadSample(nextId, navigate);
  };

  return (
    <AppCtx.Provider
      value={{
        list: inv.data ?? [],
        listLoading: inv.loading,
        listError: inv.error,
        refresh: () => {
          inv.reload();
          health.reload();
        },
        health: health.data,
        healthError: health.error,
        loadSample,
        loadNextSample,
        sampleBusy,
        sampleError,
        lastSimulatedTitle,
        clearSimulatedNotice: () => setLastSimulatedTitle(null),
      }}
    >
      {children}
    </AppCtx.Provider>
  );
}
