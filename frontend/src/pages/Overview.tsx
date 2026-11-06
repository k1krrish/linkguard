import {
  Activity,
  AlertOctagon,
  ArrowRight,
  CheckCircle2,
  FlaskConical,
  Gauge,
  History,
  Layers,
  Library,
  Loader2,
  PackageSearch,
  PlugZap,
  RotateCcw,
  Sparkles,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import { FindingCard } from "../components/domain";
import { EmptyState, ErrorBox, PageHeader, Panel, SimBadge, SkeletonBlock, Skeleton, Stat } from "../components/ui";
import { useApp } from "../context";
import { fmtTime, go, symptomLabel, useAsync } from "../lib";

const tip = {
  background: "rgba(4, 6, 11, 0.95)",
  border: "1px solid rgba(0, 240, 255, 0.3)",
  borderRadius: 8,
  color: "#f1f5f9",
  fontSize: 12,
  fontFamily: "JetBrains Mono, monospace",
  boxShadow: "0 0 20px rgba(0, 240, 255, 0.18)",
  backdropFilter: "blur(16px)",
};

function Samples() {
  const { loadSample, sampleBusy, sampleError } = useApp();
  const s = useAsync(() => api.samples(), []);

  // Strictly show only 3 reference scenarios on the dashboard
  const displayed = s.data?.slice(0, 3);

  return (
    <Panel
      title="Reference Simulation Scenarios"
      icon={FlaskConical}
      actions={<SimBadge label="3 REFERENCE PROFILES" />}
      subtitle="Standard educational scenarios for testing packet traces and live diagnostic probes."
    >
      {s.error && <ErrorBox message={s.error} onRetry={s.reload} />}
      {s.loading && <SkeletonBlock rows={2} />}
      {sampleError && <div className="mb-3"><ErrorBox message={sampleError} /></div>}

      <div className="grid gap-4 md:grid-cols-3">
        {displayed?.map((x) => (
          <div
            key={x.id}
            className="corner-hud relative flex h-full flex-col justify-between rounded-xl border border-neuro-cyan/20 bg-neuro-card/80 p-5 group transition-all duration-200 hover:border-neuro-cyan/50 hover:shadow-[0_0_20px_rgba(0,240,255,0.18)] hover:-translate-y-0.5"
          >
            <div>
              <div className="mb-3 flex items-center justify-between">
                <span className="rounded border border-neuro-cyan/40 bg-neuro-cyan/10 px-2.5 py-0.5 font-mono text-[11px] font-bold text-neuro-cyan">
                  #{x.id}
                </span>
                <span className="rounded border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-[10px] text-slate-400 uppercase tracking-wider">
                  {symptomLabel(x.symptom).split(" ")[0]}
                </span>
              </div>
              <h3 className="font-display text-sm font-bold tracking-wide text-white group-hover:text-neuro-cyan transition-colors">
                {x.title}
              </h3>
              <p className="mt-2 text-xs text-slate-300 leading-relaxed font-normal line-clamp-3">
                {x.description}
              </p>
            </div>

            <div className="mt-4 pt-3 border-t border-neuro-cyan/15">
              <div className="mb-3 font-mono text-xs text-slate-300 leading-relaxed">
                <span className="text-neuro-cyan/80 font-bold">[CONCEPT]:</span>{" "}
                <span className="text-slate-200">{x.teaches}</span>
              </div>
              <button
                className="btn-ghost btn-sm w-full border-neuro-cyan/40 text-neuro-cyan hover:bg-neuro-cyan/15 hover:shadow-[0_0_12px_rgba(0,240,255,0.25)] font-mono text-xs"
                disabled={sampleBusy !== null}
                onClick={() => void loadSample(x.id)}
              >
                {sampleBusy === x.id ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    SIMULATING…
                  </>
                ) : (
                  <>
                    <Sparkles className="h-3.5 w-3.5 text-neuro-cyan" />
                    [ RUN SIMULATION ]
                  </>
                )}
              </button>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function FirstRun() {
  const steps = [
    {
      icon: FlaskConical,
      title: "Load Reference Scenario",
      text: "Start with an offline simulated incident to immediately inspect rule evaluations and packet headers.",
    },
    {
      icon: PlugZap,
      title: "Run Live Network Probes",
      text: "Test DNS resolution, TCP handshake completion, and HTTP status codes against public hosts.",
    },
    {
      icon: Upload,
      title: "Analyze PCAP Capture",
      text: "Upload a Wireshark capture file (.pcap/.pcapng) for in-memory protocol flow dissection.",
    },
  ];

  return (
    <Panel title="Network Detective Quickstart" icon={Gauge}>
      <ol className="grid gap-4 md:grid-cols-3">
        {steps.map((s, i) => (
          <li key={s.title} className="glass-card p-4 sm:p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-200">
              <span className="grid h-6 w-6 place-items-center rounded-md bg-indigo-500/20 font-mono text-xs text-indigo-300 font-bold">
                {i + 1}
              </span>
              <s.icon className="h-4 w-4 text-cyan-400" />
              {s.title}
            </div>
            <p className="mt-2.5 text-xs sm:text-sm text-slate-300 leading-relaxed font-normal">{s.text}</p>
          </li>
        ))}
      </ol>
      <div className="mt-4 flex gap-2">
        <button className="btn-primary" onClick={() => go("/new")}>
          <PlugZap className="h-4 w-4" />
          Start New Investigation
        </button>
      </div>
    </Panel>
  );
}

function LatestFindings({ id }: { id: string }) {
  const q = useAsync(() => api.get(id), [id]);
  if (q.loading) return <SkeletonBlock rows={2} />;
  if (q.error) return <ErrorBox message={q.error} onRetry={q.reload} />;
  const inv = q.data!;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
        <span>
          Investigation:{" "}
          <a className="font-semibold text-cyan-300 hover:underline" href={`#/investigations/${inv.id}`}>
            {inv.title}
          </a>
        </span>
        <div className="flex items-center gap-2">
          {inv.status === "resolved" && (
            <span className="rounded-md border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-xs font-semibold text-emerald-300">
              Resolved ✓
            </span>
          )}
          <span className="font-mono text-slate-400">{inv.findings.length} rule evaluation(s)</span>
        </div>
      </div>
      {inv.findings.slice(0, 3).map((f, i) => (
        <FindingCard key={f.rule_id + i} f={f} invId={inv.id} defaultOpen={i === 0} />
      ))}
      {inv.findings.length === 0 && (
        <EmptyState title="No findings generated yet">
          Attach evidence to this investigation to evaluate against diagnostic rules.
        </EmptyState>
      )}
    </div>
  );
}

export function Overview() {
  const {
    list,
    listLoading,
    listError,
    refresh,
    loadSample,
    loadNextSample,
    sampleBusy,
    lastSimulatedTitle,
    clearSimulatedNotice,
  } = useApp();
  const [tab, setTab] = useState<"active" | "solved">("active");
  const [resolvingId, setResolvingId] = useState<string | null>(null);

  // Strictly partition Active vs Solved Library
  const activeList = list.filter((i) => i.status !== "resolved");
  const solvedList = list.filter((i) => i.status === "resolved");

  // Dynamic KPI counters that strictly update in real time
  const activeCount = activeList.length;
  const solvedCount = solvedList.length;
  const activeIssues = activeList.reduce((n, i) => n + i.issue_count, 0);
  const packets = list.reduce((n, i) => n + (i.packet_total ?? 0), 0);

  // Distribution chart based on current tab view
  const currentViewList = tab === "active" ? activeList : solvedList;
  const chart = currentViewList
    .slice(0, 8)
    .reverse()
    .map((i) => ({
      name: i.title.replace("[SIMULATED] ", "").slice(0, 18),
      Issues: i.status === "resolved" ? 0 : i.issue_count,
      Inconclusive: i.inconclusive_count,
      "No issue seen": i.ok_count + (i.status === "resolved" ? i.issue_count : 0),
    }));

  const remove = async (id: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    try {
      await api.remove(id);
    } finally {
      refresh();
    }
  };

  const handleResolveToggle = async (id: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setResolvingId(id);
    try {
      await api.resolve(id);
      refresh();
    } finally {
      setResolvingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incident Operations Dashboard"
        subtitle="Automated network incident triage across DNS resolution, TCP handshakes, and packet captures."
        actions={
          <div className="flex items-center gap-2">
            <button
              className="btn-ghost btn-sm border-neuro-cyan/40 text-neuro-cyan bg-neuro-cyan/10 hover:bg-neuro-cyan/20 hover:shadow-[0_0_15px_rgba(0,240,255,0.25)] font-mono text-xs"
              disabled={sampleBusy !== null}
              onClick={() => void loadNextSample(false)}
              title="Generate a diverse network problem (cycles through 16 DNS, TCP, TLS, WAF, Gateway, and Latency scenarios)"
            >
              <Sparkles className="h-3.5 w-3.5 text-neuro-cyan" />
              <span>SIMULATE NEXT FAULT ⟳</span>
            </button>
            <button
              className="btn-ghost btn-sm border-neuro-violet/40 text-neuro-violet bg-neuro-violet/10 hover:bg-neuro-violet/20 font-mono text-xs"
              disabled={sampleBusy !== null}
              onClick={() => void loadSample("tls-cert-expired")}
              title="Load TLS certificate failure scenario"
            >
              <Activity className="h-3.5 w-3.5 text-neuro-violet" />
              <span>TLS FAULT</span>
            </button>
          </div>
        }
      />

      {/* Real-time simulation feedback banner */}
      {lastSimulatedTitle && (
        <div className="corner-hud relative flex items-center justify-between rounded-lg border border-neuro-cyan/50 bg-neuro-abyss/90 px-4 py-3 text-xs sm:text-sm text-neuro-cyan backdrop-blur-xl shadow-[0_0_25px_rgba(0,240,255,0.18)]">
          <div className="flex items-center gap-2.5">
            <Sparkles className="h-4 w-4 text-neuro-cyan shrink-0 animate-pulse" />
            <span className="font-mono text-xs">
              <span className="text-white font-bold">[SIMULATION INJECTED]:</span> <strong className="text-neuro-cyan">{lastSimulatedTitle}</strong> — Added to Active Incidents.
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              className="btn-ghost btn-sm font-mono text-xs text-neuro-cyan hover:bg-neuro-cyan/15 hover:shadow-[0_0_10px_rgba(0,240,255,0.3)]"
              onClick={() => {
                if (activeList.length > 0) go(`/investigations/${activeList[0].id}`);
              }}
            >
              [ INSPECT → ]
            </button>
            <button
              className="text-slate-400 hover:text-white p-1"
              onClick={clearSimulatedNotice}
              title="Dismiss notice"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {listError && (
        <div>
          <ErrorBox message={listError} onRetry={refresh} />
        </div>
      )}

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        {listLoading && list.length === 0 ? (
          Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-24" />)
        ) : (
          <>
            {/* Active Incidents Counter */}
            <div
              onClick={() => setTab("active")}
              className={`h-full cursor-pointer rounded-xl transition-all ${
                tab === "active" ? "ring-1 ring-neuro-cyan shadow-[0_0_20px_rgba(0,240,255,0.25)]" : "hover:brightness-105"
              }`}
            >
              <Stat
                label="Active Incidents"
                value={activeCount}
                icon={Layers}
                tone={activeCount > 0 ? "text-neuro-cyan" : "text-neuro-emerald"}
                hint={`${solvedCount} solved · ${activeCount} active`}
              />
            </div>

            {/* Active Issues Counter (Decreases when issues are resolved) */}
            <div className="h-full">
              <Stat
                label="Active Issues"
                value={activeIssues}
                icon={AlertOctagon}
                tone={activeIssues > 0 ? "text-neuro-crimson" : "text-neuro-emerald"}
                hint={
                  solvedCount > 0
                    ? `${activeIssues} remaining (${solvedCount} incident(s) solved)`
                    : "from rule evaluations"
                }
              />
            </div>

            {/* Library of Solved Issues Counter */}
            <div
              onClick={() => setTab("solved")}
              className={`h-full cursor-pointer rounded-xl transition-all ${
                tab === "solved" ? "ring-1 ring-neuro-emerald shadow-[0_0_20px_rgba(0,255,136,0.25)]" : "hover:brightness-105"
              }`}
            >
              <Stat
                label="Library of Solved Issues"
                value={solvedCount}
                icon={CheckCircle2}
                tone="text-neuro-emerald"
                hint={solvedCount > 0 ? "Click to view solved history" : "Archived & verified"}
              />
            </div>

            {/* Packets Inspected */}
            <div className="h-full">
              <Stat
                label="Packets Inspected"
                value={packets.toLocaleString()}
                icon={PackageSearch}
                hint="across PCAP captures"
              />
            </div>
          </>
        )}
      </div>

      {list.length === 0 && !listLoading && !listError && (
        <div>
          <FirstRun />
        </div>
      )}

      {/* Main Workbench Grid */}
      {list.length > 0 && (
        <div className="grid gap-6 xl:grid-cols-5">
          {/* Main Investigations & Solved Library Section */}
          <div className="xl:col-span-3 space-y-4">
            {/* Segmented View Switcher Tabs */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-neuro-cyan/15 pb-3">
              <div className="inline-flex items-center p-1 rounded-xl bg-neuro-abyss/90 border border-neuro-cyan/20 shadow-inner backdrop-blur-md">
                <button
                  onClick={() => setTab("active")}
                  className={`flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-mono font-semibold transition-all ${
                    tab === "active"
                      ? "bg-neuro-cyan/15 text-neuro-cyan border border-neuro-cyan/40 shadow-[0_0_12px_rgba(0,240,255,0.2)]"
                      : "text-slate-400 hover:text-slate-200 border border-transparent"
                  }`}
                >
                  <Layers className="h-3.5 w-3.5 text-neuro-cyan" />
                  <span>ACTIVE INCIDENTS</span>
                  <span
                    className={`ml-1 rounded px-1.5 py-0.5 text-[10px] font-mono font-bold ${
                      activeCount > 0 ? "bg-neuro-crimson/20 text-neuro-crimson border border-neuro-crimson/30" : "bg-neuro-emerald/20 text-neuro-emerald border border-neuro-emerald/30"
                    }`}
                  >
                    {activeCount}
                  </span>
                </button>

                <button
                  onClick={() => setTab("solved")}
                  className={`flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-mono font-semibold transition-all ${
                    tab === "solved"
                      ? "bg-neuro-emerald/15 text-neuro-emerald border border-neuro-emerald/40 shadow-[0_0_12px_rgba(0,255,136,0.2)]"
                      : "text-slate-400 hover:text-slate-200 border border-transparent"
                  }`}
                >
                  <Library className="h-3.5 w-3.5 text-neuro-emerald" />
                  <span>LIBRARY OF SOLVED ISSUES</span>
                  <span className="ml-1 rounded bg-neuro-emerald/20 px-1.5 py-0.5 text-[10px] font-mono font-bold text-neuro-emerald border border-neuro-emerald/30">
                    {solvedCount}
                  </span>
                </button>
              </div>

              <div className="text-xs font-mono text-slate-400 hidden sm:flex items-center gap-2 font-medium">
                <span className={`h-1.5 w-1.5 rounded-full ${tab === "active" ? "bg-neuro-cyan animate-pulse shadow-[0_0_6px_#00f0ff]" : "bg-neuro-emerald"}`} />
                <span>{tab === "active" ? "[FORENSIC // ACTIVE AUDIT]" : "[ARCHIVED // VERIFIED]"}</span>
              </div>
            </div>

            {/* TAB 1: ACTIVE INCIDENTS */}
            {tab === "active" && (
              <Panel
                title="Active Network Incidents"
                icon={Layers}
                subtitle="Live and simulated incidents pending resolution. Resolved issues are removed to the Solved Library."
                pad={false}
              >
                {activeList.length === 0 ? (
                  <div className="p-8 text-center space-y-3">
                    <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl bg-neuro-emerald/15 text-neuro-emerald border border-neuro-emerald/40 shadow-[0_0_20px_rgba(0,255,136,0.2)]">
                      <CheckCircle2 className="h-6 w-6" />
                    </div>
                    <h3 className="font-display text-base font-bold text-white tracking-wide">All Incident Queries Resolved!</h3>
                    <p className="mx-auto max-w-md text-xs sm:text-sm text-slate-300 leading-relaxed font-normal">
                      Zero active incidents remain on the main dashboard. All previous queries have been resolved,
                      verified, and safely archived in the Library of Solved Issues.
                    </p>
                    <div className="pt-2 flex justify-center gap-3">
                      <button
                        className="btn-ghost btn-sm border-neuro-emerald/40 text-neuro-emerald font-mono text-xs"
                        onClick={() => setTab("solved")}
                      >
                        <Library className="h-3.5 w-3.5" />
                        [ SOLVED LIBRARY ({solvedCount}) ]
                      </button>
                      <button
                        className="btn-primary btn-sm font-mono text-xs"
                        disabled={sampleBusy !== null}
                        onClick={() => void loadNextSample()}
                      >
                        <Sparkles className="h-3.5 w-3.5" />
                        SIMULATE NEXT FAULT ⟳
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="relative overflow-x-auto">
                    <table className="w-full min-w-[34rem]">
                      <thead>
                        <tr className="border-b border-neuro-cyan/15 bg-neuro-surface/40">
                          <th className="th">Incident Title</th>
                          <th className="th">Source</th>
                          <th className="th">Diagnostic State</th>
                          <th className="th">Created</th>
                          <th className="th text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-neuro-cyan/10">
                        {activeList.slice(0, 10).map((i) => (
                          <tr key={i.id} className="transition-colors hover:bg-neuro-cyan/[0.04]">
                            <td className="td">
                              <a
                                href={`#/investigations/${i.id}`}
                                className="font-semibold text-white hover:text-neuro-cyan transition-colors focus-visible:outline-none"
                              >
                                {i.title}
                              </a>
                              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                                <span className="text-slate-300 font-medium">{symptomLabel(i.symptom)}</span>
                                {i.target ? (
                                  <span className="rounded border border-neuro-cyan/30 bg-neuro-cyan/10 px-1.5 py-0.5 font-mono text-neuro-cyan text-[11px]">
                                    {i.target}
                                  </span>
                                ) : null}
                              </div>
                            </td>
                            <td className="td whitespace-nowrap">
                              <div className="flex items-center gap-2">
                                <span className="rounded border border-white/[0.10] bg-white/[0.03] px-2 py-0.5 font-mono text-xs text-slate-300 uppercase">
                                  {i.source}
                                </span>
                                {i.simulated && <SimBadge />}
                              </div>
                            </td>
                            <td className="td whitespace-nowrap">
                              <div className="flex items-center gap-2">
                                {i.issue_count > 0 ? (
                                  <span className="inline-flex items-center gap-1.5 rounded border border-neuro-crimson/40 bg-neuro-crimson/15 px-2.5 py-1 font-mono text-xs font-semibold text-neuro-crimson shadow-[0_0_10px_rgba(255,0,85,0.2)]">
                                    <span className="h-1.5 w-1.5 rounded-full bg-neuro-crimson animate-pulse" />
                                    {i.issue_count} {i.issue_count === 1 ? "FAULT" : "FAULTS"}
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1.5 rounded border border-neuro-emerald/40 bg-neuro-emerald/15 px-2.5 py-1 font-mono text-xs font-semibold text-neuro-emerald">
                                    <span className="h-1.5 w-1.5 rounded-full bg-neuro-emerald" />
                                    CLEAN
                                  </span>
                                )}
                                {i.inconclusive_count > 0 && (
                                  <span className="inline-flex items-center gap-1.5 rounded border border-neuro-amber/40 bg-neuro-amber/15 px-2 py-0.5 font-mono text-xs font-semibold text-neuro-amber">
                                    <span className="h-1.5 w-1.5 rounded-full bg-neuro-amber" />
                                    {i.inconclusive_count} INC
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="td whitespace-nowrap font-mono text-xs text-slate-400">
                              {fmtTime(i.created_at)}
                            </td>
                            <td className="td text-right whitespace-nowrap">
                              <div className="flex items-center justify-end gap-1.5">
                                {/* 1-Click Resolve button */}
                                <button
                                  className="btn-ghost btn-sm border-neuro-emerald/40 text-neuro-emerald bg-neuro-emerald/10 hover:bg-neuro-emerald/20 hover:shadow-[0_0_12px_rgba(0,255,136,0.3)] font-mono text-xs"
                                  disabled={resolvingId === i.id}
                                  onClick={(e) => void handleResolveToggle(i.id, e)}
                                  title="Mark this issue resolved and move to Solved Library"
                                >
                                  {resolvingId === i.id ? (
                                    <Loader2 className="h-3 w-3 animate-spin" />
                                  ) : (
                                    <CheckCircle2 className="h-3 w-3 text-neuro-emerald" />
                                  )}
                                  <span>[ RESOLVE ✓ ]</span>
                                </button>
                                <button
                                  className="btn-ghost btn-sm text-neuro-cyan hover:text-white font-mono text-xs"
                                  onClick={() => go(`/investigations/${i.id}`)}
                                >
                                  OPEN
                                </button>
                                <button
                                  className="btn-ghost btn-sm text-slate-400 hover:text-neuro-crimson hover:border-neuro-crimson/40"
                                  aria-label={`Delete ${i.title}`}
                                  onClick={(e) => void remove(i.id, e)}
                                  title="Delete investigation permanently"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
            )}

            {/* TAB 2: LIBRARY OF SOLVED ISSUES */}
            {tab === "solved" && (
              <Panel
                title="Library of Solved Issues"
                icon={Library}
                subtitle="Historical repository of resolved network queries and remediated incidents."
                actions={
                  <span className="rounded border border-neuro-emerald/40 bg-neuro-emerald/15 px-2.5 py-0.5 font-mono text-xs font-semibold text-neuro-emerald">
                    {solvedCount} RESOLVED RECORDS
                  </span>
                }
                pad={false}
              >
                {solvedList.length === 0 ? (
                  <div className="p-8 text-center space-y-3">
                    <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl bg-white/[0.04] text-slate-400 border border-white/[0.08]">
                      <Library className="h-6 w-6" />
                    </div>
                    <h3 className="font-display text-base font-bold text-white tracking-wide">Library is Currently Empty</h3>
                    <p className="mx-auto max-w-md text-xs sm:text-sm text-slate-300 leading-relaxed font-normal">
                      When you resolve an incident using the "Mark Issue Resolved" button, it will automatically
                      be stored here in the Solved Library to keep your active dashboard clean.
                    </p>
                    <div className="pt-2">
                      <button className="btn-ghost btn-sm font-mono text-xs" onClick={() => setTab("active")}>
                        [ RETURN TO ACTIVE INCIDENTS ]
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="relative overflow-x-auto">
                    <table className="w-full min-w-[34rem]">
                      <thead>
                        <tr className="border-b border-neuro-cyan/15 bg-neuro-surface/40">
                          <th className="th">Remediated Incident</th>
                          <th className="th">Symptom & Target</th>
                          <th className="th">Resolution Status</th>
                          <th className="th">Logged</th>
                          <th className="th text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-neuro-cyan/10">
                        {solvedList.map((i) => (
                          <tr key={i.id} className="transition-colors hover:bg-neuro-emerald/[0.04]">
                            <td className="td">
                              <a
                                href={`#/investigations/${i.id}`}
                                className="font-semibold text-white hover:text-neuro-emerald transition-colors focus-visible:outline-none"
                              >
                                {i.title}
                              </a>
                              <div className="mt-1 flex items-center gap-2 font-mono text-xs text-slate-400">
                                <span>ID: {i.id}</span>
                                {i.simulated && <SimBadge />}
                              </div>
                            </td>
                            <td className="td whitespace-nowrap">
                              <div className="text-xs">
                                <div className="text-slate-300 font-medium">{symptomLabel(i.symptom)}</div>
                                {i.target && (
                                  <div className="font-mono text-neuro-cyan mt-0.5">{i.target}</div>
                                )}
                              </div>
                            </td>
                            <td className="td whitespace-nowrap">
                              <span className="inline-flex items-center gap-1.5 rounded border border-neuro-emerald/40 bg-neuro-emerald/20 px-2.5 py-1 font-mono text-xs font-semibold text-neuro-emerald shadow-[0_0_12px_rgba(0,255,136,0.25)]">
                                <CheckCircle2 className="h-3.5 w-3.5 text-neuro-emerald" />
                                REMEDIATED ✓
                              </span>
                            </td>
                            <td className="td whitespace-nowrap font-mono text-xs text-slate-400">
                              {fmtTime(i.created_at)}
                            </td>
                            <td className="td text-right whitespace-nowrap">
                              <div className="flex items-center justify-end gap-1.5">
                                <button
                                  className="btn-ghost btn-sm text-neuro-cyan hover:text-white font-mono text-xs"
                                  onClick={() => go(`/investigations/${i.id}`)}
                                  title="View complete incident history and audit timeline"
                                >
                                  <History className="h-3.5 w-3.5" />
                                  <span>AUDIT</span>
                                </button>
                                <button
                                  className="btn-ghost btn-sm text-neuro-amber hover:border-neuro-amber/40 font-mono text-xs"
                                  disabled={resolvingId === i.id}
                                  onClick={(e) => void handleResolveToggle(i.id, e)}
                                  title="Reopen and return to active dashboard"
                                >
                                  {resolvingId === i.id ? (
                                    <Loader2 className="h-3 w-3 animate-spin" />
                                  ) : (
                                    <RotateCcw className="h-3 w-3" />
                                  )}
                                  <span>REOPEN</span>
                                </button>
                                <button
                                  className="btn-ghost btn-sm text-slate-400 hover:text-neuro-crimson hover:border-neuro-crimson/40"
                                  aria-label={`Delete record ${i.title}`}
                                  onClick={(e) => void remove(i.id, e)}
                                  title="Delete record permanently"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
            )}
          </div>

          {/* Outcome Distribution Chart */}
          <div className="xl:col-span-2 space-y-4">
            <Panel
              title={tab === "active" ? "Active Findings Distribution" : "Solved Issues Findings"}
              icon={Gauge}
            >
              <div
                className="h-64 sm:h-72"
                role="img"
                aria-label="Stacked bar chart of findings per investigation"
              >
                {currentViewList.length === 0 ? (
                  <div className="h-full grid place-items-center text-xs text-slate-400">
                    No investigations to plot in this view.
                  </div>
                ) : (
                  <ResponsiveContainer>
                    <BarChart data={chart} margin={{ top: 8, right: 8, left: -22, bottom: 20 }}>
                      <CartesianGrid stroke="rgba(0, 240, 255, 0.08)" vertical={false} />
                      <XAxis
                        dataKey="name"
                        tick={{ fill: "#94a3b8", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }}
                        axisLine={false}
                        tickLine={false}
                        interval={0}
                        angle={-22}
                        textAnchor="end"
                        height={45}
                      />
                      <YAxis
                        allowDecimals={false}
                        tick={{ fill: "#94a3b8", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <Tooltip contentStyle={tip} cursor={{ fill: "rgba(0, 240, 255, 0.04)" }} />
                      <Legend wrapperStyle={{ fontSize: 11, fontFamily: "JetBrains Mono, monospace", color: "#cbd5e1", paddingTop: 8 }} />
                      <Bar dataKey="Issues" stackId="a" fill="#ff0055" />
                      <Bar dataKey="Inconclusive" stackId="a" fill="#ffaa00" />
                      <Bar dataKey="No issue seen" stackId="a" fill="#00ff88" radius={[2, 2, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </Panel>
          </div>
        </div>
      )}

      {/* Latest Findings Preview */}
      {list.length > 0 && (
        <div>
          <Panel
            title={activeList.length > 0 ? "Active Diagnostic Findings" : "Most Recent Remediated Findings"}
            icon={AlertOctagon}
            actions={
              <button
                className="btn-ghost btn-sm text-xs"
                onClick={() => go(`/investigations/${(activeList[0] ?? solvedList[0]).id}`)}
              >
                Inspect All Findings
                <ArrowRight className="h-3 w-3" />
              </button>
            }
          >
            <LatestFindings id={(activeList[0] ?? solvedList[0]).id} />
          </Panel>
        </div>
      )}

      {/* Reference Scenarios Grid */}
      <Samples />
    </div>
  );
}