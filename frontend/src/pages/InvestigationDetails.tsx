import { ArrowRight, CheckCircle2, FileText, ListChecks, Loader2, PackageSearch, Radar, Sparkles, Trash2, Upload } from "lucide-react";
import { useRef, useState } from "react";
import { api } from "../api";
import { ActivityTimeline, CheckTimingChart, CheckCard, EventList, FindingCard, ProtocolChart } from "../components/domain";
import { CheckBadge, EmptyState, ErrorBox, PageHeader, Panel, SimBadge, SkeletonBlock, Stat } from "../components/ui";
import { useApp } from "../context";
import { errMessage, fmtBytes, fmtTime, go, symptomLabel, useAsync } from "../lib";
import type { Investigation } from "../types";

function AddCapture({ inv, onDone }: { inv: Investigation; onDone: () => void }) {
  const ref = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const pick = async (f?: File) => {
    if (!f) return;
    setErr(null);
    setBusy(true);
    try {
      await api.upload(inv.id, f);
      onDone();
    } catch (e) {
      setErr(errMessage(e));
    } finally {
      setBusy(false);
      if (ref.current) ref.current.value = "";
    }
  };

  return (
    <div>
      <input
        ref={ref}
        type="file"
        accept=".pcap,.pcapng,.cap"
        className="sr-only"
        aria-label="Upload capture file"
        onChange={(e) => void pick(e.target.files?.[0])}
      />
      <button className="btn-primary" disabled={busy} onClick={() => ref.current?.click()}>
        {busy ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Parsing Frames…
          </>
        ) : (
          <>
            <Upload className="h-4 w-4" />
            Attach PCAP Capture
          </>
        )}
      </button>
      {err && (
        <div className="mt-2.5">
          <ErrorBox message={err} />
        </div>
      )}
    </div>
  );
}

export function InvestigationDetails({ id }: { id: string }) {
  const { refresh } = useApp();
  const q = useAsync(() => api.get(id), [id]);
  const [deleting, setDeleting] = useState(false);
  const [delErr, setDelErr] = useState<string | null>(null);
  const [resolving, setResolving] = useState(false);

  const handleResolve = async (invId: string) => {
    setResolving(true);
    try {
      await api.resolve(invId);
      q.reload();
      refresh();
    } finally {
      setResolving(false);
    }
  };

  if (q.loading && !q.data) {
    return (
      <div className="space-y-5">
        <PageHeader title="Loading Investigation…" />
        <SkeletonBlock rows={5} />
      </div>
    );
  }

  if (q.error || !q.data) {
    return (
      <div className="space-y-4">
        <PageHeader title="Investigation Record" />
        <ErrorBox message={q.error ?? "Investigation record not found"} onRetry={q.reload} />
        <button className="btn-ghost mt-2" onClick={() => go("/")}>
          Return to Overview
        </button>
      </div>
    );
  }

  const inv = q.data;
  const cap = inv.capture;
  const counts = { issue: 0, inconclusive: 0, ok: 0 };
  inv.findings.forEach((f) => {
    counts[f.status]++;
  });

  const remove = async () => {
    if (!window.confirm(`Are you sure you want to remove "${inv.title}"?`)) return;
    setDeleting(true);
    setDelErr(null);
    try {
      await api.remove(inv.id);
      refresh();
      go("/");
    } catch (e) {
      setDelErr(errMessage(e));
      setDeleting(false);
    }
  };

  const done = () => {
    q.reload();
    refresh();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={inv.title}
        subtitle={
          <div className="flex flex-wrap items-center gap-2 mt-1">
            <span className="rounded border border-white/[0.08] bg-white/[0.02] px-2 py-0.5 text-xs font-medium text-slate-300">
              {symptomLabel(inv.symptom)}
            </span>
            {inv.target && (
              <span className="rounded border border-neuro-cyan/40 bg-neuro-cyan/10 px-2 py-0.5 font-mono text-xs font-semibold text-neuro-cyan">
                {inv.target}
              </span>
            )}
            <span className="font-mono text-xs text-slate-400">LOGGED {fmtTime(inv.created_at)}</span>
            {inv.simulated && <SimBadge label="SIMULATED PROFILE" />}
            {inv.status === "resolved" ? (
              <span className="rounded border border-neuro-emerald/40 bg-neuro-emerald/20 px-2.5 py-0.5 font-mono text-xs font-semibold text-neuro-emerald shadow-[0_0_10px_rgba(0,255,136,0.2)]">
                RESOLVED ✓
              </span>
            ) : (
              <span className="rounded border border-white/[0.12] bg-white/[0.04] px-2.5 py-0.5 font-mono text-xs font-medium text-slate-300">
                {inv.status === "awaiting_capture" ? "AWAITING PCAP" : "ACTIVE AUDIT"}
              </span>
            )}
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            {/* Primary Action: Mark Issue Resolved / Reopen */}
            <button
              className={`btn-sm font-mono text-xs tracking-wider ${
                inv.status === "resolved"
                  ? "btn-ghost border-neuro-emerald/40 text-neuro-emerald bg-neuro-emerald/15 hover:bg-neuro-emerald/25"
                  : "btn-primary bg-gradient-to-r from-neuro-emerald to-teal-500 text-black font-bold hover:shadow-[0_0_20px_rgba(0,255,136,0.35)]"
              }`}
              onClick={() => void handleResolve(inv.id)}
              disabled={resolving}
              title={inv.status === "resolved" ? "Reopen this incident" : "Confirm and mark this issue as resolved"}
            >
              {resolving ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <CheckCircle2 className="h-3.5 w-3.5 text-black" />
              )}
              <span>{inv.status === "resolved" ? "[ RESOLVED ✓ (REOPEN) ]" : "[ MARK ISSUE RESOLVED ]"}</span>
            </button>

            {cap && (
              <button className="btn-ghost btn-sm font-mono text-xs border-neuro-cyan/40 text-neuro-cyan" onClick={() => go(`/packets/${inv.id}`)}>
                <PackageSearch className="h-3.5 w-3.5 text-neuro-cyan" />
                <span>PACKET EXPLORER</span>
              </button>
            )}
            <button className="btn-ghost btn-sm font-mono text-xs border-neuro-violet/40 text-neuro-violet" onClick={() => go(`/reports/${inv.id}`)}>
              <FileText className="h-3.5 w-3.5 text-neuro-violet" />
              <span>REPORT</span>
            </button>
            <button
              className="btn-ghost btn-sm text-slate-400 hover:text-neuro-crimson hover:border-neuro-crimson/40"
              onClick={() => void remove()}
              disabled={deleting}
              aria-label="Delete investigation"
              title="Delete and remove this investigation permanently"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        }
      />

      {delErr && (
        <div>
          <ErrorBox message={delErr} />
        </div>
      )}

      {/* Prominent Resolution Confirmation Banner */}
      {inv.status === "resolved" && (
        <div className="corner-hud relative flex flex-wrap items-center justify-between gap-3 rounded-xl border border-neuro-emerald/50 bg-neuro-abyss/90 p-4 text-neuro-emerald backdrop-blur-xl shadow-[0_0_30px_rgba(0,255,136,0.2)]">
          <div className="flex items-center gap-3">
            <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-neuro-emerald/40 bg-neuro-emerald/20 text-neuro-emerald shadow-[0_0_12px_rgba(0,255,136,0.3)]">
              <CheckCircle2 className="h-5 w-5" />
            </span>
            <div>
              <div className="font-display text-sm font-bold text-white flex items-center gap-2">
                <span>INCIDENT REMEDIATED & ARCHIVED</span>
                <span className="rounded bg-neuro-emerald/20 px-2 py-0.5 font-mono text-xs font-semibold text-neuro-emerald border border-neuro-emerald/40">
                  STATUS // RESOLVED
                </span>
              </div>
              <p className="mt-0.5 text-xs text-neuro-emerald/80 font-normal">
                Root cause verified and remediated. Front dashboard KPIs and incident status have been updated.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => go("/")}
              className="btn-ghost btn-sm font-mono text-xs border-neuro-emerald/40 text-neuro-emerald hover:text-white hover:bg-neuro-emerald/20"
            >
              [ RETURN TO DASHBOARD ]
            </button>
            <button
              onClick={() => void handleResolve(inv.id)}
              disabled={resolving}
              className="btn-ghost btn-sm font-mono text-xs text-slate-400 hover:text-slate-200"
            >
              REOPEN
            </button>
          </div>
        </div>
      )}

      {inv.simulated && (
        <div className="corner-hud relative flex items-center gap-2.5 rounded-lg border border-neuro-violet/35 bg-neuro-violet/10 px-3.5 py-2 text-xs text-neuro-violet backdrop-blur-sm">
          <Sparkles className="h-3.5 w-3.5 shrink-0 text-neuro-violet" />
          <div className="font-mono text-xs">
            <strong>[SIMULATED PROFILE]:</strong> Synthetic packets and probe telemetry generated for diagnostic validation.
          </div>
        </div>
      )}

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat
          label="Issues Identified"
          value={counts.issue}
          icon={ListChecks}
          tone={counts.issue ? "text-neuro-crimson" : "text-white"}
        />
        <Stat
          label="Inconclusive"
          value={counts.inconclusive}
          icon={ListChecks}
          tone={counts.inconclusive ? "text-amber-300" : "text-white"}
        />
        <Stat
          label="No Issue Seen"
          value={counts.ok}
          icon={ListChecks}
          tone={counts.ok ? "text-emerald-400" : "text-white"}
        />
        <Stat
          label="Evidence Items"
          value={inv.evidence.length}
          icon={Radar}
          hint={`${inv.checks.length} probe(s)${cap ? ` · ${cap.total_packets} packets` : ""}`}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        {/* Left Column (Findings & Evidence) */}
        <div className="space-y-6 xl:col-span-2">
          {/* Findings Panel */}
          <Panel title="Diagnostic Rule Findings" icon={ListChecks}>
            {inv.findings.length === 0 ? (
              <EmptyState title="No findings generated yet">
                Attach packet evidence or execute live checks to evaluate against diagnostic rules.
              </EmptyState>
            ) : (
              <div className="space-y-3">
                {inv.findings.map((f, i) => (
                  <FindingCard
                    key={f.rule_id + i}
                    f={f}
                    invId={inv.id}
                    defaultOpen={i === 0 && f.status !== "ok"}
                  />
                ))}
              </div>
            )}
          </Panel>

          {/* Live Check Results */}
          {inv.checks.length > 0 && (
            <Panel title="Live Probe Outcomes" icon={Radar}>
              <div className="grid gap-3 sm:grid-cols-2">
                {inv.checks.map((c, i) => (
                  <CheckCard key={i} c={c} />
                ))}
              </div>
              <div className="mt-5 pt-4 border-t border-white/[0.06]">
                <h3 className="label">Probe Response Latency</h3>
                <CheckTimingChart checks={inv.checks} />
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                <span className="font-semibold uppercase tracking-wider text-xs text-slate-400">Statuses:</span>
                {Array.from(new Set(inv.checks.map((c) => c.status))).map((s) => (
                  <CheckBadge key={s} status={s} />
                ))}
              </div>
            </Panel>
          )}

          {/* Packet Evidence Summary */}
          {cap ? (
            <Panel
              title="Packet Evidence Summary"
              icon={PackageSearch}
              actions={
                <button
                  className="btn-ghost btn-sm text-cyan-300 hover:text-white"
                  onClick={() => go(`/packets/${inv.id}`)}
                >
                  Explore Frame Dissections
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              }
            >
              <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
                <span className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 font-mono font-medium text-cyan-200">
                  {cap.filename ?? "capture.pcap"}
                </span>
                <span className="rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-slate-300 uppercase">
                  {cap.file_format}
                </span>
                <span className="rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-slate-300">
                  {fmtBytes(cap.file_size_bytes)}
                </span>
                <span className="rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-slate-300">
                  {cap.total_packets.toLocaleString()} frames
                </span>
                <span className="rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-slate-300">
                  {cap.duration_seconds.toFixed(2)}s capture window
                </span>
                {cap.simulated && <SimBadge label="Synthetic PCAP" />}
              </div>

              {cap.warnings.map((w) => (
                <div key={w} className="mb-3">
                  <ErrorBox message={w} />
                </div>
              ))}

              {cap.total_packets === 0 ? (
                <EmptyState title="Capture file contains zero packets" />
              ) : (
                <div className="rounded-xl border border-white/[0.06] bg-ink-950/40 p-4">
                  <ProtocolChart counts={cap.protocol_counts} />
                </div>
              )}

              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
                {[
                  ["DNS Transactions", cap.dns_transactions.length],
                  ["Unanswered DNS", cap.dns_transactions.filter((t) => !t.answered).length],
                  ["TCP Flows", cap.tcp_flows.length],
                  ["Flows with RST", cap.tcp_flows.filter((f) => f.reset_packets.length).length],
                ].map(([k, v]) => (
                  <div key={k as string} className="glass-card p-3.5 text-center">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-300">{k}</div>
                    <div className="mt-1 text-2xl font-extrabold tabular-nums text-white">{v}</div>
                  </div>
                ))}
              </div>
              <p className="mt-2.5 text-xs text-slate-400 italic">
                * Unanswered: No reply packet was observed in this capture sample.
              </p>
            </Panel>
          ) : (
            !inv.simulated &&
            inv.source !== "live" && (
              <Panel title="Packet Evidence" icon={PackageSearch}>
                <EmptyState
                  icon={Upload}
                  title="No packet capture attached"
                  action={<AddCapture inv={inv} onDone={done} />}
                >
                  Upload a .pcap or .pcapng file so the diagnostic engine can examine protocol flows and TCP flags.
                </EmptyState>
              </Panel>
            )
          )}
        </div>

        {/* Right Sidebar Column */}
        <div className="space-y-6">
          {/* Action Checklist */}
          <Panel title="Recommended Next Actions" icon={ArrowRight}>
            <ol className="space-y-3">
              {inv.next_actions.map((a, i) => (
                <li key={i} className="flex gap-3 text-xs sm:text-sm text-slate-200 leading-relaxed">
                  <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-md bg-indigo-500/20 font-mono text-xs font-bold text-indigo-300">
                    {i + 1}
                  </span>
                  <div className="flex-1 font-medium">{a}</div>
                </li>
              ))}
            </ol>
            {!cap && !inv.simulated && inv.source === "live" && (
              <div className="mt-4 border-t border-white/[0.06] pt-3">
                <p className="mb-2 text-xs text-slate-400 font-medium">Have a capture of the failing traffic?</p>
                <AddCapture inv={inv} onDone={done} />
              </div>
            )}
          </Panel>

          {/* Activity Timeline */}
          <Panel title="Investigation Timeline" icon={ListChecks}>
            <ActivityTimeline items={inv.activity} />
          </Panel>

          {/* Capture Events */}
          {cap && cap.events.length > 0 && (
            <Panel
              title="Notable Capture Events"
              icon={PackageSearch}
              actions={
                <span className="font-mono text-xs text-slate-400">
                  {cap.events.length} event(s)
                </span>
              }
            >
              <EventList events={cap.events.filter((e) => e.level !== "info")} invId={inv.id} max={8} />
              {cap.events.filter((e) => e.level !== "info").length === 0 && (
                <p className="text-xs text-slate-400">No anomalous protocol events flagged in this capture.</p>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
