import { Download, FileJson, FileSpreadsheet, FileText, Printer, Sparkles } from "lucide-react";
import { api } from "../api";
import { FindingCard } from "../components/domain";
import { CheckBadge, EmptyState, ErrorBox, PageHeader, Panel, SimBadge, SkeletonBlock } from "../components/ui";
import { useApp } from "../context";
import { fmtMs, fmtTime, go, symptomLabel, useAsync } from "../lib";

function Picker() {
  const { list, listLoading, listError, refresh, loadSample } = useApp();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Diagnostic Incident Reports"
        subtitle="Comprehensive incident records with probe outcomes, packet traces, and rule evaluations."
      />
      {listError && <ErrorBox message={listError} onRetry={refresh} />}
      {listLoading && list.length === 0 && <SkeletonBlock rows={3} />}
      {!listLoading && !listError && list.length === 0 && (
        <Panel>
          <EmptyState
            icon={FileText}
            title="No investigations logged yet"
            action={
              <div className="flex gap-2.5">
                <button className="btn-primary" onClick={() => void loadSample("dns-unanswered")}>
                  <Sparkles className="h-4 w-4" />
                  Load Reference Report
                </button>
                <button className="btn-ghost" onClick={() => go("/new")}>
                  New Investigation
                </button>
              </div>
            }
          >
            Execute an investigation or load an educational reference scenario to generate exportable diagnostic reports.
          </EmptyState>
        </Panel>
      )}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {list.map((i) => (
          <button
            key={i.id}
            onClick={() => go(`/reports/${i.id}`)}
            className="corner-hud relative flex flex-col justify-between rounded-xl border border-neuro-cyan/20 bg-neuro-card/85 p-5 text-left transition-all duration-150 hover:border-neuro-cyan/50 hover:shadow-[0_0_20px_rgba(0,240,255,0.2)] hover:-translate-y-0.5 focus-visible:outline-none group"
          >
            <div>
              <div className="mb-3 flex items-center justify-between">
                <span className="grid h-8 w-8 place-items-center rounded-lg border border-neuro-cyan/40 bg-neuro-cyan/10 text-neuro-cyan shadow-[0_0_10px_rgba(0,240,255,0.2)]">
                  <FileText className="h-4 w-4" />
                </span>
                {i.simulated && <SimBadge />}
              </div>
              <div className="font-display font-bold text-white group-hover:text-neuro-cyan transition-colors text-sm sm:text-base tracking-wide">
                {i.title}
              </div>
              <div className="mt-1 font-mono text-xs text-slate-400">
                {symptomLabel(i.symptom)} · {fmtTime(i.created_at)}
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2 text-xs border-t border-neuro-cyan/15 pt-2.5 font-mono">
              {i.issue_count > 0 ? (
                <span className="inline-flex items-center gap-1 rounded border border-neuro-crimson/40 bg-neuro-crimson/15 px-2 py-0.5 font-semibold text-neuro-crimson shadow-[0_0_8px_rgba(255,0,85,0.2)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-neuro-crimson" />
                  {i.issue_count} {i.issue_count === 1 ? "FAULT" : "FAULTS"}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded border border-neuro-emerald/40 bg-neuro-emerald/15 px-2 py-0.5 font-semibold text-neuro-emerald">
                  <span className="h-1.5 w-1.5 rounded-full bg-neuro-emerald" />
                  CLEAN
                </span>
              )}
              {i.inconclusive_count > 0 && (
                <span className="text-neuro-amber font-semibold">· {i.inconclusive_count} INC</span>
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

export function Reports({ id }: { id?: string }) {
  const { list } = useApp();
  if (!id) return <Picker />;
  return <ReportView id={id} others={list} />;
}

function ReportView({ id, others }: { id: string; others: ReturnType<typeof useApp>["list"] }) {
  const q = useAsync(() => api.report(id), [id]);
  if (q.loading && !q.data) {
    return (
      <div className="space-y-6">
        <PageHeader title="Generating Diagnostic Report…" />
        <SkeletonBlock rows={5} />
      </div>
    );
  }
  if (q.error || !q.data) {
    return (
      <div className="space-y-4">
        <PageHeader title="Diagnostic Report" />
        <ErrorBox message={q.error ?? "Report record not found"} onRetry={q.reload} />
        <button className="btn-ghost mt-2" onClick={() => go("/reports")}>
          Return to Reports Index
        </button>
      </div>
    );
  }

  const r = q.data;
  const pe = r.packet_evidence;

  return (
    <div className="print-area space-y-6">
      <PageHeader
        title={r.title}
        subtitle={
          <div className="flex flex-wrap items-center gap-2 mt-1">
            <span>Investigation Evidence Report</span>
            <span>· Generated {fmtTime(r.generated_at)}</span>
            {r.simulated && <SimBadge label="Simulated Data" />}
          </div>
        }
        actions={
          <div className="flex items-center gap-2 font-mono text-xs">
            <select
              aria-label="Select report"
              className="field w-auto h-7.5 py-0 px-2.5 text-xs font-semibold"
              value={id}
              onChange={(e) => go(`/reports/${e.target.value}`)}
            >
              {others.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.title.slice(0, 48)}
                </option>
              ))}
              {!others.some((o) => o.id === id) && <option value={id}>{r.title.slice(0, 48)}</option>}
            </select>
            <a className="btn-ghost btn-sm border-neuro-cyan/40 text-neuro-cyan hover:bg-neuro-cyan/15" href={api.reportUrl(id, "json")} download>
              <FileJson className="h-3.5 w-3.5 text-neuro-cyan" />
              JSON
            </a>
            <a className="btn-ghost btn-sm border-neuro-violet/40 text-neuro-violet hover:bg-neuro-violet/15" href={api.reportUrl(id, "csv")} download>
              <FileSpreadsheet className="h-3.5 w-3.5 text-neuro-violet" />
              CSV
            </a>
            <button className="btn-primary btn-sm font-mono text-xs" onClick={() => window.print()}>
              <Printer className="h-3.5 w-3.5" />
              PRINT / PDF
            </button>
          </div>
        }
      />

      <div className="space-y-6">
        {/* Executive Summary */}
        <Panel title="Executive Summary" icon={FileText}>
          <p className="text-sm sm:text-base leading-relaxed text-slate-100 font-normal">{r.summary}</p>
          <dl className="mt-4 grid gap-3.5 rounded-lg border border-neuro-cyan/20 bg-neuro-abyss/80 p-4 text-xs sm:text-sm sm:grid-cols-2 lg:grid-cols-4 font-mono">
            <div>
              <dt className="text-xs font-bold uppercase tracking-wider text-slate-400">Reported Symptom</dt>
              <dd className="mt-1 font-semibold text-slate-200">{symptomLabel(r.symptom)}</dd>
            </div>
            <div>
              <dt className="text-xs font-bold uppercase tracking-wider text-slate-400">Target Endpoint</dt>
              <dd className="mt-1 text-neuro-cyan font-bold">{r.target ?? "Capture Only (No Live Host)"}</dd>
            </div>
            <div>
              <dt className="text-xs font-bold uppercase tracking-wider text-slate-400">Evidence Source</dt>
              <dd className="mt-1 text-slate-200 uppercase">{r.source}</dd>
            </div>
            <div>
              <dt className="text-xs font-bold uppercase tracking-wider text-slate-400">Findings Breakdown</dt>
              <dd className="mt-1 text-xs flex gap-2">
                <span className="text-neuro-crimson font-bold">{r.status_counts.issue} FAULT</span>
                <span className="text-neuro-amber font-bold">{r.status_counts.inconclusive} INC</span>
                <span className="text-neuro-emerald font-bold">{r.status_counts.ok} OK</span>
              </dd>
            </div>
          </dl>
        </Panel>

        {/* Test Outcomes */}
        <Panel title="Live Probe Outcomes" icon={Download} pad={false}>
          {r.test_outcomes.length === 0 ? (
            <EmptyState title="No live probe checks were executed for this investigation" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[34rem]">
                <thead>
                  <tr className="border-b border-white/[0.07] bg-white/[0.015]">
                    <th className="th">Probe</th>
                    <th className="th">Target Endpoint</th>
                    <th className="th">Result Status</th>
                    <th className="th">Response Latency</th>
                    <th className="th">Observed Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {r.test_outcomes.map((t, i) => (
                    <tr key={i} className="hover:bg-white/[0.02]">
                      <td className="td font-bold uppercase text-slate-200">{t.check}</td>
                      <td className="td font-mono text-xs text-cyan-200">{t.target}</td>
                      <td className="td">
                        <CheckBadge status={t.status} />
                      </td>
                      <td className="td font-mono text-xs text-slate-300">{fmtMs(t.elapsed_ms)}</td>
                      <td className="td text-slate-200">
                        {t.message}
                        {t.simulated && <span className="ml-2"><SimBadge /></span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* Packet Evidence */}
        {pe && (
          <Panel title="Packet Analysis Evidence" icon={FileText}>
            <dl className="grid gap-3 rounded-lg border border-white/[0.06] bg-ink-950/50 p-3.5 text-xs sm:grid-cols-3 lg:grid-cols-6">
              {[
                ["Filename", pe.filename ?? "-"],
                ["Format", pe.file_format.toUpperCase()],
                ["Total Frames", pe.total_packets.toLocaleString()],
                ["Capture Window", `${pe.duration_seconds.toFixed(2)}s`],
                ["DNS Unanswered", `${pe.dns_unanswered} / ${pe.dns_transactions}`],
                ["Flows with RST", `${pe.tcp_flows_with_reset} / ${pe.tcp_flows}`],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt className="text-xs font-semibold uppercase tracking-wider text-slate-400">{k}</dt>
                  <dd className="mt-0.5 break-all font-mono text-xs font-semibold text-slate-200">{v}</dd>
                </div>
              ))}
            </dl>
            <p className="mt-3 text-xs text-slate-300">
              Protocols: {Object.entries(pe.protocol_counts).map(([k, v]) => `${k} (${v})`).join(", ") || "None"} · TCP segment retransmissions: {pe.tcp_retransmission_packets}
            </p>
            {pe.warnings.map((w) => (
              <p key={w} className="mt-2 text-xs text-amber-300 font-medium">
                Warning: {w}
              </p>
            ))}
            {pe.notable_events.length > 0 && (
              <div className="mt-3 pt-3 border-t border-white/[0.05]">
                <h4 className="label">Notable Capture Events</h4>
                <ul className="space-y-1 text-xs text-slate-300 font-mono">
                  {pe.notable_events.slice(0, 10).map((e, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="text-indigo-300">#{e.packet} (+{e.rel_time.toFixed(3)}s)</span>
                      <span className="text-slate-200">{e.description}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Panel>
        )}

        {/* Diagnostic Findings */}
        <Panel title="Diagnostic Rule Findings" icon={FileText}>
          {r.findings.length === 0 ? (
            <EmptyState title="No findings generated">
              No evidence was provided to trigger rules.
            </EmptyState>
          ) : (
            <div className="space-y-3">
              {r.findings.map((f, i) => (
                <FindingCard key={f.rule_id + i} f={f} invId={id} defaultOpen />
              ))}
            </div>
          )}
        </Panel>

        {/* Limitations & Next Steps */}
        <div className="grid gap-6 lg:grid-cols-2">
          <Panel title="Diagnostic Boundaries" icon={FileText}>
            <ul className="list-disc space-y-1.5 pl-4 text-xs sm:text-sm text-slate-200 marker:text-amber-400 leading-relaxed">
              {r.limitations.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </Panel>
          <Panel title="Recommended Next Actions" icon={FileText}>
            <ol className="list-decimal space-y-1.5 pl-4 text-xs sm:text-sm text-slate-200 marker:text-cyan-400 leading-relaxed">
              {r.next_steps.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ol>
          </Panel>
        </div>

        {/* Evidence Index Table */}
        <Panel title={`Evidence Index (${r.evidence_index.length} records)`} icon={FileText} pad={false}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[34rem]">
              <thead>
                <tr className="border-b border-white/[0.07] bg-white/[0.015]">
                  <th className="th">Evidence ID</th>
                  <th className="th">Category</th>
                  <th className="th">Source</th>
                  <th className="th">Summary Observation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {r.evidence_index.map((e) => (
                  <tr key={e.id} className="hover:bg-white/[0.02]">
                    <td className="td font-mono font-bold text-xs text-indigo-300">{e.id}</td>
                    <td className="td font-mono text-xs text-slate-300">{e.kind}</td>
                    <td className="td text-xs">
                      <span className="capitalize">{e.source === "pcap" ? "Capture" : "Live Probe"}</span>
                      {e.simulated && <span className="ml-1.5"><SimBadge /></span>}
                    </td>
                    <td className="td text-slate-200">{e.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
