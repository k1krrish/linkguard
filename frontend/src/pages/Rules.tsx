import { BookOpenCheck } from "lucide-react";
import { api } from "../api";
import { EmptyState, ErrorBox, PageHeader, Panel, SkeletonBlock } from "../components/ui";
import { useAsync } from "../lib";

export function Rules() {
  const q = useAsync(() => api.rules(), []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Diagnostic Rule Catalog"
        subtitle="Formal diagnostic rules grounded in Computer Networks principles, documenting trigger criteria and diagnostic boundaries."
      />
      {q.error && <ErrorBox message={q.error} onRetry={q.reload} />}
      {q.loading && <SkeletonBlock rows={4} />}
      {q.data && q.data.length === 0 && <EmptyState icon={BookOpenCheck} title="No rules registered" />}

      <div className="grid gap-4 sm:gap-5 lg:grid-cols-2">
        {q.data?.map((r) => (
          <Panel
            key={r.rule_id}
            title={
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded border border-neuro-cyan/40 bg-neuro-cyan/10 px-2 py-0.5 font-mono text-xs font-bold text-neuro-cyan shadow-[0_0_8px_rgba(0,240,255,0.2)]">
                  [RULE // {r.rule_id}]
                </span>
                <span className="font-display font-bold text-white text-xs sm:text-sm tracking-wide">{r.title}</span>
              </div>
            }
            icon={BookOpenCheck}
          >
            <dl className="space-y-3 text-xs sm:text-sm">
              <div>
                <dt className="label font-mono text-xs uppercase !mb-1 text-slate-400">Diagnostic Purpose</dt>
                <dd className="text-slate-200 leading-relaxed font-normal">{r.description}</dd>
              </div>
              <div>
                <dt className="label font-mono text-xs uppercase !mb-1 text-neuro-cyan/80">Trigger Conditions</dt>
                <dd className="rounded-lg border border-neuro-cyan/20 bg-neuro-abyss/80 p-2.5 font-mono text-xs text-neuro-cyan">
                  {r.triggers}
                </dd>
              </div>
              <div>
                <dt className="label font-mono text-xs uppercase !mb-1 !text-neuro-amber">
                  Diagnostic Boundaries
                </dt>
                <dd className="rounded-lg border border-neuro-amber/30 bg-neuro-amber/[0.08] p-2.5 font-mono text-xs text-neuro-amber leading-relaxed font-normal">
                  {r.does_not_prove}
                </dd>
              </div>
              <div className="pt-2.5 border-t border-neuro-cyan/15 flex items-center justify-between text-xs text-slate-400 font-mono">
                <span>EVIDENCE SOURCE:</span>
                <span className="rounded border border-neuro-cyan/30 bg-neuro-cyan/10 px-2.5 py-0.5 text-neuro-cyan text-xs font-bold uppercase">
                  {r.source === "pcap" ? "PACKET CAPTURE" : "LIVE PROBE"}
                </span>
              </div>
            </dl>
          </Panel>
        ))}
      </div>
    </div>
  );
}
