import { Activity, ChevronDown, Globe, Network, PlugZap, ShieldCheck, FileSearch, ListChecks, Link2, Sparkles } from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtClock, fmtMs, fmtRel, go } from "../lib";
import type { ActivityEntry, CaptureSummary, CheckResult, Finding, TimelineEvent } from "../types";
import { CheckBadge, FindingBadge, Mono, SeverityTag, SimBadge } from "./ui";

/* ---------- findings ---------- */
function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <h4 className="font-mono text-[11px] font-bold uppercase tracking-wider text-neuro-cyan/90">{title}</h4>
      <div className="text-xs sm:text-sm leading-relaxed text-slate-100 font-medium">{children}</div>
    </div>
  );
}

export function FindingCard({ f, invId, defaultOpen = false }: { f: Finding; invId?: string; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);

  const edge =
    f.status === "issue"
      ? "before:bg-neuro-crimson before:shadow-[-2px_0_12px_rgba(255,0,85,0.6)]"
      : f.status === "inconclusive"
      ? "before:bg-neuro-amber before:shadow-[-2px_0_12px_rgba(255,170,0,0.6)]"
      : "before:bg-neuro-emerald before:shadow-[-2px_0_12px_rgba(0,255,136,0.6)]";

  return (
    <article className={`corner-hud relative overflow-hidden rounded-xl border border-neuro-cyan/20 bg-neuro-card/85 transition-all duration-150 before:absolute before:inset-y-0 before:left-0 before:w-1 ${edge} hover:border-neuro-cyan/40 hover:shadow-[0_0_20px_rgba(0,240,255,0.12)]`}>
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-start justify-between gap-3 px-4 py-4 sm:px-5 text-left focus-visible:outline-none"
      >
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <FindingBadge status={f.status} />
            <SeverityTag severity={f.severity} />
            <span className="rounded border border-neuro-cyan/35 bg-neuro-cyan/10 px-2 py-0.5 font-mono text-[11px] font-bold text-neuro-cyan">
              [RULE // {f.rule_id}]
            </span>
            <span className="font-mono text-xs text-slate-400">
              {f.source === "pcap" ? "PACKET CAPTURE" : "LIVE PROBE"}
            </span>
            {f.simulated && <SimBadge />}
          </div>
          <h3 className="font-display text-sm sm:text-base font-bold text-white tracking-wide">{f.title}</h3>
          {!open && <p className="mt-1.5 line-clamp-2 text-xs sm:text-sm text-slate-300 leading-relaxed font-normal">{f.observed}</p>}
        </div>
        <div className="mt-1 grid h-7 w-7 place-items-center rounded border border-neuro-cyan/30 bg-neuro-cyan/5 text-neuro-cyan">
          <ChevronDown className={`h-4 w-4 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
        </div>
      </button>

      {open && (
        <div className="space-y-4 border-t border-neuro-cyan/15 bg-neuro-abyss/60 px-4 py-4 sm:px-5 sm:py-5">
          <Section title="[ OBSERVED EVIDENCE ]">{f.observed}</Section>
          <Section title="[ TECHNICAL INTERPRETATION ]">{f.interpretation}</Section>

          {f.limitations.length > 0 && (
            <Section title="[ DIAGNOSTIC BOUNDARIES ]">
              <ul className="list-disc space-y-1.5 pl-4 marker:text-neuro-amber text-slate-300 text-xs sm:text-sm leading-relaxed">
                {f.limitations.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </Section>
          )}

          {f.alternatives.length > 0 && (
            <Section title="[ ALTERNATIVE EXPLANATIONS ]">
              <ul className="list-disc space-y-1.5 pl-4 marker:text-neuro-cyan text-slate-300 text-xs sm:text-sm leading-relaxed">
                {f.alternatives.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </Section>
          )}

          <div className="rounded-xl border border-neuro-cyan/30 bg-neuro-cyan/[0.06] p-3.5 backdrop-blur-sm shadow-[0_0_15px_rgba(0,240,255,0.06)]">
            <div className="mb-1 flex items-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider text-neuro-cyan">
              <Sparkles className="h-3.5 w-3.5 text-neuro-cyan" />
              [ REMEDIATION // RECOMMENDED NEXT TEST ]
            </div>
            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-normal">{f.next_test}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-neuro-cyan/15">
            <span className="font-mono text-xs font-semibold text-slate-400 mr-1">EVIDENCE INDEX:</span>
            {f.evidence_refs.map((e) => (
              <span key={e} className="rounded border border-neuro-cyan/25 bg-neuro-cyan/5 px-2 py-0.5 font-mono text-xs text-neuro-cyan/90">
                {e}
              </span>
            ))}
            {invId &&
              f.packet_refs.slice(0, 10).map((p) => (
                <button
                  key={p}
                  onClick={() => go(`/packets/${invId}?sel=${p}`)}
                  title={`Inspect packet frame #${p}`}
                  className="inline-flex items-center gap-1 rounded border border-neuro-cyan/40 bg-neuro-cyan/10 px-2 py-0.5 font-mono text-xs text-neuro-cyan hover:bg-neuro-cyan/20 transition-colors"
                >
                  <Link2 className="h-3 w-3" />
                  frame #{p}
                </button>
              ))}
            {f.packet_refs.length > 10 && (
              <span className="font-mono text-xs text-slate-400">+{f.packet_refs.length - 10} more</span>
            )}
          </div>
        </div>
      )}
    </article>
  );
}

/* ---------- live checks ---------- */
const KIND_ICON = { dns: Globe, tcp: PlugZap, http: Network } as const;

function factsFor(c: CheckResult): [string, string][] {
  const d = c.details as Record<string, unknown>;
  const out: [string, string][] = [];
  if (Array.isArray(d.addresses) && d.addresses.length) out.push(["Resolved IP(s)", d.addresses.slice(0, 4).join(", ")]);
  if (d.status_code) out.push(["HTTP Status", `${d.status_code} ${String(d.reason ?? "")}`.trim()]);
  if (d.http_version) out.push(["HTTP Version", String(d.http_version)]);
  if (d.tls_version) out.push(["TLS Protocol", String(d.tls_version)]);
  if (d.connected_ip) out.push(["Remote IP", String(d.connected_ip)]);
  if (Array.isArray(d.attempts) && d.attempts.length) {
    out.push([
      "Attempts",
      d.attempts
        .map((a: unknown) => {
          const item = a as { ip?: string; status?: string };
          return `${item.ip ?? ""} (${item.status ?? ""})`;
        })
        .join("; "),
    ]);
  }
  if (c.error_kind) out.push(["Diagnostic Code", c.error_kind]);
  if (d.tls_error) out.push(["TLS Failure", String(d.tls_error)]);
  return out;
}

export function CheckCard({ c }: { c: CheckResult }) {
  const Icon = KIND_ICON[c.check] ?? Network;
  const facts = factsFor(c);
  return (
    <div className="corner-hud relative rounded-xl border border-neuro-cyan/20 bg-neuro-card/85 p-4 sm:p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="grid h-8 w-8 place-items-center rounded-lg border border-neuro-cyan/40 bg-neuro-cyan/10 text-neuro-cyan shadow-[0_0_10px_rgba(0,240,255,0.15)]">
            <Icon className="h-4 w-4" />
          </span>
          <div>
            <div className="font-mono text-xs font-bold uppercase tracking-wider text-neuro-cyan/80">[PROBE // {c.check}]</div>
            <div className="break-all font-mono text-xs sm:text-sm font-semibold text-white">{c.target}</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {c.simulated && <SimBadge />}
          <CheckBadge status={c.status} />
        </div>
      </div>
      <p className="mt-3 text-xs sm:text-sm text-slate-200 leading-relaxed font-normal">{c.message}</p>
      <dl className="mt-3.5 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 rounded-lg border border-neuro-cyan/15 bg-neuro-abyss/80 p-3 text-xs font-mono">
        <dt className="text-slate-400 font-medium">LATENCY</dt>
        <dd className="text-neuro-cyan font-bold">{fmtMs(c.elapsed_ms)}</dd>
        <dt className="text-slate-400 font-medium">TIMESTAMP</dt>
        <dd className="text-slate-300">{fmtClock(c.started_at)}</dd>
        {facts.map(([k, v]) => (
          <Fragment key={k}>
            <dt className="text-slate-400 font-medium uppercase">{k}</dt>
            <dd className="break-all text-slate-200">{v}</dd>
          </Fragment>
        ))}
      </dl>
    </div>
  );
}

/* ---------- activity timeline ---------- */
const ACT_ICON = { created: ShieldCheck, check: PlugZap, capture: FileSearch, rules: ListChecks, sample: Activity } as const;
const DOT: Record<string, string> = {
  success: "text-emerald-400",
  failure: "text-rose-400",
  inconclusive: "text-amber-400",
  unavailable: "text-slate-400",
};

export function ActivityTimeline({ items }: { items: ActivityEntry[] }) {
  return (
    <ol className="relative space-y-4 pl-6 before:absolute before:bottom-1 before:left-[9px] before:top-1 before:w-px before:bg-white/[0.08]">
      {items.map((a, i) => {
        const Icon = ACT_ICON[a.kind as keyof typeof ACT_ICON] ?? Activity;
        return (
          <li key={i} className="relative">
            <span className="absolute -left-6 top-0.5 grid h-5 w-5 place-items-center rounded-full border border-white/[0.10] bg-ink-900 shadow-sm">
              <Icon className={`h-3 w-3 ${a.status ? DOT[a.status] ?? "text-slate-300" : "text-cyan-400"}`} />
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-400">{fmtClock(a.at)}</span>
              {a.simulated && <SimBadge />}
            </div>
            <p className="text-xs sm:text-sm font-medium text-slate-200 mt-0.5 leading-snug">{a.label}</p>
          </li>
        );
      })}
    </ol>
  );
}

/* ---------- capture events ---------- */
const LEVEL_DOT = {
  info: "bg-slate-400",
  notable: "bg-cyan-400",
  warning: "bg-amber-400",
} as const;

export function EventList({ events, invId, max }: { events: TimelineEvent[]; invId?: string; max?: number }) {
  const shown = max ? events.slice(0, max) : events;
  return (
    <ul className="divide-y divide-white/[0.05]">
      {shown.map((e, i) => (
        <li key={i} className="flex items-start gap-3 py-2.5 transition hover:bg-white/[0.02]">
          <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${LEVEL_DOT[e.level]}`} title={e.level} />
          <span className="w-16 shrink-0 font-mono text-xs text-slate-400">+{fmtRel(e.rel_time)}s</span>
          <span className="flex-1 text-xs sm:text-sm text-slate-300 leading-snug">{e.description}</span>
          {invId ? (
            <button
              onClick={() => go(`/packets/${invId}?sel=${e.packet}`)}
              className="shrink-0 rounded border border-indigo-500/25 bg-indigo-500/10 px-2 py-0.5 font-mono text-xs text-indigo-300 hover:bg-indigo-500/20"
            >
              #{e.packet}
            </button>
          ) : (
            <span className="shrink-0 font-mono text-xs text-slate-400">#{e.packet}</span>
          )}
        </li>
      ))}
    </ul>
  );
}

/* ---------- charts ---------- */
const PROTO_COLORS: Record<string, string> = {
  DNS: "#00f0ff",
  TCP: "#7b2cbf",
  UDP: "#00ff88",
  ICMP: "#ffaa00",
  ICMPv6: "#ffaa00",
  ARP: "#00f0ff",
  mDNS: "#38bdf8",
  Other: "#64748b",
};
const protoColor = (p: string) => PROTO_COLORS[p] ?? "#94a3b8";

const tipStyle = {
  background: "rgba(4, 6, 11, 0.95)",
  border: "1px solid rgba(0, 240, 255, 0.3)",
  borderRadius: 8,
  color: "#f1f5f9",
  fontSize: 12,
  fontFamily: "JetBrains Mono, monospace",
  boxShadow: "0 0 20px rgba(0, 240, 255, 0.18)",
  backdropFilter: "blur(16px)",
};

export function ProtocolChart({ counts }: { counts: Record<string, number> }) {
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) return null;
  return (
    <div className="flex flex-wrap items-center gap-5">
      <div className="h-36 w-36 shrink-0" role="img" aria-label={`Protocol distribution: ${data.map((d) => `${d.name} ${d.value}`).join(", ")}`}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={40} outerRadius={64} paddingAngle={2} stroke="none">
              {data.map((d) => (
                <Cell key={d.name} fill={protoColor(d.name)} />
              ))}
            </Pie>
            <Tooltip contentStyle={tipStyle} itemStyle={{ color: "#f1f5f9" }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <ul className="min-w-[9rem] flex-1 space-y-1.5 text-xs font-mono">
        {data.map((d) => (
          <li key={d.name} className="flex items-center gap-2 rounded border border-neuro-cyan/15 bg-neuro-surface/40 px-2 py-1">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: protoColor(d.name), boxShadow: `0 0 6px ${protoColor(d.name)}` }} />
            <span className="font-semibold text-slate-300">{d.name}</span>
            <span className="ml-auto font-mono text-white font-bold">{d.value}</span>
            <span className="w-10 text-right font-mono text-xs text-neuro-cyan/80">
              {Math.round((d.value / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function TrafficChart({ cap }: { cap: CaptureSummary }) {
  const data = cap.time_buckets.map((b) => ({ t: b.start, normal: b.packets - b.flagged, flagged: b.flagged }));
  if (!data.length) return null;
  return (
    <div className="h-44" role="img" aria-label="Packets over time; flagged packets carry an anomaly marker">
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 6, right: 6, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="gN" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.6} />
              <stop offset="100%" stopColor="#00f0ff" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="gF" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ff0055" stopOpacity={0.75} />
              <stop offset="100%" stopColor="#ff0055" stopOpacity={0.05} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(0, 240, 255, 0.08)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: "#94a3b8", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }} tickFormatter={(v: number) => `${v.toFixed(v < 10 ? 1 : 0)}s`} axisLine={false} tickLine={false} />
          <YAxis allowDecimals={false} tick={{ fill: "#94a3b8", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={tipStyle} labelFormatter={(v) => `+${Number(v).toFixed(2)} s`} />
          <Area type="monotone" stackId="1" dataKey="normal" name="Standard Frames" stroke="#00f0ff" fill="url(#gN)" strokeWidth={1.5} />
          <Area type="monotone" stackId="1" dataKey="flagged" name="Anomaly Flags" stroke="#ff0055" fill="url(#gF)" strokeWidth={1.5} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function CheckTimingChart({ checks }: { checks: CheckResult[] }) {
  const data = checks
    .filter((c) => c.elapsed_ms != null)
    .map((c) => ({
      name: `${c.check.toUpperCase()} ${c.target.length > 20 ? c.target.slice(0, 18) + "…" : c.target}`,
      ms: c.elapsed_ms as number,
      status: c.status,
    }));
  if (data.length < 1) return null;
  const color = { success: "#00ff88", failure: "#ff0055", inconclusive: "#ffaa00", unavailable: "#64748b" } as const;
  return (
    <div style={{ height: 40 + data.length * 32 }} role="img" aria-label="Probe latency per live check">
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="rgba(0, 240, 255, 0.08)" horizontal={false} />
          <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }} axisLine={false} tickLine={false} unit=" ms" />
          <YAxis type="category" dataKey="name" width={140} tick={{ fill: "#cbd5e1", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={tipStyle} cursor={{ fill: "rgba(0, 240, 255, 0.04)" }} formatter={(v) => [`${v} ms`, "Latency"]} />
          <Bar dataKey="ms" radius={[0, 4, 4, 0]}>
            {data.map((d, i) => (
              <Cell key={i} fill={color[d.status]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export { Mono };
