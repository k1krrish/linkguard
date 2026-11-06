import { AlertTriangle, CheckCircle2, CircleHelp, Inbox, Loader2, MinusCircle, RefreshCw, XCircle, FlaskConical } from "lucide-react";
import type { ComponentType, ReactNode } from "react";
import { checkTone, findingTone } from "../lib";
import type { CheckStatus, FindingStatus, Severity } from "../types";

export function Panel({
  title,
  icon: Icon,
  actions,
  children,
  className = "",
  pad = true,
  subtitle,
}: {
  title?: ReactNode;
  icon?: ComponentType<{ className?: string }>;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  pad?: boolean;
  subtitle?: ReactNode;
}) {
  return (
    <section className={`glass animate-rise min-w-0 relative overflow-hidden group ${className}`}>
      {/* Tactical HUD Corner Notches */}
      <span className="pointer-events-none absolute top-0 left-0 h-2 w-2 border-t border-l border-cyan-400/40" />
      <span className="pointer-events-none absolute top-0 right-0 h-2 w-2 border-t border-r border-cyan-400/40" />
      <span className="pointer-events-none absolute bottom-0 left-0 h-2 w-2 border-b border-l border-cyan-400/40" />
      <span className="pointer-events-none absolute bottom-0 right-0 h-2 w-2 border-b border-r border-cyan-400/40" />

      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] px-5 py-3.5 bg-neuro-surface/50 backdrop-blur-md">
          <div className="flex items-center gap-3">
            {Icon && (
              <span className="grid h-8 w-8 place-items-center rounded border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-hologram-sm">
                <Icon className="h-4 w-4" />
              </span>
            )}
            <div>
              <h2 className="font-display text-xs sm:text-sm font-bold uppercase tracking-wider text-white">
                {title}
              </h2>
              {subtitle && <p className="text-xs text-slate-400 mt-0.5 font-medium leading-relaxed tracking-normal">{subtitle}</p>}
            </div>
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={pad ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-cyan-500/15 pb-5 relative">
      <div>
        <div className="flex items-center gap-2 mb-1.5 font-mono text-[10px] font-bold tracking-cyber text-cyan-400/80 uppercase">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
          <span>LINKGUARD // TACTICAL NETWORK FORENSICS</span>
        </div>
        <h1 className="font-display text-2xl sm:text-3xl font-black uppercase tracking-wider text-white drop-shadow-[0_0_15px_rgba(0,240,255,0.25)]">
          {title}
        </h1>
        {subtitle && <div className="mt-1 text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed font-medium">{subtitle}</div>}
      </div>
      {actions && <div className="no-print flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
}

const FINDING_META: Record<FindingStatus, { label: string; icon: ComponentType<{ className?: string }> }> = {
  issue: { label: "Issue Identified", icon: XCircle },
  inconclusive: { label: "Inconclusive", icon: CircleHelp },
  ok: { label: "No Issue Seen", icon: CheckCircle2 },
};

export function FindingBadge({ status }: { status: FindingStatus }) {
  const { label, icon: Icon } = FINDING_META[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-0.5 font-mono text-[11px] font-bold uppercase tracking-wider backdrop-blur-sm ${findingTone[status]}`}>
      <Icon className="h-3 w-3 shrink-0" />
      {label}
    </span>
  );
}

const CHECK_META: Record<CheckStatus, { label: string; icon: ComponentType<{ className?: string }> }> = {
  success: { label: "Success", icon: CheckCircle2 },
  failure: { label: "Failed", icon: XCircle },
  inconclusive: { label: "Inconclusive", icon: CircleHelp },
  unavailable: { label: "Unavailable", icon: MinusCircle },
};

export function CheckBadge({ status }: { status: CheckStatus }) {
  const { label, icon: Icon } = CHECK_META[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-0.5 font-mono text-[11px] font-bold uppercase tracking-wider backdrop-blur-sm ${checkTone[status]}`}>
      <Icon className="h-3 w-3 shrink-0" />
      {label}
    </span>
  );
}

export function SeverityTag({ severity }: { severity: Severity }) {
  const tone =
    severity === "medium"
      ? "text-amber-300 border-amber-400/40 bg-amber-400/15"
      : severity === "low"
      ? "text-sky-300 border-sky-400/40 bg-sky-400/15"
      : "text-slate-300 border-slate-500/30 bg-slate-500/15";
  return (
    <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider border ${tone}`}>
      {severity}
    </span>
  );
}

export function SimBadge({ label = "Simulated" }: { label?: string }) {
  return (
    <span
      title="Synthetic reference scenario; not an observation on a live network"
      className="inline-flex items-center gap-1.5 rounded border border-purple-500/40 bg-purple-500/15 px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-purple-300 backdrop-blur-sm shadow-sm"
    >
      <FlaskConical className="h-3 w-3 text-purple-300" />
      {label}
    </span>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden />;
}

export function SkeletonBlock({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3" role="status" aria-label="Loading content">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-11 w-full" />
      ))}
    </div>
  );
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  children,
  action,
}: {
  icon?: ComponentType<{ className?: string }>;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-12 text-center">
      <div className="mb-4 grid h-12 w-12 place-items-center rounded-2xl border border-white/[0.08] bg-white/[0.03] text-cyan-400 shadow-sm">
        <Icon className="h-6 w-6" />
      </div>
      <p className="text-base font-bold text-white">{title}</p>
      {children && <p className="mt-1.5 max-w-md text-xs sm:text-sm leading-relaxed text-slate-300">{children}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs sm:text-sm text-rose-200 backdrop-blur-sm"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
      <div className="flex-1 leading-relaxed">{message}</div>
      {onRetry && (
        <button className="btn-ghost btn-sm text-xs ml-2 text-rose-300 hover:border-rose-400/40" onClick={onRetry}>
          <RefreshCw className="h-3 w-3" />
          Retry
        </button>
      )}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-xs sm:text-sm text-slate-300">
      <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
      {label}
    </span>
  );
}

export function Stat({
  label,
  value,
  hint,
  icon: Icon,
  tone = "text-white",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon: ComponentType<{ className?: string }>;
  tone?: string;
}) {
  return (
    <div className="glass-card group relative flex h-full flex-col justify-between p-4 sm:p-5 transition-all duration-150 hover:border-cyan-500/40 hover:-translate-y-0.5 overflow-hidden">
      {/* Corner HUD Ticks */}
      <span className="pointer-events-none absolute top-0 right-0 h-2 w-2 border-t border-r border-cyan-400/35" />
      <span className="pointer-events-none absolute bottom-0 left-0 h-2 w-2 border-b border-l border-cyan-400/35" />

      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-400">{label}</span>
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded border border-cyan-400/20 bg-cyan-500/10 text-cyan-300 group-hover:border-cyan-400/45 group-hover:shadow-hologram-sm transition-all">
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <div>
        <div className={`mt-2 font-display text-2xl sm:text-3xl font-black tabular-nums tracking-wide ${tone}`}>{value}</div>
        {hint && <div className="mt-1 text-xs text-slate-400 font-medium leading-normal">{hint}</div>}
      </div>
    </div>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: string; count?: number }[];
  value: T;
  onChange: (t: T) => void;
}) {
  return (
    <div role="tablist" className="inline-flex gap-1 rounded-xl border border-white/[0.08] bg-ink-950/70 p-1.5 backdrop-blur-md">
      {tabs.map((t) => {
        const active = value === t.id;
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            className={`rounded-lg px-3.5 py-2 text-xs sm:text-sm font-semibold transition-all ${
              active
                ? "bg-white/[0.10] text-white shadow-sm border border-white/[0.14]"
                : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent"
            }`}
          >
            {t.label}
            {t.count != null && (
              <span
                className={`ml-2 rounded-full px-2 py-0.5 font-mono text-xs ${
                  active ? "bg-cyan-500/25 text-cyan-200 font-bold" : "bg-white/[0.06] text-slate-400"
                }`}
              >
                {t.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export const Mono = ({ children }: { children: ReactNode }) => (
  <span className="rounded border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.5 font-mono text-xs text-slate-200">
    {children}
  </span>
);
