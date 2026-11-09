import { Activity, BookOpenCheck, CheckCircle2, ChevronRight, ExternalLink, FileText, FlaskConical, LayoutDashboard, Menu, PackageSearch, PlusCircle, RefreshCw, ShieldCheck, Sparkles, X } from "lucide-react";
import { useEffect, useState, type ComponentType } from "react";
import { AppProvider, useApp } from "./context";
import { go, useRoute } from "./lib";
import { InvestigationDetails } from "./pages/InvestigationDetails";
import { NewInvestigation } from "./pages/NewInvestigation";
import { Overview } from "./pages/Overview";
import { PacketExplorer } from "./pages/PacketExplorer";
import { Reports } from "./pages/Reports";
import { Rules } from "./pages/Rules";

const NAV: { to: string; key: string; label: string; icon: ComponentType<{ className?: string }> }[] = [
  { to: "/", key: "", label: "Incident Overview", icon: LayoutDashboard },
  { to: "/new", key: "new", label: "New Investigation", icon: PlusCircle },
  { to: "/packets", key: "packets", label: "Packet Explorer", icon: PackageSearch },
  { to: "/reports", key: "reports", label: "Diagnostic Reports", icon: FileText },
  { to: "/rules", key: "rules", label: "Diagnostic Rules", icon: BookOpenCheck },
];

function BackendStatus() {
  const { health, healthError } = useApp();
  const up = !!health && !healthError;
  return (
    <div
      className="flex items-center gap-2.5 rounded-lg border border-neuro-cyan/20 bg-neuro-abyss/80 px-3 py-2 text-xs font-mono tracking-wider backdrop-blur-md"
      role="status"
    >
      <span className="relative flex h-2 w-2">
        {up && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neuro-emerald opacity-75" />}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${up ? "bg-neuro-emerald shadow-[0_0_8px_#00ff88]" : healthError ? "bg-neuro-crimson shadow-[0_0_8px_#ff0055]" : "bg-slate-500"}`} />
      </span>
      <span className="text-slate-300">
        {up ? (
          <span className="text-neuro-cyan">
            <span className="opacity-60">[SYS // </span>v{health!.version} ACTIVE<span className="opacity-60">]</span>
          </span>
        ) : healthError ? (
          <span className="text-neuro-crimson">[SYS // OFFLINE]</span>
        ) : (
          <span className="text-slate-400">[CONNECTING…]</span>
        )}
      </span>
    </div>
  );
}

function Sidebar({ active, onNavigate }: { active: string; onNavigate: () => void }) {
  const { list, loadSample, sampleBusy } = useApp();

  return (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r border-neuro-cyan/15 bg-neuro-abyss/90 backdrop-blur-2xl">
      {/* Brand Header */}
      <a href="#/" onClick={onNavigate} className="flex items-center gap-3 px-5 py-4 border-b border-neuro-cyan/15 focus-visible:outline-none group">
        <span className="relative grid h-10 w-10 place-items-center rounded-lg border border-neuro-cyan/40 bg-neuro-cyan/10 text-neuro-cyan shadow-[0_0_15px_rgba(0,240,255,0.2)] group-hover:shadow-[0_0_22px_rgba(0,240,255,0.4)] transition-all">
          <ShieldCheck className="h-5 w-5" />
          <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-neuro-cyan animate-pulse" />
        </span>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-display text-sm font-bold tracking-wider text-white">LINKGUARD</span>
            <span className="rounded border border-neuro-cyan/40 bg-neuro-cyan/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-neuro-cyan">
              v2.0
            </span>
          </div>
          <span className="block font-mono text-[11px] text-neuro-cyan/70 tracking-wide">NET // DETECTIVE</span>
        </div>
      </a>

      {/* Main Navigation */}
      <nav className="p-3 space-y-1.5" aria-label="Main">
        {NAV.map((n) => {
          const on = active === n.key;
          return (
            <a
              key={n.key}
              href={`#${n.to}`}
              onClick={onNavigate}
              aria-current={on ? "page" : undefined}
              className={`group flex items-center justify-between rounded-lg px-3 py-2 text-xs font-mono tracking-wider transition-all duration-150 focus-visible:outline-none ${
                on
                  ? "bg-neuro-cyan/10 text-neuro-cyan border border-neuro-cyan/40 shadow-[0_0_15px_rgba(0,240,255,0.15)] font-semibold"
                  : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-200 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <n.icon className={`h-4 w-4 transition-colors ${on ? "text-neuro-cyan drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-400 group-hover:text-slate-200"}`} />
                <span>{n.label}</span>
              </div>
              {on && <span className="text-[10px] text-neuro-cyan font-bold tracking-tighter">›</span>}
            </a>
          );
        })}
      </nav>

      {/* Reference Scenario Presets */}
      <div className="px-3 pt-2">
        <div className="px-2 pb-2 flex items-center justify-between">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-neuro-cyan/80 flex items-center gap-1.5">
            <Sparkles className="h-3 w-3 text-neuro-cyan" />
            [ REF // SCENARIOS ]
          </h3>
        </div>
        <div className="space-y-1">
          {[
            { id: "dns-unanswered", label: "DNS Queries Dropped" },
            { id: "tcp-refused", label: "TCP Port Refused" },
            { id: "http-503", label: "HTTP 503 Web Failure" },
          ].map((sample) => (
            <button
              key={sample.id}
              disabled={sampleBusy !== null}
              onClick={() => {
                onNavigate();
                void loadSample(sample.id);
              }}
              className="w-full text-left rounded-lg border border-white/[0.06] bg-neuro-surface/50 px-3 py-2 text-xs font-mono transition-all hover:border-neuro-cyan/40 hover:bg-neuro-cyan/[0.08] text-slate-300 flex items-center justify-between group"
            >
              <span className="truncate">{sample.label}</span>
              <ChevronRight className="h-3.5 w-3.5 text-slate-500 group-hover:text-neuro-cyan transition-transform group-hover:translate-x-0.5" />
            </button>
          ))}
        </div>
      </div>

      {/* Recent Investigations */}
      <div className="mt-3 min-h-0 flex-1 overflow-y-auto px-3 border-t border-neuro-cyan/15 pt-3">
        <h3 className="px-2 pb-2 font-mono text-[11px] uppercase tracking-wider text-slate-400">
          [ TELEMETRY // LOGS ]
        </h3>
        {list.length === 0 ? (
          <p className="px-2 py-1 font-mono text-xs text-slate-500">No telemetry logged yet.</p>
        ) : (
          list.slice(0, 5).map((i) => (
            <a
              key={i.id}
              href={`#/investigations/${i.id}`}
              onClick={onNavigate}
              className={`group mb-1.5 block rounded-lg border p-2.5 text-xs transition-all hover:border-neuro-cyan/40 hover:bg-neuro-surface/80 focus-visible:outline-none ${
                i.status === "resolved"
                  ? "border-neuro-emerald/20 bg-neuro-emerald/[0.03]"
                  : i.issue_count > 0
                  ? "border-neuro-crimson/20 bg-neuro-crimson/[0.03]"
                  : "border-white/[0.06] bg-white/[0.02]"
              }`}
            >
              <div className="line-clamp-1 font-semibold text-slate-200 group-hover:text-neuro-cyan transition-colors">
                {i.title}
              </div>
              <div className="mt-1 flex items-center gap-2 font-mono text-[11px] text-slate-400">
                {i.status === "resolved" ? (
                  <span className="inline-flex items-center gap-1 font-semibold text-neuro-emerald">
                    <CheckCircle2 className="h-3 w-3" />
                    SOLVED ✓
                  </span>
                ) : i.issue_count > 0 ? (
                  <span className="inline-flex items-center gap-1 font-semibold text-neuro-crimson">
                    <span className="h-1.5 w-1.5 rounded-full bg-neuro-crimson animate-pulse" />
                    {i.issue_count} {i.issue_count === 1 ? "FAULT" : "FAULTS"}
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-neuro-emerald">
                    <span className="h-1.5 w-1.5 rounded-full bg-neuro-emerald" />
                    CLEAN
                  </span>
                )}
                {i.status !== "resolved" && i.inconclusive_count > 0 && (
                  <span>· {i.inconclusive_count} inc</span>
                )}
                {i.simulated && (
                  <span className="rounded bg-neuro-violet/20 px-1 text-neuro-violet font-mono text-[10px]">sim</span>
                )}
              </div>
            </a>
          ))
        )}
      </div>

      {/* Cloud Deployment, System About & Engine Status */}
      <div className="p-3 border-t border-neuro-cyan/15 space-y-2">
        <a
          href="https://linkguard-de1c.onrender.com/#/"
          target="_blank"
          rel="noreferrer"
          className="flex items-center justify-between rounded-lg border border-neuro-cyan/30 bg-neuro-cyan/10 px-3 py-2 text-xs font-mono text-neuro-cyan hover:bg-neuro-cyan/20 hover:border-neuro-cyan/60 transition-all group"
          title="Open Live Cloud Deployment on Render"
        >
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neuro-cyan opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-neuro-cyan shadow-[0_0_8px_#00f0ff]" />
            </span>
            <span className="font-semibold tracking-wider text-white group-hover:text-neuro-cyan transition-colors">
              LIVE CLOUD
            </span>
          </div>
          <span className="flex items-center gap-1 text-[10px] text-neuro-cyan/80 group-hover:text-white transition-colors">
            onrender.com <ExternalLink className="h-3 w-3" />
          </span>
        </a>

        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5 font-mono text-[11px] space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-neuro-cyan/80 font-semibold">[ABOUT // SYS]</span>
            <span className="text-[10px] text-slate-500">CSE3003</span>
          </div>
          <div className="text-[10px] text-slate-400 line-clamp-1">
            LinkGuard Forensic Detective
          </div>
          <a
            href="https://github.com/k1krrish/linkguard"
            target="_blank"
            rel="noreferrer"
            className="flex items-center justify-between pt-1 text-[10px] text-slate-400 hover:text-neuro-cyan transition-colors"
          >
            <span>GitHub Repository</span>
            <ExternalLink className="h-2.5 w-2.5" />
          </a>
        </div>

        <BackendStatus />
      </div>
    </aside>
  );
}

function Topbar({ onMenu, active }: { onMenu: () => void; active: string }) {
  const { refresh, loadNextSample, sampleBusy } = useApp();
  const [refreshing, setRefreshing] = useState(false);
  const title = NAV.find((n) => n.key === active)?.label ?? "Investigation";

  const handleRefresh = async () => {
    setRefreshing(true);
    refresh();
    setTimeout(() => setRefreshing(false), 450);
  };

  return (
    <header className="no-print flex h-14 items-center gap-3 border-b border-neuro-cyan/15 bg-neuro-abyss/85 px-4 backdrop-blur-xl sm:gap-4 sm:px-6 sticky top-0 z-20">
      <button className="btn-ghost btn-sm shrink-0 lg:hidden" onClick={onMenu} aria-label="Toggle navigation">
        <Menu className="h-4 w-4" />
      </button>

      <div className="flex min-w-0 items-center gap-2.5 font-mono text-xs sm:text-sm text-slate-400">
        <Activity className="hidden h-3.5 w-3.5 shrink-0 text-neuro-cyan sm:block" />
        <span className="hidden sm:inline text-neuro-cyan/80">LINKGUARD // HUD</span>
        <span className="hidden text-slate-600 sm:inline">›</span>
        <span className="truncate font-display font-bold uppercase tracking-wider text-white">{title}</span>
      </div>

      <div className="ml-auto flex shrink-0 items-center gap-2">
        <button
          className="btn-ghost btn-sm hidden sm:inline-flex border-neuro-cyan/40 text-neuro-cyan bg-neuro-cyan/10 hover:bg-neuro-cyan/20 hover:shadow-[0_0_12px_rgba(0,240,255,0.3)] transition-all font-mono text-xs"
          disabled={sampleBusy !== null}
          onClick={() => void loadNextSample(false)}
          title="Simulate a different network incident (cycles through DNS, TCP, HTTP, and packet drops)"
        >
          <FlaskConical className={`h-3.5 w-3.5 text-neuro-cyan ${sampleBusy ? "animate-spin" : ""}`} />
          <span>{sampleBusy ? "SIMULATING…" : "SIMULATE ⟳"}</span>
        </button>

        <button className="btn-ghost btn-sm font-mono text-xs" onClick={handleRefresh} title="Refresh telemetry records">
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-neuro-cyan" : ""}`} />
          <span className="hidden sm:inline">SYNC</span>
        </button>

        <button className="btn-primary btn-sm font-mono text-xs tracking-wider" onClick={() => go("/new")} aria-label="New investigation">
          <PlusCircle className="h-3.5 w-3.5" />
          <span>+ NEW AUDIT</span>
        </button>
      </div>
    </header>
  );
}

function Routes() {
  const { path } = useRoute();
  const [a, id] = path;
  if (!a) return <Overview />;
  if (a === "new") return <NewInvestigation />;
  if (a === "investigations" && id) return <InvestigationDetails id={id} />;
  if (a === "packets") return <PacketExplorer id={id} />;
  if (a === "reports") return <Reports id={id} />;
  if (a === "rules") return <Rules />;
  return <Overview />;
}

function Shell() {
  const route = useRoute();
  const [menu, setMenu] = useState(false);
  const active = route.path[0] === "investigations" ? "" : route.path[0] ?? "";
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [route.path.join("/")]);
  useEffect(() => {
    if (!window.location.hash) go("/");
  }, []);

  return (
    <div className="flex h-full">
      <div className="no-print hidden lg:block">
        <Sidebar active={active} onNavigate={() => {}} />
      </div>
      {menu && (
        <div className="no-print fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 bg-black/75 backdrop-blur-sm" onClick={() => setMenu(false)} />
          <div className="relative h-full w-64 shadow-2xl">
            <Sidebar active={active} onNavigate={() => setMenu(false)} />
            <button
              className="btn-ghost btn-sm absolute right-2.5 top-3"
              onClick={() => setMenu(false)}
              aria-label="Close navigation"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <Topbar onMenu={() => setMenu(true)} active={active} />
        <main className="min-h-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6 sm:py-6 lg:px-8">
          <div className="mx-auto max-w-7xl">
            <Routes />
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}
