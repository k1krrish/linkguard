import { ChevronLeft, ChevronRight, FilterX, PackageSearch, Search, Layers, Network, PlugZap, Timer, Sparkles } from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import { EventList, ProtocolChart, TrafficChart } from "../components/domain";
import { EmptyState, ErrorBox, PageHeader, Panel, SimBadge, Skeleton, SkeletonBlock, Stat, Tabs } from "../components/ui";
import { useApp } from "../context";
import { fmtBytes, fmtRel, go, useAsync, useDebounced, useRoute } from "../lib";
import type { CaptureSummary, PacketFilters, PacketSummary } from "../types";

const PAGE = 50;
const FLAGS = ["SYN", "ACK", "FIN", "RST", "PSH"];
const MARKERS: Record<string, string> = {
  reset: "TCP Reset",
  retransmission: "Retransmission",
  dns_unanswered: "Unanswered DNS",
  dns_error: "DNS Error",
  syn_no_reply: "SYN No Reply",
};

const markerTone = (m: string) =>
  m === "dns_unanswered" || m === "syn_no_reply"
    ? "border-neuro-amber/40 text-neuro-amber bg-neuro-amber/10 shadow-[0_0_8px_rgba(255,170,0,0.2)]"
    : "border-neuro-crimson/40 text-neuro-crimson bg-neuro-crimson/10 shadow-[0_0_8px_rgba(255,0,85,0.2)]";

function MarkerTag({ m }: { m: string }) {
  return (
    <span className={`whitespace-nowrap rounded px-2 py-0.5 font-mono text-xs font-semibold border ${markerTone(m)}`}>
      {MARKERS[m] ?? m}
    </span>
  );
}

function Picker() {
  const { list, listLoading, listError, refresh, loadSample } = useApp();
  const withCap = list.filter((i) => i.packet_total != null);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Packet Analysis Explorer"
        subtitle="Inspect individual packet frames, protocol layer dissections, DNS query/reply transactions, and TCP flows."
      />
      {listError && <ErrorBox message={listError} onRetry={refresh} />}
      {listLoading && list.length === 0 && <SkeletonBlock rows={3} />}
      {!listLoading && !listError && withCap.length === 0 && (
        <Panel>
          <EmptyState
            icon={PackageSearch}
            title="No packet captures available"
            action={
              <div className="flex flex-wrap gap-2.5">
                <button className="btn-primary font-mono text-xs" onClick={() => void loadSample("dns-unanswered")}>
                  <Sparkles className="h-4 w-4" />
                  LOAD SAMPLE PCAP
                </button>
                <button className="btn-ghost font-mono text-xs" onClick={() => go("/new")}>
                  UPLOAD PCAP FILE
                </button>
              </div>
            }
          >
            Packet captures become available when an investigation is created with a .pcap file or a reference scenario.
          </EmptyState>
        </Panel>
      )}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {withCap.map((i) => (
          <button
            key={i.id}
            onClick={() => go(`/packets/${i.id}`)}
            className="corner-hud relative flex flex-col justify-between rounded-xl border border-neuro-cyan/20 bg-neuro-card/85 p-5 text-left transition-all duration-150 hover:border-neuro-cyan/50 hover:shadow-[0_0_20px_rgba(0,240,255,0.2)] hover:-translate-y-0.5 focus-visible:outline-none group"
          >
            <div>
              <div className="mb-3 flex items-center justify-between">
                <span className="grid h-8 w-8 place-items-center rounded-lg border border-neuro-cyan/40 bg-neuro-cyan/10 text-neuro-cyan shadow-[0_0_10px_rgba(0,240,255,0.2)]">
                  <PackageSearch className="h-4 w-4" />
                </span>
                {i.simulated && <SimBadge />}
              </div>
              <div className="font-display font-bold text-white group-hover:text-neuro-cyan transition-colors text-sm sm:text-base tracking-wide">
                {i.title}
              </div>
              <div className="mt-2.5 flex items-center gap-2 font-mono text-xs text-slate-400">
                <span className="rounded border border-neuro-cyan/30 bg-neuro-cyan/10 px-2 py-0.5 text-neuro-cyan font-bold">
                  {i.packet_total?.toLocaleString()} FRAMES
                </span>
                <span className="uppercase">· {i.source}</span>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function Detail({ id, sel }: { id: string; sel: number }) {
  const q = useAsync(() => api.packet(id, sel), [id, sel]);
  if (q.loading) return <SkeletonBlock rows={4} />;
  if (q.error || !q.data) return <ErrorBox message={q.error ?? "Packet record not found"} onRetry={q.reload} />;
  const p = q.data;

  return (
    <div className="space-y-4 text-xs sm:text-sm">
      <div className="rounded-lg border border-white/[0.07] bg-ink-950/50 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 font-mono text-sm font-bold text-cyan-300">
            Frame #{p.index}
          </span>
          <span className="rounded border border-white/[0.12] bg-white/[0.04] px-1.5 py-0.5 font-mono text-xs font-semibold text-slate-200">
            {p.protocol}
          </span>
          {p.markers.map((m) => (
            <MarkerTag key={m} m={m} />
          ))}
        </div>
        <p className="mt-2 break-words font-medium text-slate-200 leading-relaxed text-xs">{p.info}</p>
      </div>

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-white/[0.05] bg-ink-950/40 p-3 text-xs">
        <dt className="text-slate-400 font-medium">Relative Time</dt>
        <dd className="font-mono text-slate-200">+{fmtRel(p.rel_time)} s</dd>
        <dt className="text-slate-400 font-medium">Frame Length</dt>
        <dd className="font-mono text-slate-200">{p.length} bytes</dd>
        <dt className="text-slate-400 font-medium">Source Endpoint</dt>
        <dd className="break-all font-mono text-cyan-300">
          {p.src ?? "-"}{p.src_port != null ? `:${p.src_port}` : ""}
        </dd>
        <dt className="text-slate-400 font-medium">Destination Endpoint</dt>
        <dd className="break-all font-mono text-indigo-300">
          {p.dst ?? "-"}{p.dst_port != null ? `:${p.dst_port}` : ""}
        </dd>
        {p.ip_version && (
          <>
            <dt className="text-slate-400 font-medium">IP Header</dt>
            <dd className="font-mono text-slate-200">
              IPv{p.ip_version}{p.ttl != null ? ` · TTL ${p.ttl}` : ""}
            </dd>
          </>
        )}
        {p.tcp_flags && (
          <>
            <dt className="text-slate-400 font-medium">TCP Flags</dt>
            <dd className="font-mono font-semibold text-amber-300">{p.tcp_flags}</dd>
            <dt className="text-slate-400 font-medium">Seq / Ack</dt>
            <dd className="font-mono text-slate-200">{p.tcp_seq} / {p.tcp_ack}</dd>
            <dt className="text-slate-400 font-medium">Window</dt>
            <dd className="font-mono text-slate-200">{p.tcp_window}</dd>
            <dt className="text-slate-400 font-medium">Payload</dt>
            <dd className="font-mono text-slate-200">{p.tcp_payload_len ?? "0"} bytes</dd>
          </>
        )}
      </dl>

      {p.dns && (
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/[0.08] p-3 text-xs">
          <div className="mb-1 font-semibold uppercase tracking-wider text-cyan-300">
            DNS {p.dns.is_response ? "Response" : "Query"} Header
          </div>
          <div className="font-mono text-slate-200">
            ID: 0x{p.dns.id.toString(16).padStart(4, "0")} · {p.dns.qname} ({p.dns.qtype})
          </div>
          {p.dns.is_response && (
            <div className="mt-1 font-mono text-emerald-300">
              RCODE: {p.dns.rcode_name} · {p.dns.answer_count} answer(s)
              {p.dns.answers.length ? `: ${p.dns.answers.join(", ")}` : ""}
            </div>
          )}
        </div>
      )}

      <div>
        <h4 className="label">Protocol Layers</h4>
        <div className="space-y-1.5">
          {p.layers.map((l, i) => (
            <details
              key={i}
              className="rounded-lg border border-white/[0.06] bg-ink-950/40 p-2.5 transition hover:border-white/[0.12]"
              open={i < 2}
            >
              <summary className="cursor-pointer text-xs font-semibold text-slate-200 flex items-center justify-between">
                <span>{l.name}</span>
                <span className="text-xs text-slate-400 font-mono">layer {i + 1}</span>
              </summary>
              <dl className="mt-2.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs border-t border-white/[0.06] pt-2">
                {Object.entries(l.fields).map(([k, v]) => (
                  <Fragment key={k}>
                    <dt className="text-slate-400 font-medium">{k}</dt>
                    <dd className="break-all font-mono text-slate-200">{String(v)}</dd>
                  </Fragment>
                ))}
              </dl>
            </details>
          ))}
        </div>
        <p className="mt-3 text-xs text-slate-400 italic leading-relaxed">
          * Raw packet payloads are parsed in memory; only header fields are returned to the client.
        </p>
      </div>
    </div>
  );
}

function PacketsTab({ id, cap, sel }: { id: string; cap: CaptureSummary; sel: number | null }) {
  const [filters, setFilters] = useState<PacketFilters>({});
  const [offset, setOffset] = useState(0);
  const debounced = useDebounced(filters, 300);
  const key = JSON.stringify(debounced);
  useEffect(() => setOffset(0), [key, id]);
  const q = useAsync(() => api.packets(id, offset, PAGE, debounced), [id, offset, key]);
  const set = (k: keyof PacketFilters, v: string) => setFilters((f) => ({ ...f, [k]: v || undefined }));
  const active = Object.values(filters).some(Boolean);
  const total = q.data?.total ?? 0;
  const open = (p: PacketSummary) => go(`/packets/${id}?sel=${p.index}`);

  return (
    <div className="grid gap-6 xl:grid-cols-5">
      <Panel
        className="xl:col-span-3"
        pad={false}
        title={
          <span className="flex items-center gap-2">
            Captured Frames
            <span className="rounded border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.2 font-mono text-xs font-normal text-slate-300">
              {q.data ? `${total.toLocaleString()} match` : "…"}
            </span>
          </span>
        }
        actions={
          active ? (
            <button className="btn-ghost btn-sm text-xs" onClick={() => setFilters({})}>
              <FilterX className="h-3 w-3" />
              Reset Filters
            </button>
          ) : undefined
        }
      >
        {/* Filter Bar */}
        <div className="grid grid-cols-2 gap-2 border-b border-white/[0.07] bg-white/[0.015] p-3 sm:grid-cols-4">
          <div className="relative col-span-2">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              aria-label="Search frame content"
              className="field pl-8 text-xs"
              placeholder="Search endpoint, port, info…"
              value={filters.q ?? ""}
              onChange={(e) => set("q", e.target.value)}
            />
          </div>
          <select
            aria-label="Protocol filter"
            className="field text-xs"
            value={filters.protocol ?? ""}
            onChange={(e) => set("protocol", e.target.value)}
          >
            <option value="">All Protocols</option>
            {Object.keys(cap.protocol_counts).map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
          <select
            aria-label="TCP flag filter"
            className="field text-xs"
            value={filters.flag ?? ""}
            onChange={(e) => set("flag", e.target.value)}
          >
            <option value="">Any TCP Flag</option>
            {FLAGS.map((f) => (
              <option key={f}>{f}</option>
            ))}
          </select>
          <input
            aria-label="IP filter"
            className="field font-mono text-xs"
            placeholder="IP Address"
            value={filters.ip ?? ""}
            onChange={(e) => set("ip", e.target.value.trim())}
          />
          <input
            aria-label="Port filter"
            className="field font-mono text-xs"
            inputMode="numeric"
            placeholder="Port Number"
            value={filters.port ?? ""}
            onChange={(e) => set("port", e.target.value.replace(/\D/g, ""))}
          />
          <input
            aria-label="DNS name filter"
            className="field text-xs"
            placeholder="DNS Query Contains"
            value={filters.dns_name ?? ""}
            onChange={(e) => set("dns_name", e.target.value.trim())}
          />
          <select
            aria-label="Anomaly marker filter"
            className="field text-xs"
            value={filters.marker ?? ""}
            onChange={(e) => set("marker", e.target.value)}
          >
            <option value="">Any Anomaly Marker</option>
            {Object.entries(MARKERS).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
        </div>

        {q.error && (
          <div className="p-4">
            <ErrorBox message={q.error} onRetry={q.reload} />
          </div>
        )}
        {q.loading && !q.data && (
          <div className="p-4">
            <SkeletonBlock rows={6} />
          </div>
        )}
        {q.data && q.data.items.length === 0 && (
          <EmptyState icon={Search} title={active ? "No frames match active filters" : "Capture contains zero frames"}>
            {active ? "Try removing a filter. Absence of a frame in this capture does not prove the event never occurred." : undefined}
          </EmptyState>
        )}

        {q.data && q.data.items.length > 0 && (
          <div className={`overflow-x-auto ${q.loading ? "opacity-60" : ""}`}>
            <table className="w-full min-w-[42rem]">
              <thead>
                <tr className="border-b border-white/[0.07] bg-white/[0.015]">
                  <th className="th w-14">#</th>
                  <th className="th">Time (Rel)</th>
                  <th className="th">Source</th>
                  <th className="th">Destination</th>
                  <th className="th">Proto</th>
                  <th className="th">Frame Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {q.data.items.map((p) => {
                  const isSelected = sel === p.index;
                  return (
                    <tr
                      key={p.index}
                      onClick={() => open(p)}
                      aria-selected={isSelected}
                      className={`cursor-pointer transition-colors hover:bg-white/[0.04] ${
                        isSelected ? "bg-cyan-500/10 border-l-2 border-l-cyan-400" : ""
                      }`}
                    >
                      <td className="td font-mono text-xs">
                        <button
                          className="font-bold text-cyan-300 hover:underline focus-visible:outline-none"
                          onClick={(e) => {
                            e.stopPropagation();
                            open(p);
                          }}
                          aria-label={`Open frame #${p.index}`}
                        >
                          {p.index}
                        </button>
                      </td>
                      <td className="td whitespace-nowrap font-mono text-xs text-slate-400">
                        +{fmtRel(p.rel_time)}s
                      </td>
                      <td className="td whitespace-nowrap font-mono text-xs text-slate-200">
                        {p.src ?? "-"}{p.src_port != null ? `:${p.src_port}` : ""}
                      </td>
                      <td className="td whitespace-nowrap font-mono text-xs text-slate-200">
                        {p.dst ?? "-"}{p.dst_port != null ? `:${p.dst_port}` : ""}
                      </td>
                      <td className="td text-xs">
                        <span className="rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-xs font-semibold text-slate-300">
                          {p.protocol}
                        </span>
                      </td>
                      <td className="td text-xs text-slate-300">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span>{p.info}</span>
                          {p.markers.map((m) => (
                            <MarkerTag key={m} m={m} />
                          ))}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {total > PAGE && (
          <div className="flex items-center justify-between border-t border-white/[0.07] px-4 py-2.5 text-xs text-slate-400">
            <span>
              Showing {offset + 1}–{Math.min(offset + PAGE, total)} of {total.toLocaleString()} frames
            </span>
            <div className="flex gap-1.5">
              <button
                className="btn-ghost btn-sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE))}
                aria-label="Previous page"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Prev
              </button>
              <button
                className="btn-ghost btn-sm"
                disabled={offset + PAGE >= total}
                onClick={() => setOffset(offset + PAGE)}
                aria-label="Next page"
              >
                Next
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </Panel>

      {/* Frame Detail Pane */}
      <Panel
        className="xl:col-span-2 xl:sticky xl:top-16 xl:self-start"
        title="Frame Dissection"
        icon={PackageSearch}
      >
        {sel == null ? (
          <EmptyState title="Select a frame">
            Click any row in the captured frames table to inspect headers, flags, and payload length.
          </EmptyState>
        ) : (
          <Detail id={id} sel={sel} />
        )}
      </Panel>
    </div>
  );
}

function Pk({ id, nums }: { id: string; nums: number[] }) {
  if (!nums.length) return <span className="text-slate-500 font-medium">None observed</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {nums.slice(0, 6).map((n) => (
        <button
          key={n}
          className="rounded-md border border-indigo-500/25 bg-indigo-500/10 px-2 py-0.5 font-mono text-xs font-semibold text-indigo-300 hover:bg-indigo-500/20"
          onClick={() => go(`/packets/${id}?sel=${n}`)}
        >
          #{n}
        </button>
      ))}
      {nums.length > 6 && <span className="text-xs text-slate-400">+{nums.length - 6}</span>}
    </span>
  );
}

function DnsTab({ id, cap }: { id: string; cap: CaptureSummary }) {
  if (!cap.dns_transactions.length) {
    return (
      <Panel>
        <EmptyState title="No DNS query transactions observed in this capture" />
      </Panel>
    );
  }
  return (
    <Panel title="DNS Transactions" pad={false} subtitle="Matched queries and responses based on Transaction ID and QNAME">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[44rem]">
          <thead>
            <tr className="border-b border-white/[0.07] bg-white/[0.015]">
              <th className="th">Query Name</th>
              <th className="th">Type</th>
              <th className="th">Client → Resolver</th>
              <th className="th">Attempts</th>
              <th className="th">Outcome</th>
              <th className="th">Query Pkts</th>
              <th className="th">Response Pkts</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {cap.dns_transactions.map((t) => (
              <tr key={t.id} className="hover:bg-white/[0.02]">
                <td className="td font-mono font-semibold text-xs text-cyan-200">{t.qname}</td>
                <td className="td text-xs font-semibold text-slate-300">{t.qtype}</td>
                <td className="td font-mono text-xs text-slate-300">{t.client} → {t.server}</td>
                <td className="td text-xs font-mono">{t.attempts}</td>
                <td className="td text-xs">
                  {t.answered ? (
                    <span className={`font-semibold ${t.rcode_name === "NOERROR" ? "text-emerald-300" : "text-rose-300"}`}>
                      {t.rcode_name}
                    </span>
                  ) : (
                    <span className="font-semibold text-amber-300">Unanswered in capture</span>
                  )}
                </td>
                <td className="td"><Pk id={id} nums={t.query_packets} /></td>
                <td className="td"><Pk id={id} nums={t.response_packets} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function TcpTab({ id, cap }: { id: string; cap: CaptureSummary }) {
  if (!cap.tcp_flows.length) {
    return (
      <Panel>
        <EmptyState title="No TCP connection flows observed in this capture" />
      </Panel>
    );
  }
  return (
    <Panel title="TCP Connection Flows" pad={false} subtitle="Tracked handshake attempts, active resets, and segment retransmissions">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[44rem]">
          <thead>
            <tr className="border-b border-white/[0.07] bg-white/[0.015]">
              <th className="th">Flow ID</th>
              <th className="th">Client → Server</th>
              <th className="th">Frames</th>
              <th className="th">Handshake Outcome</th>
              <th className="th">RST Frames</th>
              <th className="th">Retransmissions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {cap.tcp_flows.map((f) => (
              <tr key={f.id} className="hover:bg-white/[0.02]">
                <td className="td font-mono text-xs font-semibold text-indigo-200">{f.id}</td>
                <td className="td font-mono text-xs text-slate-300">{f.client} → {f.server}</td>
                <td className="td text-xs font-mono">{f.packets}</td>
                <td className="td text-xs text-slate-200 font-medium">{f.outcome}</td>
                <td className="td"><Pk id={id} nums={f.reset_packets} /></td>
                <td className="td"><Pk id={id} nums={f.retransmission_packets} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

export function PacketExplorer({ id }: { id?: string }) {
  const { list } = useApp();
  const { query } = useRoute();
  const [tab, setTab] = useState<"packets" | "events" | "dns" | "tcp">("packets");
  const q = useAsync(() => (id ? api.get(id) : Promise.resolve(null)), [id]);

  if (!id) return <Picker />;
  if (q.loading && !q.data) {
    return (
      <div className="space-y-6">
        <PageHeader title="Packet Analysis Explorer" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
      </div>
    );
  }
  if (q.error || !q.data) {
    return (
      <div className="space-y-4">
        <PageHeader title="Packet Analysis Explorer" />
        <ErrorBox message={q.error ?? "Investigation not found"} onRetry={q.reload} />
        <button className="btn-ghost mt-2" onClick={() => go("/packets")}>
          Select Another Capture
        </button>
      </div>
    );
  }

  const inv = q.data;
  const cap = inv.capture;
  const selRaw = Number(query.get("sel"));
  const sel = Number.isInteger(selRaw) && selRaw > 0 ? selRaw : null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Packet Analysis Explorer"
        subtitle={
          <div className="flex flex-wrap items-center gap-2 mt-1">
            <span>Investigation:</span>
            <a href={`#/investigations/${inv.id}`} className="font-semibold text-cyan-300 hover:underline">
              {inv.title}
            </a>
            {cap?.simulated && <SimBadge label="Synthetic PCAP" />}
          </div>
        }
        actions={
          <select
            aria-label="Switch capture file"
            className="field w-auto py-1 text-xs font-medium"
            value={id}
            onChange={(e) => go(`/packets/${e.target.value}`)}
          >
            {list
              .filter((i) => i.packet_total != null || i.id === id)
              .map((i) => (
                <option key={i.id} value={i.id}>
                  {i.title.slice(0, 48)}
                </option>
              ))}
          </select>
        }
      />

      {!cap ? (
        <Panel>
          <EmptyState
            icon={PackageSearch}
            title="No packet capture attached to this investigation"
            action={
              <button className="btn-primary" onClick={() => go(`/investigations/${inv.id}`)}>
                Open Investigation
              </button>
            }
          >
            Attach a .pcap or .pcapng file from the investigation page to enable frame-by-frame analysis.
          </EmptyState>
        </Panel>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
            <Stat
              label="Total Frames"
              value={cap.total_packets.toLocaleString()}
              icon={Layers}
              hint={`${cap.file_format.toUpperCase()} · ${fmtBytes(cap.file_size_bytes)}`}
            />
            <Stat
              label="Capture Duration"
              value={`${cap.duration_seconds.toFixed(2)}s`}
              icon={Timer}
            />
            <Stat
              label="DNS Transactions"
              value={cap.dns_packets}
              icon={Network}
              hint={`${cap.dns_transactions.length} query flow(s)`}
            />
            <Stat
              label="TCP Segments"
              value={cap.tcp_packets}
              icon={PlugZap}
              hint={`${cap.tcp_flows.length} connection flow(s)`}
            />
          </div>

          {cap.warnings.map((w) => (
            <div key={w} className="mb-4">
              <ErrorBox message={w} />
            </div>
          ))}

          {cap.total_packets === 0 ? (
            <Panel>
              <EmptyState icon={PackageSearch} title="Capture contains zero packets" />
            </Panel>
          ) : (
            <>
              <div className="grid gap-6 lg:grid-cols-2">
                <Panel title="Protocol Breakdown" icon={Layers}>
                  <ProtocolChart counts={cap.protocol_counts} />
                </Panel>
                <Panel title="Traffic Density & Anomaly Frequency" icon={Timer}>
                  <TrafficChart cap={cap} />
                  <p className="mt-2 text-xs text-slate-400">
                    Highlighted red areas denote packets with anomaly flags (RST, repeated segments, or unreplied SYNs).
                  </p>
                </Panel>
              </div>

              <div>
                <Tabs
                  tabs={[
                    { id: "packets" as const, label: "Frame Inspector", count: cap.total_packets },
                    { id: "events" as const, label: "Event Log", count: cap.events.length },
                    { id: "dns" as const, label: "DNS Transactions", count: cap.dns_transactions.length },
                    { id: "tcp" as const, label: "TCP Flows", count: cap.tcp_flows.length },
                  ]}
                  value={tab}
                  onChange={setTab}
                />
              </div>

              {tab === "packets" && <PacketsTab id={id} cap={cap} sel={sel} />}
              {tab === "events" && (
                <Panel title="Notable Capture Events" subtitle="Extracted protocol anomalies and state transitions">
                  {cap.events.length ? (
                    <EventList events={cap.events} invId={id} />
                  ) : (
                    <EmptyState title="No notable anomalies detected" />
                  )}
                  {cap.events_truncated && (
                    <p className="mt-2 text-xs text-slate-500">
                      Timeline truncated to the first {cap.events.length} events for performance.
                    </p>
                  )}
                </Panel>
              )}
              {tab === "dns" && <DnsTab id={id} cap={cap} />}
              {tab === "tcp" && <TcpTab id={id} cap={cap} />}
            </>
          )}
        </>
      )}
    </div>
  );
}
