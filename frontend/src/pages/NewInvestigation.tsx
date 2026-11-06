import { FileUp, Globe, Loader2, Network, PlayCircle, PlugZap, Radar, ShieldAlert, Upload, X, Sparkles, Check } from "lucide-react";
import { useRef, useState, type DragEvent, type FormEvent } from "react";
import { ApiError, api } from "../api";
import { CheckCard } from "../components/domain";
import { ErrorBox, PageHeader, Panel, Tabs } from "../components/ui";
import { useApp } from "../context";
import { SYMPTOMS, errMessage, fmtBytes, go } from "../lib";
import type { CheckResult, Symptom } from "../types";

const TCP_PORTS = [443, 80, 22, 53, 25, 8080];
type Source = "live" | "pcap" | "both";
const SOURCES: { id: Source; label: string; hint: string; icon: typeof Globe }[] = [
  { id: "live", label: "Live Probes", hint: "Active DNS, TCP connect, and HTTP(S) checks", icon: Radar },
  { id: "pcap", label: "PCAP Capture", hint: "In-memory packet & flow dissection", icon: FileUp },
  { id: "both", label: "Hybrid", hint: "Combined live probes and packet capture", icon: Network },
];

function describe(e: unknown): string {
  if (e instanceof ApiError && e.fields?.length) {
    return `${e.message} ${e.fields.map((f) => `${f.field}: ${f.problem}`).join("; ")}`;
  }
  return errMessage(e);
}

function Guided() {
  const { health, refresh } = useApp();
  const maxMb = health?.limits.max_upload_mb ?? 10;
  const [symptom, setSymptom] = useState<Symptom>("dns_resolution_failure");
  const [source, setSource] = useState<Source>("live");
  const [target, setTarget] = useState("");
  const [title, setTitle] = useState("");
  const [dns, setDns] = useState(true);
  const [ports, setPorts] = useState<number[]>([443]);
  const [http, setHttp] = useState(true);
  const [scheme, setScheme] = useState<"https" | "http">("https");
  const [timeout, setTimeoutS] = useState(5);
  const [file, setFile] = useState<File | null>(null);
  const [fileErr, setFileErr] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const live = source !== "pcap";
  const wantsFile = source !== "live";

  const pick = (f: File | null | undefined) => {
    setFileErr(null);
    if (!f) return;
    if (!/\.(pcap|pcapng|cap)$/i.test(f.name)) return setFileErr("Please select a valid .pcap, .pcapng, or .cap file.");
    if (f.size > maxMb * 1048576) return setFileErr(`File size is ${fmtBytes(f.size)}; maximum allowed is ${maxMb} MB.`);
    if (f.size === 0) return setFileErr("The selected capture file is empty.");
    setFile(f);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDrag(false);
    pick(e.dataTransfer.files[0]);
  };

  const togglePort = (p: number) =>
    setPorts((cur) =>
      cur.includes(p) ? cur.filter((x) => x !== p) : cur.length >= 3 ? cur : [...cur, p].sort((a, b) => a - b)
    );

  const applyPreset = (presetSymptom: Symptom, presetTarget: string, presetTitle: string) => {
    setSymptom(presetSymptom);
    setTarget(presetTarget);
    setTitle(presetTitle);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (live && !target.trim()) return setError("Please specify a target domain name or public IP address.");
    if (live && !dns && !ports.length && !http) return setError("Please select at least one live probe check to run.");
    if (wantsFile && !file) return setFileErr("Please select a packet capture file to analyze.");

    let createdId: string | null = null;
    try {
      setBusy(live ? "Executing live checks…" : "Creating investigation…");
      const inv = await api.create({
        title: title.trim() || undefined,
        symptom,
        target: target.trim() || undefined,
        source,
        live: { dns, tcp_ports: ports, http, http_scheme: scheme, timeout },
      });
      createdId = inv.id;
      if (wantsFile && file) {
        setBusy("Parsing packet frames in memory…");
        await api.upload(inv.id, file);
      }
      refresh();
      go(`/investigations/${inv.id}`);
    } catch (err) {
      if (createdId) {
        try {
          await api.remove(createdId);
        } catch {
          /* ignore */
        }
        refresh();
      }
      setError(describe(err) + (createdId ? " The investigation was not saved." : ""));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Quick Presets Bar */}
      <div className="corner-hud relative rounded-xl border border-neuro-cyan/20 bg-neuro-card/85 p-3.5 flex flex-wrap items-center justify-between gap-2.5 backdrop-blur-xl">
        <div className="flex items-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider text-neuro-cyan">
          <Sparkles className="h-3.5 w-3.5 text-neuro-cyan" />
          <span>[ PRESETS // TELEMETRY PROFILES ]:</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => applyPreset("dns_resolution_failure", "example.com", "DNS Check: example.com")}
            className="rounded border border-neuro-cyan/30 bg-neuro-cyan/10 px-2.5 py-1 font-mono text-xs text-neuro-cyan hover:bg-neuro-cyan/20 hover:shadow-[0_0_10px_rgba(0,240,255,0.25)] transition-all"
          >
            DNS (example.com)
          </button>
          <button
            type="button"
            onClick={() => applyPreset("connection_failure", "cloudflare.com", "HTTPS Probe: cloudflare.com")}
            className="rounded border border-neuro-violet/30 bg-neuro-violet/10 px-2.5 py-1 font-mono text-xs text-neuro-violet hover:bg-neuro-violet/20 hover:shadow-[0_0_10px_rgba(123,44,191,0.25)] transition-all"
          >
            HTTPS (cloudflare.com)
          </button>
          <button
            type="button"
            onClick={() => applyPreset("http_error", "httpbin.org", "HTTP API: httpbin.org")}
            className="rounded border border-neuro-emerald/30 bg-neuro-emerald/10 px-2.5 py-1 font-mono text-xs text-neuro-emerald hover:bg-neuro-emerald/20 hover:shadow-[0_0_10px_rgba(0,255,136,0.25)] transition-all"
          >
            HTTP API (httpbin.org)
          </button>
        </div>
      </div>

      <form onSubmit={submit} className="grid gap-6 xl:grid-cols-3" noValidate>
        <div className="space-y-6 xl:col-span-2">
          {/* Step 1: Symptom */}
          <Panel title="1. Reported Symptom" icon={ShieldAlert}>
            <div role="radiogroup" aria-label="Reported symptom" className="grid gap-2.5 sm:grid-cols-2">
              {SYMPTOMS.map((s) => {
                const active = symptom === s.value;
                return (
                  <label
                    key={s.value}
                    className={`corner-hud relative cursor-pointer rounded-lg border p-3.5 transition-all duration-150 ${
                      active
                        ? "border-neuro-cyan/60 bg-neuro-cyan/15 shadow-[0_0_15px_rgba(0,240,255,0.2)]"
                        : "border-white/[0.07] bg-neuro-surface/30 hover:border-neuro-cyan/30 hover:bg-neuro-surface/60"
                    }`}
                  >
                    <input
                      type="radio"
                      name="symptom"
                      className="sr-only"
                      checked={active}
                      onChange={() => setSymptom(s.value)}
                    />
                    <div className="flex items-center justify-between">
                      <span className="font-display text-xs sm:text-sm font-bold tracking-wide text-white">{s.label}</span>
                      {active && (
                        <div className="grid h-4 w-4 place-items-center rounded-full bg-neuro-cyan text-black">
                          <Check className="h-3 w-3 stroke-[3]" />
                        </div>
                      )}
                    </div>
                    <span className="mt-1 block text-xs text-slate-300 leading-relaxed font-normal">{s.hint}</span>
                  </label>
                );
              })}
            </div>
          </Panel>

          {/* Step 2: Diagnostic Source */}
          <Panel title="2. Investigation Method" icon={Radar}>
            <div role="radiogroup" aria-label="Investigation method" className="grid gap-2.5 sm:grid-cols-3">
              {SOURCES.map((s) => {
                const active = source === s.id;
                return (
                  <label
                    key={s.id}
                    className={`corner-hud relative cursor-pointer rounded-lg border p-3.5 transition-all duration-150 ${
                      active
                        ? "border-neuro-cyan/60 bg-neuro-cyan/15 shadow-[0_0_15px_rgba(0,240,255,0.2)]"
                        : "border-white/[0.07] bg-neuro-surface/30 hover:border-neuro-cyan/30 hover:bg-neuro-surface/60"
                    }`}
                  >
                    <input
                      type="radio"
                      name="source"
                      className="sr-only"
                      checked={active}
                      onChange={() => setSource(s.id)}
                    />
                    <s.icon className={`mb-1.5 h-4 w-4 ${active ? "text-neuro-cyan drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-400"}`} />
                    <span className="block font-display text-xs sm:text-sm font-bold tracking-wide text-white">{s.label}</span>
                    <span className="mt-0.5 block text-xs text-slate-300 leading-relaxed font-normal">{s.hint}</span>
                  </label>
                );
              })}
            </div>
          </Panel>

          {/* Step 3: Live Probes */}
          {live && (
            <Panel title="3. Live Network Probes" icon={Globe}>
              <div className="space-y-4">
                <div>
                  <label className="label font-mono text-xs uppercase" htmlFor="target">
                    Target Domain or Public IPv4/IPv6 Address
                  </label>
                  <input
                    id="target"
                    className="field font-mono text-xs sm:text-sm"
                    placeholder="e.g. example.com or 93.184.216.34"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <p className="mt-1.5 font-mono text-xs text-slate-400">
                    [RFC 1918 private subnets and loopback addresses are blocked]
                  </p>
                </div>

                <div className="grid gap-4 sm:grid-cols-2 pt-2 border-t border-neuro-cyan/15">
                  <div>
                    <span className="label font-mono text-xs uppercase">Protocols to Check</span>
                    <div className="space-y-2 mt-2 text-xs sm:text-sm">
                      <label className="flex items-center gap-2 font-medium text-slate-200 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={dns}
                          onChange={(e) => setDns(e.target.checked)}
                          className="h-3.5 w-3.5 rounded accent-cyan-400 cursor-pointer"
                        />
                        DNS Resolution (A records)
                      </label>
                      <label className="flex items-center gap-2 font-medium text-slate-200 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={http}
                          onChange={(e) => setHttp(e.target.checked)}
                          className="h-3.5 w-3.5 rounded accent-cyan-400 cursor-pointer"
                        />
                        HTTP(S) Request:
                        <select
                          aria-label="HTTP Scheme"
                          className="field ml-1 w-auto py-0.5 px-2 text-xs font-semibold"
                          value={scheme}
                          onChange={(e) => setScheme(e.target.value as "http" | "https")}
                        >
                          <option value="https">HTTPS</option>
                          <option value="http">HTTP</option>
                        </select>
                      </label>
                    </div>
                  </div>

                  <div>
                    <span className="label font-mono text-xs uppercase">TCP Connect Ports (Select up to 3)</span>
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {TCP_PORTS.map((p) => {
                        const active = ports.includes(p);
                        return (
                          <label
                            key={p}
                            className={`cursor-pointer rounded border px-2.5 py-1 font-mono text-xs font-semibold transition ${
                              active
                                ? "border-neuro-cyan/60 bg-neuro-cyan/20 text-neuro-cyan shadow-[0_0_8px_rgba(0,240,255,0.3)]"
                                : "border-white/[0.08] bg-white/[0.02] text-slate-400 hover:text-slate-200"
                            }`}
                          >
                            <input
                              type="checkbox"
                              className="sr-only"
                              checked={active}
                              onChange={() => togglePort(p)}
                            />
                            Port {p}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-neuro-cyan/15">
                  <div className="flex items-center justify-between mb-1">
                    <label className="label font-mono text-xs uppercase !mb-0" htmlFor="timeout">
                      Socket Latency Timeout
                    </label>
                    <span className="font-mono text-xs font-semibold text-neuro-cyan">{timeout} seconds</span>
                  </div>
                  <input
                    id="timeout"
                    type="range"
                    min={1}
                    max={10}
                    value={timeout}
                    onChange={(e) => setTimeoutS(Number(e.target.value))}
                    className="w-full accent-cyan-400 cursor-pointer"
                  />
                </div>
              </div>
            </Panel>
          )}

          {/* Step 4: PCAP File Upload */}
          {wantsFile && (
            <Panel title={live ? "4. Packet Capture Evidence" : "3. Packet Capture Evidence"} icon={Upload}>
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setDrag(true);
                }}
                onDragLeave={() => setDrag(false)}
                onDrop={onDrop}
                className={`corner-hud relative rounded-xl border-2 border-dashed p-6 text-center transition-all ${
                  drag
                    ? "border-neuro-cyan bg-neuro-cyan/10 shadow-[0_0_20px_rgba(0,240,255,0.25)]"
                    : "border-neuro-cyan/30 bg-neuro-surface/30 hover:border-neuro-cyan/60 hover:shadow-[0_0_15px_rgba(0,240,255,0.12)]"
                }`}
              >
                {file ? (
                  <div className="flex items-center justify-center gap-3">
                    <div className="grid h-9 w-9 place-items-center rounded-lg bg-neuro-cyan/10 text-neuro-cyan">
                      <FileUp className="h-4.5 w-4.5" />
                    </div>
                    <div className="text-left">
                      <span className="block font-mono text-xs sm:text-sm font-semibold text-white">{file.name}</span>
                      <span className="font-mono text-xs text-slate-400">{fmtBytes(file.size)}</span>
                    </div>
                    <button
                      type="button"
                      className="btn-ghost btn-sm ml-2 text-rose-300 hover:border-rose-500/40"
                      onClick={() => {
                        setFile(null);
                        if (input.current) input.current.value = "";
                      }}
                      aria-label="Remove capture file"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ) : (
                  <>
                    <Upload className="mx-auto mb-2 h-7 w-7 text-neuro-cyan/70" />
                    <p className="font-display text-xs sm:text-sm font-bold tracking-wide text-slate-200">
                      DRAG & DROP PCAP CAPTURE FILE
                    </p>
                    <p className="mt-0.5 font-mono text-xs text-slate-400">or</p>
                    <button
                      type="button"
                      className="btn-ghost btn-sm mt-2 border-neuro-cyan/40 text-neuro-cyan hover:bg-neuro-cyan/15 font-mono text-xs"
                      onClick={() => input.current?.click()}
                    >
                      [ SELECT PCAP FILE ]
                    </button>
                    <p className="mt-2 font-mono text-[11px] text-slate-400">
                      Wireshark/tcpdump .pcap & .pcapng · max {maxMb} MB · parsed in memory only
                    </p>
                  </>
                )}
                <input
                  ref={input}
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  className="sr-only"
                  aria-label="Upload capture file"
                  onChange={(e) => pick(e.target.files?.[0])}
                />
              </div>
              {fileErr && <p role="alert" className="mt-2 text-xs text-rose-300">{fileErr}</p>}
            </Panel>
          )}
        </div>

        {/* Right Summary Sidebar */}
        <div className="space-y-6">
          <Panel title="Investigation Plan" icon={PlayCircle}>
            <div>
              <label className="label" htmlFor="title">
                Investigation Title (Optional)
              </label>
              <input
                id="title"
                className="field text-xs sm:text-sm"
                maxLength={120}
                placeholder="e.g. Gateway Latency Incident"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>

            <div className="mt-3.5 rounded-lg border border-white/[0.06] bg-ink-950/60 p-3.5 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Symptom:</span>
                <span className="font-semibold text-slate-200">
                  {SYMPTOMS.find((s) => s.value === symptom)?.label}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Method:</span>
                <span className="font-semibold text-cyan-300 capitalize">
                  {SOURCES.find((s) => s.id === source)?.label}
                </span>
              </div>
              {live && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Checks:</span>
                  <span className="font-mono text-slate-200">
                    {[dns && "DNS", ...ports.map((p) => `TCP:${p}`), http && scheme.toUpperCase()].filter(Boolean).join(", ") || "None"}
                  </span>
                </div>
              )}
              {wantsFile && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Capture:</span>
                  <span className="font-mono text-slate-200 truncate max-w-[140px]">
                    {file?.name ?? "None chosen"}
                  </span>
                </div>
              )}
            </div>

            {error && (
              <div className="mt-3">
                <ErrorBox message={error} />
              </div>
            )}

            <button type="submit" className="btn-primary mt-4 w-full py-2.5" disabled={busy !== null}>
              {busy ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {busy}
                </>
              ) : (
                <>
                  <PlayCircle className="h-4 w-4" />
                  Start Investigation
                </>
              )}
            </button>
          </Panel>
        </div>
      </form>
    </div>
  );
}

function SingleCheck() {
  const [kind, setKind] = useState<"dns" | "tcp" | "http">("dns");
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("443");
  const [url, setUrl] = useState("https://");
  const [timeout, setTimeoutS] = useState(5);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CheckResult | null>(null);

  const run = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      if (kind === "dns") {
        setResult(await api.checkDns(target.trim(), "A", timeout));
      } else if (kind === "tcp") {
        setResult(await api.checkTcp(target.trim(), Number(port), timeout));
      } else {
        setResult(await api.checkHttp(url.trim(), "GET", timeout));
      }
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-6 xl:grid-cols-2">
      <Panel title="Ad-Hoc Network Probe" icon={PlugZap}>
        <form onSubmit={run} className="space-y-4" noValidate>
          <div className="flex gap-2">
            {(["dns", "tcp", "http"] as const).map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setKind(k)}
                className={`flex-1 rounded-lg border py-1.5 text-xs font-semibold uppercase tracking-wider transition ${
                  kind === k
                    ? "border-cyan-500/50 bg-cyan-500/15 text-white"
                    : "border-white/[0.08] bg-white/[0.02] text-slate-400 hover:text-white"
                }`}
              >
                {k.toUpperCase()}
              </button>
            ))}
          </div>

          {kind === "dns" && (
            <div>
              <label className="label" htmlFor="dns-target">Domain Name</label>
              <input
                id="dns-target"
                className="field font-mono text-xs sm:text-sm"
                placeholder="example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
          )}

          {kind === "tcp" && (
            <div className="grid grid-cols-3 gap-2">
              <div className="col-span-2">
                <label className="label" htmlFor="tcp-host">Host Address</label>
                <input
                  id="tcp-host"
                  className="field font-mono text-xs sm:text-sm"
                  placeholder="example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
              </div>
              <div>
                <label className="label" htmlFor="tcp-port">Port</label>
                <input
                  id="tcp-port"
                  className="field font-mono text-xs sm:text-sm"
                  placeholder="443"
                  value={port}
                  onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))}
                />
              </div>
            </div>
          )}

          {kind === "http" && (
            <div>
              <label className="label" htmlFor="http-url">Target URL</label>
              <input
                id="http-url"
                className="field font-mono text-xs sm:text-sm"
                placeholder="https://example.com/"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
          )}

          <div>
            <div className="flex justify-between mb-1">
              <label className="label !mb-0" htmlFor="timeout-single">Timeout</label>
              <span className="font-mono text-xs font-semibold text-cyan-300">{timeout} s</span>
            </div>
            <input
              id="timeout-single"
              type="range"
              min={1}
              max={10}
              value={timeout}
              onChange={(e) => setTimeoutS(Number(e.target.value))}
              className="w-full accent-cyan-400 cursor-pointer"
            />
          </div>

          {error && <ErrorBox message={error} />}

          <button type="submit" className="btn-primary w-full py-2.5" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
            Execute Probe
          </button>
        </form>
      </Panel>

      <div>
        {result ? (
          <CheckCard c={result} />
        ) : (
          <Panel title="Probe Output" icon={Radar}>
            <div className="p-8 text-center text-xs text-slate-400">
              Run a single ad-hoc diagnostic probe to view real-time latency and status codes.
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}

export function NewInvestigation() {
  const [tab, setTab] = useState<"guided" | "single">("guided");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Start Diagnostic Investigation"
        subtitle="Combine live network checks with packet captures to evaluate evidence against formal diagnostic rules."
      />

      <div>
        <Tabs
          tabs={[
            { id: "guided" as const, label: "Full Guided Investigation" },
            { id: "single" as const, label: "Ad-Hoc Network Probe" },
          ]}
          value={tab}
          onChange={setTab}
        />
      </div>

      {tab === "guided" ? <Guided /> : <SingleCheck />}
    </div>
  );
}
