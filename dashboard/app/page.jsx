'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import AnalyticsView from './analytics';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

function adminHeaders(token) {
  return { 'X-Admin-Token': token, 'Content-Type': 'application/json' };
}

const SEVERITY_STYLES = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/40',
  warning: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  info: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
};

function SeverityBadge({ severity }) {
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs border ${SEVERITY_STYLES[severity] || SEVERITY_STYLES.info}`}>
      {severity}
    </span>
  );
}

const RISK_STYLES = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/40',
  elevated: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  low: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
  clear: 'bg-slate-700/40 text-slate-400 border-slate-600/40',
};

function MitreTag({ mitre }) {
  if (!mitre) return null;
  return (
    <a
      href={mitre.url}
      target="_blank"
      rel="noreferrer"
      title={`MITRE ATT&CK — ${mitre.name}`}
      className="rounded border border-violet-500/40 bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-mono text-violet-300 hover:bg-violet-500/30"
    >
      {mitre.id}
    </a>
  );
}

function RiskBadge({ score, band }) {
  return (
    <span
      title={`Risk score ${score} — ${band} (rolling 24h)`}
      className={`px-2 py-0.5 rounded-full text-xs border ${RISK_STYLES[band] || RISK_STYLES.clear}`}
    >
      {score} · {band}
    </span>
  );
}

export default function Dashboard() {
  const [token, setToken] = useState('');
  const [authed, setAuthed] = useState(false);
  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const [blocklist, setBlocklist] = useState([]);
  const [quarantine, setQuarantine] = useState([]);
  const [newEntry, setNewEntry] = useState({ kind: 'domain', value: '' });
  const [error, setError] = useState('');
  const [wsLive, setWsLive] = useState(false);
  const [tab, setTab] = useState('overview');
  const tokenRef = useRef('');

  const refresh = useCallback(async (tok) => {
    const t = tok ?? tokenRef.current;
    const [d, e, b, q] = await Promise.all([
      fetch(`${API}/api/admin/devices`, { headers: adminHeaders(t) }),
      fetch(`${API}/api/admin/events?limit=500`, { headers: adminHeaders(t) }),
      fetch(`${API}/api/admin/blocklist`, { headers: adminHeaders(t) }),
      fetch(`${API}/api/admin/quarantine`, { headers: adminHeaders(t) }),
    ]);
    if (d.status === 401) throw new Error('Invalid admin token');
    setDevices(await d.json());
    setEvents(await e.json());
    setBlocklist(await b.json());
    setQuarantine(await q.json());
  }, []);

  const login = async (ev) => {
    ev.preventDefault();
    setError('');
    try {
      tokenRef.current = token;
      await refresh(token);
      setAuthed(true);
    } catch (err) {
      setError(err.message || 'Login failed');
    }
  };

  // Live updates: WebSocket push + slow polling fallback for online status.
  useEffect(() => {
    if (!authed) return undefined;
    const wsUrl =
      API.replace(/^http/, 'ws') + '/api/ws?token=' + encodeURIComponent(tokenRef.current);
    let ws;
    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setWsLive(true);
      ws.onclose = () => setWsLive(false);
      ws.onmessage = () => refresh();
    } catch {
      /* fall back to polling */
    }
    const iv = setInterval(() => refresh().catch(() => {}), 5000);
    return () => {
      clearInterval(iv);
      if (ws) ws.close();
    };
  }, [authed, refresh]);

  const setIsolation = async (deviceId, isolate) => {
    await fetch(`${API}/api/admin/devices/${deviceId}/${isolate ? 'isolate' : 'release'}`, {
      method: 'POST',
      headers: adminHeaders(tokenRef.current),
    });
    refresh();
  };

  const addBlocklist = async (ev) => {
    ev.preventDefault();
    if (!newEntry.value.trim()) return;
    await fetch(`${API}/api/admin/blocklist`, {
      method: 'POST',
      headers: adminHeaders(tokenRef.current),
      body: JSON.stringify({ kind: newEntry.kind, value: newEntry.value.trim() }),
    });
    setNewEntry({ ...newEntry, value: '' });
    refresh();
  };

  const removeBlocklist = async (id) => {
    await fetch(`${API}/api/admin/blocklist/${id}`, {
      method: 'DELETE',
      headers: adminHeaders(tokenRef.current),
    });
    refresh();
  };

  const restoreQuarantine = async (id) => {
    await fetch(`${API}/api/admin/quarantine/${id}/restore`, {
      method: 'POST',
      headers: adminHeaders(tokenRef.current),
    });
    refresh();
  };

  if (!authed) {
    return (
      <main className="flex min-h-screen items-center justify-center p-6">
        <form onSubmit={login} className="w-full max-w-sm space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-8">
          <h1 className="text-xl font-semibold">
            <span className="text-emerald-400">SilentGuard</span> XDR
          </h1>
          <p className="text-sm text-slate-400">Command Matrix — admin sign in</p>
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Admin token"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500"
          />
          {error && <p className="text-sm text-red-400">{error}</p>}
          <button type="submit" className="w-full rounded-lg bg-emerald-600 py-2 text-sm font-medium hover:bg-emerald-500">
            Sign in
          </button>
        </form>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-7xl space-y-6 p-6">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">
          <span className="text-emerald-400">SilentGuard</span> XDR — Command Matrix
        </h1>
        <div className="flex items-center gap-4">
          <nav className="flex rounded-lg border border-slate-800 bg-slate-900 p-0.5 text-xs">
            {['overview', 'analytics'].map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`rounded-md px-3 py-1.5 font-medium capitalize ${
                  tab === t ? 'bg-slate-700 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t}
              </button>
            ))}
          </nav>
          <span className={`text-xs ${wsLive ? 'text-emerald-400' : 'text-slate-500'}`}>
            {wsLive ? '● live stream connected' : '○ polling mode'}
          </span>
        </div>
      </header>

      {tab === 'analytics' && (
        <AnalyticsView devices={devices} events={events} blocklist={blocklist} />
      )}

      {tab === 'overview' && (
      <>
      {/* Fleet overview */}
      <section className="rounded-xl border border-slate-800 bg-slate-900">
        <div className="border-b border-slate-800 px-5 py-3 text-sm font-medium text-slate-300">
          Device Fleet ({devices.length})
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500">
              <tr>
                <th className="px-5 py-2">Hostname</th>
                <th className="px-5 py-2">Platform</th>
                <th className="px-5 py-2">Status</th>
                <th className="px-5 py-2">Risk</th>
                <th className="px-5 py-2">Last seen</th>
                <th className="px-5 py-2">Isolation</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id} className="border-t border-slate-800/60">
                  <td className="px-5 py-3 font-medium">{d.hostname}</td>
                  <td className="px-5 py-3 text-slate-400">{d.platform}</td>
                  <td className="px-5 py-3">
                    {d.isolated ? (
                      <span className="text-red-400">⛔ isolated</span>
                    ) : d.online ? (
                      <span className="text-emerald-400">● online</span>
                    ) : (
                      <span className="text-slate-500">○ offline</span>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    <RiskBadge score={d.risk_score} band={d.risk_band} />
                  </td>
                  <td className="px-5 py-3 text-slate-400">{new Date(d.last_seen).toLocaleString()}</td>
                  <td className="px-5 py-3">
                    <button
                      onClick={() => setIsolation(d.id, !d.isolated)}
                      className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                        d.isolated
                          ? 'bg-slate-700 hover:bg-slate-600'
                          : 'bg-red-600 hover:bg-red-500'
                      }`}
                    >
                      {d.isolated ? 'Release' : 'Isolate device'}
                    </button>
                  </td>
                </tr>
              ))}
              {devices.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-6 text-center text-slate-500">
                    No devices enrolled yet — start an agent to see it here.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Threat timeline */}
        <section className="rounded-xl border border-slate-800 bg-slate-900 lg:col-span-2">
          <div className="border-b border-slate-800 px-5 py-3 text-sm font-medium text-slate-300">
            Threat Timeline
          </div>
          <ul className="max-h-[32rem] divide-y divide-slate-800/60 overflow-y-auto">
            {events.map((e) => (
              <li key={e.id} className="flex items-start gap-3 px-5 py-3">
                <SeverityBadge severity={e.severity} />
                <div className="min-w-0 flex-1">
                  <p className="text-sm">
                    {e.summary} <MitreTag mitre={e.mitre} />
                  </p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {e.hostname} · {e.source} · {e.action} · {new Date(e.timestamp).toLocaleString()}
                  </p>
                </div>
              </li>
            ))}
            {events.length === 0 && (
              <li className="px-5 py-6 text-center text-sm text-slate-500">No events yet.</li>
            )}
          </ul>
        </section>

        {/* Blocklist management */}
        <section className="rounded-xl border border-slate-800 bg-slate-900">
          <div className="border-b border-slate-800 px-5 py-3 text-sm font-medium text-slate-300">
            Fleet Blocklist
          </div>
          <form onSubmit={addBlocklist} className="flex gap-2 border-b border-slate-800 p-4">
            <select
              value={newEntry.kind}
              onChange={(e) => setNewEntry({ ...newEntry, kind: e.target.value })}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs"
            >
              <option value="domain">domain</option>
              <option value="process">process</option>
              <option value="port">port</option>
            </select>
            <input
              value={newEntry.value}
              onChange={(e) => setNewEntry({ ...newEntry, value: e.target.value })}
              placeholder="evil.example / mimikatz.exe / 4444"
              className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs outline-none focus:border-emerald-500"
            />
            <button type="submit" className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium hover:bg-emerald-500">
              Push
            </button>
          </form>
          <ul className="max-h-96 divide-y divide-slate-800/60 overflow-y-auto">
            {blocklist.map((b) => (
              <li key={b.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
                <span>
                  <span className="mr-2 rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{b.kind}</span>
                  {b.value}
                </span>
                <button onClick={() => removeBlocklist(b.id)} className="text-xs text-slate-500 hover:text-red-400">
                  remove
                </button>
              </li>
            ))}
            {blocklist.length === 0 && (
              <li className="px-4 py-5 text-center text-sm text-slate-500">
                No fleet blocklist entries — agents use their built-in defaults.
              </li>
            )}
          </ul>
        </section>
      </div>

      {/* Quarantine */}
      <section className="rounded-xl border border-slate-800 bg-slate-900">
        <div className="border-b border-slate-800 px-5 py-3 text-sm font-medium text-slate-300">
          Quarantine ({quarantine.filter((q) => q.status !== 'restored').length} active)
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500">
              <tr>
                <th className="px-5 py-2">File</th>
                <th className="px-5 py-2">Host</th>
                <th className="px-5 py-2">SHA-256</th>
                <th className="px-5 py-2">Verdict</th>
                <th className="px-5 py-2">Status</th>
                <th className="px-5 py-2" />
              </tr>
            </thead>
            <tbody>
              {quarantine.map((q) => (
                <tr key={q.id} className="border-t border-slate-800/60">
                  <td className="px-5 py-3 font-mono text-xs">{q.original_path}</td>
                  <td className="px-5 py-3 text-slate-400">{q.hostname}</td>
                  <td className="px-5 py-3 font-mono text-xs text-slate-500" title={q.sha256}>
                    {q.sha256 ? `${q.sha256.slice(0, 12)}…` : '—'}
                  </td>
                  <td className="px-5 py-3">
                    <span className={q.verdict === 'known_bad' ? 'text-red-400' : 'text-slate-400'}>
                      {q.verdict}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-slate-400">{q.status}</td>
                  <td className="px-5 py-3 text-right">
                    {q.status === 'quarantined' && (
                      <button
                        onClick={() => restoreQuarantine(q.id)}
                        className="rounded-lg bg-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-600"
                      >
                        Restore
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {quarantine.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-6 text-center text-slate-500">
                    Nothing in quarantine.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
      </>
      )}
    </main>
  );
}
