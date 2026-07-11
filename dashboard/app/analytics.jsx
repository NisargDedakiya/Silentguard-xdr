'use client';

import { useMemo } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

// Palette validated (dataviz six checks) against the slate-900 card surface.
const SURFACE = '#0f172a';
const SEVERITY_COLORS = { critical: '#ef4444', warning: '#d97706', info: '#0284c7' };
const BAR_BLUE = '#3b82f6';
const INK_MUTED = '#94a3b8';
const INK_AXIS = '#64748b';
const GRID = '#1e293b';

const DAY_MS = 24 * 60 * 60 * 1000;
const WINDOW_DAYS = 14;

function dayKey(date) {
  return date.toISOString().slice(0, 10);
}

function eventsPerDay(events) {
  const today = new Date();
  const buckets = [];
  const index = {};
  for (let i = WINDOW_DAYS - 1; i >= 0; i -= 1) {
    const d = new Date(today.getTime() - i * DAY_MS);
    const key = dayKey(d);
    index[key] = buckets.length;
    buckets.push({
      day: key,
      label: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      critical: 0,
      warning: 0,
      info: 0,
    });
  }
  for (const e of events) {
    const key = dayKey(new Date(e.timestamp));
    if (key in index) {
      const sev = e.severity in SEVERITY_COLORS ? e.severity : 'info';
      buckets[index[key]][sev] += 1;
    }
  }
  return buckets;
}

function topCounts(events, labelOf, limit = 6) {
  const counts = new Map();
  for (const e of events) {
    const label = labelOf(e);
    if (!label) continue;
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

// Blocklist enforcement actions and what was enforced.
function blocklistHitLabel(e) {
  if (e.source === 'dns_sinkhole' && e.action === 'blocked') {
    return e.details?.domain ? `domain · ${e.details.domain}` : 'domain';
  }
  if (e.source === 'port_watchdog' && (e.action === 'killed' || e.action === 'kill_failed')) {
    if (e.details?.port) return `port · ${e.details.port}`;
    if (e.details?.process) return `process · ${e.details.process}`;
  }
  return null;
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-950/95 px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-medium text-slate-200">{label}</p>
      {payload
        .filter((p) => p.value > 0)
        .map((p) => (
          <p key={p.dataKey} className="flex items-center gap-1.5 text-slate-300">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: p.fill || p.color }} />
            {p.name}: {p.value}
          </p>
        ))}
    </div>
  );
}

function SeverityLegend() {
  return (
    <div className="flex gap-4 px-5 pb-1 text-xs text-slate-400">
      {Object.entries(SEVERITY_COLORS).map(([name, color]) => (
        <span key={name} className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: color }} />
          {name}
        </span>
      ))}
    </div>
  );
}

function Card({ title, subtitle, children }) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-5 py-3">
        <p className="text-sm font-medium text-slate-300">{title}</p>
        {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
}

function StatTile({ label, value, accent }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-3xl font-semibold ${accent || 'text-slate-100'}`}>{value}</p>
    </div>
  );
}

function HBars({ data, name }) {
  if (data.length === 0) {
    return <p className="px-5 py-8 text-center text-sm text-slate-500">No data in the current window.</p>;
  }
  return (
    <div className="px-2 py-3">
      <ResponsiveContainer width="100%" height={Math.max(120, data.length * 38)}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 44, left: 8, bottom: 4 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={170}
            tickLine={false}
            axisLine={false}
            tick={{ fill: INK_MUTED, fontSize: 12 }}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(148,163,184,0.08)' }} />
          <Bar dataKey="count" name={name} fill={BAR_BLUE} barSize={14} radius={[0, 4, 4, 0]}>
            <LabelList dataKey="count" position="right" fill={INK_MUTED} fontSize={12} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default function AnalyticsView({ devices, events, blocklist }) {
  const perDay = useMemo(() => eventsPerDay(events), [events]);
  const topDevices = useMemo(() => topCounts(events, (e) => e.hostname), [events]);
  const blocklistHits = useMemo(() => topCounts(events, blocklistHitLabel), [events]);

  const criticalCount = events.filter((e) => e.severity === 'critical').length;
  const onlineCount = devices.filter((d) => d.online).length;
  const totalHits = blocklistHits.reduce((acc, h) => acc + h.count, 0);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Events (loaded window)" value={events.length} />
        <StatTile label="Critical events" value={criticalCount} accent={criticalCount > 0 ? 'text-red-400' : ''} />
        <StatTile label="Devices online" value={`${onlineCount} / ${devices.length}`} />
        <StatTile label="Blocklist enforcements" value={totalHits} />
      </div>

      <Card
        title={`Events per day by severity — last ${WINDOW_DAYS} days`}
        subtitle="Counts from the most recent events window (up to 500)"
      >
        <div className="px-2 pt-4">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={perDay} margin={{ top: 4, right: 16, left: -16, bottom: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="0" vertical={false} />
              <XAxis
                dataKey="label"
                tickLine={false}
                axisLine={{ stroke: GRID }}
                tick={{ fill: INK_AXIS, fontSize: 11 }}
                interval="preserveStartEnd"
              />
              <YAxis
                allowDecimals={false}
                tickLine={false}
                axisLine={false}
                tick={{ fill: INK_AXIS, fontSize: 11 }}
              />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(148,163,184,0.08)' }} />
              <Bar dataKey="info" name="info" stackId="sev" fill={SEVERITY_COLORS.info}
                   stroke={SURFACE} strokeWidth={2} />
              <Bar dataKey="warning" name="warning" stackId="sev" fill={SEVERITY_COLORS.warning}
                   stroke={SURFACE} strokeWidth={2} />
              <Bar dataKey="critical" name="critical" stackId="sev" fill={SEVERITY_COLORS.critical}
                   stroke={SURFACE} strokeWidth={2} radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <SeverityLegend />
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Top triggered devices" subtitle="Events per device in the loaded window">
          <HBars data={topDevices} name="events" />
        </Card>
        <Card title="Blocklist hit counts" subtitle="Enforcement actions per blocked domain / process / port">
          <HBars data={blocklistHits} name="hits" />
        </Card>
      </div>

      <p className="text-xs text-slate-600">
        Analytics are computed client-side from the {`/api/admin/events`} window ·{' '}
        {blocklist.length} blocklist entr{blocklist.length === 1 ? 'y' : 'ies'} currently active.
      </p>
    </div>
  );
}
