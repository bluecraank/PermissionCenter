import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { AlertTriangle, Building2, FolderLock, FolderTree, Server, Share2, Users } from 'lucide-react'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  EmptyState,
  ErrorState,
  GradeBadge,
  Loading,
  PageHeader,
  ScoreGauge,
  SeverityBadge,
  SeverityDots,
  StatCard,
} from '@/components/common'
import { api, type Dashboard } from '@/lib/api'
import { dateTime, num, relative, SEVERITIES, severityColor, severityLabel } from '@/lib/format'

export default function DashboardPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ['dashboard'], queryFn: () => api.get<Dashboard>('/dashboard') })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={8} />

  const chart = SEVERITIES.map((s) => ({ key: s, name: severityLabel[s], value: data.findings[s] }))
  const empty = data.totals.systems === 0

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={
          data.analysis_at ? `Letzte Analyse ${relative(data.analysis_at)} (${dateTime(data.analysis_at)})` : 'Noch keine Analyse'
        }
      />

      {empty && (
        <EmptyState title="Noch keine Scan-Ergebnisse">
          Installieren Sie den <code>pc-client</code> auf den Windows-Servern und tragen Sie diese Server-Adresse in
          <code> pc-client.toml</code> ein. Nach dem ersten Scan erscheinen hier die Ergebnisse.
        </EmptyState>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Sicherheitsbewertung</CardTitle>
            <CardDescription>0–100 Punkte, gewichtet nach Schwere und Umfang der Befunde</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-center justify-around gap-2">
            <ScoreGauge score={data.score} label="Gesamt" />
            <div className="flex gap-2">
              <div className="scale-75">
                <ScoreGauge score={data.infrastructure_score} label="Dateisysteme" />
              </div>
              <div className="scale-75">
                <ScoreGauge score={data.ad_score} label="Active Directory" />
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-2 gap-4 lg:col-span-2 xl:grid-cols-3">
          <StatCard title="Systeme" value={num(data.totals.systems)} icon={<Server className="size-4" />} to="/systems" />
          <StatCard
            title="Gescannte Ordner"
            value={num(data.totals.folders_scanned)}
            icon={<FolderTree className="size-4" />}
            hint={`${num(data.totals.folders_reported)} mit Detaildaten`}
          />
          <StatCard
            title="Eigene Berechtigungen"
            value={num(data.totals.explicit_folders)}
            icon={<FolderLock className="size-4" />}
            hint="Ordner mit expliziten ACEs"
          />
          <StatCard title="Freigaben" value={num(data.totals.shares)} icon={<Share2 className="size-4" />} />
          <StatCard
            title="Berechtigte Prinzipale"
            value={num(data.totals.principals)}
            icon={<Users className="size-4" />}
            to="/principals"
          />
          <StatCard
            title="Kritisch + Hoch"
            value={num(data.findings.critical + data.findings.high)}
            icon={<AlertTriangle className="size-4" />}
            tone={data.findings.critical + data.findings.high > 0 ? 'bad' : undefined}
            to="/findings?severity=high"
          />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Befunde nach Schwere</CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chart} margin={{ left: -20 }}>
                <XAxis dataKey="name" tickLine={false} axisLine={false} fontSize={12} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} fontSize={12} />
                <Tooltip
                  cursor={{ fill: 'var(--muted)' }}
                  contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8 }}
                />
                <Bar dataKey="value" name="Befunde" radius={[6, 6, 0, 0]}>
                  {chart.map((c) => (
                    <Cell key={c.key} fill={severityColor[c.key]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle>Häufigste Probleme</CardTitle>
            <CardDescription>Nach Schwere und Anzahl betroffener Objekte</CardDescription>
          </CardHeader>
          <CardContent>
            {data.top_rules.length === 0 ? (
              <p className="text-muted-foreground text-sm">Keine Befunde.</p>
            ) : (
              <div className="space-y-1">
                {data.top_rules.slice(0, 7).map((r) => (
                  <Link
                    key={r.rule}
                    to={`/findings?rule=${r.rule}`}
                    className="hover:bg-accent flex items-center gap-3 rounded-md px-2 py-1.5 text-sm"
                  >
                    <SeverityBadge severity={r.severity} className="w-20 justify-center" />
                    <span className="flex-1 truncate">{r.title}</span>
                    <span className="text-muted-foreground tabular-nums">
                      {num(r.findings)} Befunde · {num(r.affected)} Objekte
                    </span>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Systeme</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">Note</TableHead>
                  <TableHead>System</TableHead>
                  <TableHead className="hidden md:table-cell">Letzter Scan</TableHead>
                  <TableHead className="text-right">Ordner</TableHead>
                  <TableHead>Befunde</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.systems.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <GradeBadge score={s.score} size="sm" />
                    </TableCell>
                    <TableCell>
                      <Link to={`/systems/${s.id}`} className="font-medium hover:underline">
                        {s.hostname}
                      </Link>
                      <div className="text-muted-foreground text-xs">{s.os_name}</div>
                    </TableCell>
                    <TableCell className="text-muted-foreground hidden md:table-cell">{relative(s.last_scan_at)}</TableCell>
                    <TableCell className="text-right tabular-nums">{num(s.folders_scanned)}</TableCell>
                    <TableCell>
                      <SeverityDots counts={s.findings} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Active Directory</CardTitle>
              <Building2 className="text-muted-foreground size-4" />
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {data.ad.loaded ? (
                <>
                  <Row k="Domäne" v={data.ad.domain ?? '–'} />
                  <Row k="Benutzer" v={num(data.ad.users)} />
                  <Row k="Gruppen" v={num(data.ad.groups)} />
                  <Row k="Computer" v={num(data.ad.computers)} />
                  <Row k="Stand" v={`${relative(data.ad.synced_at)} (${data.ad.source === 'ldap' ? 'LDAP' : 'Import'})`} />
                </>
              ) : (
                <p className="text-muted-foreground">
                  Noch keine AD-Daten. <Link to="/ad" className="underline">Jetzt synchronisieren oder importieren</Link>.
                </p>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Letzte Scans</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {data.recent_scans.length === 0 && <p className="text-muted-foreground">–</p>}
              {data.recent_scans.map((s, i) => (
                <div key={i} className="flex justify-between gap-2">
                  <Link to={`/systems/${s.system_id}`} className="truncate hover:underline">
                    {s.hostname}
                  </Link>
                  <span className="text-muted-foreground shrink-0">{relative(s.received_at)}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-muted-foreground">{k}</span>
      <span className="truncate font-medium">{v}</span>
    </div>
  )
}
