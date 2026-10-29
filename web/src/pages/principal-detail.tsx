import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Download, FileText, Folder, History, Share2 } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  PrincipalIcon,
  PrincipalLink,
  RightsBadge,
  SeverityBadge,
  StatusBadge,
} from '@/components/common'
import { GraphLegend, GraphView } from '@/components/graph-view'
import { api, type AccessEntry, type GraphData, type GraphNode, type PrincipalDetail } from '@/lib/api'
import { dateTime, kindLabel, num } from '@/lib/format'

export default function PrincipalDetailPage() {
  const sid = decodeURIComponent(useParams().sid ?? '')
  const navigate = useNavigate()
  const { data, isLoading, error } = useQuery({
    queryKey: ['principal', sid],
    queryFn: () => api.get<PrincipalDetail>(`/principals/${encodeURIComponent(sid)}`),
  })
  const graph = useQuery({
    queryKey: ['graph', 'principal', sid],
    queryFn: () => api.get<GraphData>(`/graph?mode=principal&sid=${encodeURIComponent(sid)}&limit=60`),
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={8} />
  const p = data.principal
  const ad = data.ad as Record<string, string | number | boolean | null> | null

  const click = (n: GraphNode) => {
    if (n.sid && n.sid !== sid) navigate(`/principals/${encodeURIComponent(n.sid)}`)
    else if (n.type === 'system' && n.system_id) navigate(`/systems/${n.system_id}`)
  }

  return (
    <>
      <PageHeader
        title={p.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <PrincipalIcon kind={p.kind} status={p.status} />
            {kindLabel[p.kind] ?? p.kind}
            <StatusBadge status={p.status} />
            <span className="font-mono text-xs">{p.sid}</span>
          </span>
        }
        actions={
          <>
            <Button variant="outline" size="sm" asChild>
              <Link to={`/report/principal/${encodeURIComponent(p.sid)}`}>
                <FileText className="size-4" /> Zugriffsbericht
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href={`/api/v1/export/principal/${encodeURIComponent(p.sid)}`}>
                <Download className="size-4" /> CSV
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to={`/changes?sid=${encodeURIComponent(p.sid)}&days=365`}>
                <History className="size-4" /> Änderungen
              </Link>
            </Button>
          </>
        }
      />

      {p.status === 'orphaned' && (
        <Card className="border-sev-high/50 bg-sev-high/5">
          <CardContent className="text-sm">
            Diese SID gehört zu keinem existierenden Konto mehr. Alle Berechtigungen dieses Eintrags sind wirkungslos und
            sollten entfernt werden.
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Eigenschaften</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {ad ? (
              Object.entries(ad).map(([k, v]) => (
                <div key={k} className="flex justify-between gap-2">
                  <span className="text-muted-foreground">{adLabel[k] ?? k}</span>
                  <span className="truncate text-right">{formatValue(k, v)}</span>
                </div>
              ))
            ) : (
              <p className="text-muted-foreground">{p.in_ad ? '–' : 'Nicht im Active Directory gefunden.'}</p>
            )}
            {p.description && <p className="text-muted-foreground pt-2">{p.description}</p>}
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Gruppenmitgliedschaften</CardTitle>
            <CardDescription>Direkt und verschachtelt (transitiv)</CardDescription>
          </CardHeader>
          <CardContent className="max-h-72 space-y-1 overflow-auto text-sm">
            {data.member_of.length === 0 && <p className="text-muted-foreground">Keine bekannten Mitgliedschaften.</p>}
            {data.member_of.map((m) => (
              <div key={m.group.sid} className="flex items-center justify-between gap-2">
                <PrincipalLink p={m.group} />
                <span className="text-muted-foreground truncate text-xs">
                  {m.direct ? 'direkt' : `über ${m.path.slice(0, -1).join(' → ')}`}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="access">
        <TabsList>
          <TabsTrigger value="access">Zugriffe ({data.direct_access.length + data.indirect_access.length})</TabsTrigger>
          {data.members.length > 0 && <TabsTrigger value="members">Mitglieder ({data.members.length})</TabsTrigger>}
          <TabsTrigger value="graph">Zusammenhänge</TabsTrigger>
          <TabsTrigger value="findings">Befunde ({data.findings.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="access" className="space-y-4">
          <AccessTable title="Direkt berechtigt" rows={data.direct_access} />
          <AccessTable title="Über Gruppen berechtigt" rows={data.indirect_access} showVia />
        </TabsContent>
        <TabsContent value="members">
          <Card>
            <CardContent className="grid gap-1 text-sm sm:grid-cols-2 lg:grid-cols-3">
              {data.members.map((m) => (
                <PrincipalLink key={m.sid} p={m} />
              ))}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="graph">
          <Card>
            <CardContent className="space-y-2">
              {graph.data ? <GraphView data={graph.data} onNodeClick={click} height="60vh" /> : <Loading />}
              <GraphLegend />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="findings">
          <Card>
            <CardContent className="space-y-2">
              {data.findings.length === 0 && <EmptyState title="Keine Befunde" />}
              {data.findings.map((f) => (
                <div key={f.id} className="flex flex-wrap items-center gap-2 text-sm">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-medium">{f.title}</span>
                  <span className="text-muted-foreground">{f.hostname ?? 'Active Directory'}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}

const adLabel: Record<string, string> = {
  sam: 'Anmeldename',
  upn: 'UPN',
  display_name: 'Anzeigename',
  enabled: 'Aktiviert',
  last_logon: 'Letzte Anmeldung',
  created: 'Erstellt',
  is_computer: 'Computerkonto',
  description: 'Beschreibung',
  scope: 'Bereich',
  is_security: 'Sicherheitsgruppe',
  transitive_users: 'Benutzer (transitiv)',
}

function formatValue(k: string, v: unknown): string {
  if (v === null || v === undefined) return '–'
  if (typeof v === 'boolean') return v ? 'ja' : 'nein'
  if (k === 'last_logon' || k === 'created') return dateTime(String(v))
  if (typeof v === 'number') return num(v)
  return String(v)
}

function AccessTable({ title, rows, showVia }: { title: string; rows: AccessEntry[]; showVia?: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} <span className="text-muted-foreground font-normal">({rows.length})</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-muted-foreground text-sm">Keine</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>System</TableHead>
                <TableHead>Ordner / Freigabe</TableHead>
                <TableHead>Recht</TableHead>
                {showVia && <TableHead className="hidden md:table-cell">Über</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={i}>
                  <TableCell>
                    <Link to={`/systems/${r.system_id}`} className="hover:underline">
                      {r.hostname}
                    </Link>
                  </TableCell>
                  <TableCell className="max-w-lg">
                    <span className="flex items-center gap-2 font-mono text-xs">
                      {r.kind === 'share' ? <Share2 className="size-3.5 shrink-0" /> : <Folder className="size-3.5 shrink-0" />}
                      <span className="truncate">{r.kind === 'share' ? `\\\\${r.share} (${r.path})` : r.path}</span>
                    </span>
                  </TableCell>
                  <TableCell>
                    <RightsBadge label={r.rights_label} deny={r.ace_type === 'deny'} />
                  </TableCell>
                  {showVia && (
                    <TableCell className="hidden md:table-cell">
                      {r.via ? <PrincipalLink p={r.via} /> : <Badge variant="outline">direkt</Badge>}
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
