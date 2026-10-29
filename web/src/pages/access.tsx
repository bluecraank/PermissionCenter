import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Download, Info, Search, Share2, UserRoundCheck, Users } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Loading, PageHeader, PrincipalLink, RightsBadge, StatusBadge } from '@/components/common'
import { api, qs, type AccessGrant, type AccessResult, type SystemSummary } from '@/lib/api'
import { num } from '@/lib/format'

function GrantList({ items }: { items: AccessGrant[] }) {
  return (
    <div className="space-y-1">
      {items.map((g, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2 text-sm">
          <PrincipalLink p={g.principal} />
          <RightsBadge label={g.rights_label} deny={g.ace_type === 'deny'} />
          {g.inherited === false && <Badge variant="outline">explizit</Badge>}
        </div>
      ))}
    </div>
  )
}

export default function AccessPage() {
  const [params, setParams] = useSearchParams()
  const { data: systems } = useQuery({ queryKey: ['systems'], queryFn: () => api.get<SystemSummary[]>('/systems') })
  const [sys, setSys] = useState(params.get('system_id') ?? '')
  const [path, setPath] = useState(params.get('path') ?? '')
  const [filter, setFilter] = useState('')
  const query = { system_id: params.get('system_id') ?? undefined, path: params.get('path') ?? '' }
  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ['access', query],
    queryFn: () => api.get<AccessResult>(`/access${qs(query)}`),
    enabled: !!query.path,
    retry: false,
  })
  const run = () => {
    const p = new URLSearchParams()
    if (sys && !path.trim().startsWith('\\\\')) p.set('system_id', sys)
    p.set('path', path.trim())
    setParams(p)
  }
  const users = (data?.users ?? []).filter(
    (u) => !filter || u.principal.name.toLowerCase().includes(filter.toLowerCase()) || u.via.some((v) => v.toLowerCase().includes(filter.toLowerCase())),
  )

  return (
    <>
      <PageHeader
        title="Zugriffsprüfung"
        description="Wer hat Zugriff auf einen Ordner? Gruppen werden bis zum einzelnen Benutzer aufgelöst."
        actions={
          data && (
            <Button variant="outline" asChild>
              <a href={`/api/v1/export/access.csv${qs(query)}`}>
                <Download className="size-4" /> CSV
              </a>
            </Button>
          )
        }
      />
      <Card>
        <CardContent className="flex flex-wrap items-center gap-2">
          <Select value={sys} onValueChange={setSys}>
            <SelectTrigger className="w-44">
              <SelectValue placeholder="System" />
            </SelectTrigger>
            <SelectContent>
              {systems?.map((s) => (
                <SelectItem key={s.id} value={String(s.id)}>
                  {s.hostname}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            className="min-w-64 flex-1 font-mono"
            placeholder="D:\Daten\Vertrieb  oder  \\FS01\Daten\Vertrieb"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()}
          />
          <Button onClick={run} disabled={!path.trim() || (!sys && !path.trim().startsWith('\\\\'))}>
            <Search className="size-4" /> Prüfen
          </Button>
        </CardContent>
      </Card>

      {!query.path ? (
        <EmptyState title="Pfad eingeben">
          Lokalen Pfad mit System oder UNC-Pfad einer Freigabe eingeben. Ausgewertet wird der Stand des letzten Scans.
        </EmptyState>
      ) : error ? (
        <ErrorState error={error} />
      ) : isLoading || !data ? (
        <Loading rows={6} />
      ) : (
        <div className={isFetching ? 'opacity-60' : undefined}>
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="font-mono text-base break-all">{data.path}</CardTitle>
                <CardDescription className="flex flex-wrap items-center gap-2">
                  <Link to={`/systems/${data.system_id}`} className="hover:underline">
                    {data.hostname}
                  </Link>
                  {data.via_share && <Badge variant="outline">über Freigabe {data.via_share}</Badge>}
                  {data.folder.protected && data.folder.exact && <Badge variant="outline">Vererbung unterbrochen</Badge>}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {!data.folder.exact && (
                  <Alert>
                    <Info />
                    <AlertTitle>Rechte geerbt</AlertTitle>
                    <AlertDescription>
                      Der Ordner hat keine eigenen Berechtigungen und erbt von <span className="font-mono">{data.folder.path}</span>.
                    </AlertDescription>
                  </Alert>
                )}
                {data.everyone.length > 0 && (
                  <Alert variant="destructive">
                    <AlertTriangle />
                    <AlertTitle>Zugriff für alle Benutzer</AlertTitle>
                    <AlertDescription>
                      <GrantList items={data.everyone} />
                    </AlertDescription>
                  </Alert>
                )}
                <div>
                  <h3 className="mb-2 text-sm font-medium">Berechtigungen (NTFS)</h3>
                  <GrantList items={data.aces} />
                </div>
                {data.unresolved.length > 0 && (
                  <div>
                    <h3 className="mb-1 text-sm font-medium">Nicht auflösbar</h3>
                    <p className="text-muted-foreground mb-2 text-xs">
                      Lokale Gruppen oder unbekannte Konten – deren Mitglieder sind nicht bekannt.
                    </p>
                    <GrantList items={data.unresolved} />
                  </div>
                )}
              </CardContent>
            </Card>
            <div className="space-y-4">
              <Card className="gap-2">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <UserRoundCheck className="size-4" /> Dateneigentümer
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-sm">
                  {data.owner ? (
                    <>
                      <div>{data.owner.owner}</div>
                      {data.owner.email && <div className="text-muted-foreground">{data.owner.email}</div>}
                      <div className="text-muted-foreground mt-1 truncate font-mono text-xs">{data.owner.path}</div>
                    </>
                  ) : (
                    <span className="text-muted-foreground">
                      Nicht festgelegt – <Link to="/owners" className="underline">festlegen</Link>
                    </span>
                  )}
                </CardContent>
              </Card>
              {data.shares.map((s) => (
                <Card key={s.unc} className="gap-2">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Share2 className="size-4" /> {s.unc}
                    </CardTitle>
                    <CardDescription>Über die Freigabe gilt jeweils das strengere von Freigabe- und NTFS-Recht.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {s.no_security ? <RightsBadge label="Jeder: Vollzugriff (keine Freigabeberechtigungen)" /> : <GrantList items={s.permissions} />}
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>

          <Card className="mt-4">
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Users className="size-4" /> Benutzer mit Zugriff ({num(data.users_total)})
                </CardTitle>
                <CardDescription>Aufgelöst über AD-Gruppen (auch verschachtelt) und lokale Administratoren</CardDescription>
              </div>
              <Input className="w-56" placeholder="Filtern…" value={filter} onChange={(e) => setFilter(e.target.value)} />
            </CardHeader>
            <CardContent>
              {users.length === 0 ? (
                <p className="text-muted-foreground text-sm">Keine einzeln aufgelösten Benutzer.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Benutzer</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Rechte</TableHead>
                      <TableHead className="hidden md:table-cell">Über</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.slice(0, 1000).map((u) => (
                      <TableRow key={u.principal.sid}>
                        <TableCell className="max-w-64">
                          <PrincipalLink p={u.principal} />
                        </TableCell>
                        <TableCell>
                          <StatusBadge status={u.principal.status} />
                        </TableCell>
                        <TableCell className="space-x-1">
                          <RightsBadge label={u.rights_label} />
                          {u.denied && <RightsBadge label={u.deny_label ?? ''} deny />}
                        </TableCell>
                        <TableCell className="text-muted-foreground hidden max-w-sm truncate text-xs md:table-cell">
                          {[u.direct ? 'direkt' : null, ...u.via].filter(Boolean).join(', ')}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </>
  )
}
