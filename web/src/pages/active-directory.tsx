import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { FileUp, RefreshCw, Search, UserX, Users, UsersRound, UserRoundX } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  PrincipalLink,
  ScoreGauge,
  SeverityDots,
  StatCard,
  StatusBadge,
} from '@/components/common'
import { FindingsTable } from '@/components/findings-table'
import { api, qs, type AdGroupRow, type AdSummary, type AdUserRow } from '@/lib/api'
import { date, dateTime, num, relative } from '@/lib/format'
import { cn } from '@/lib/utils'

const groupStatus: Record<AdGroupRow['status'], { label: string; cls: string }> = {
  ok: { label: 'OK', cls: 'text-ok border-ok/40' },
  empty: { label: 'Leer', cls: 'text-sev-low border-sev-low/50' },
  orphaned: { label: 'Verwaist', cls: 'text-sev-high border-sev-high/50 bg-sev-high/10' },
  unused: { label: 'Ungenutzt', cls: 'text-muted-foreground' },
}

export default function AdPage() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const { data, isLoading, error } = useQuery({ queryKey: ['ad-summary'], queryFn: () => api.get<AdSummary>('/ad/summary') })
  const done = (r: { users: number; groups: number; findings: number }) => {
    toast.success(`${num(r.users)} Konten und ${num(r.groups)} Gruppen übernommen – ${num(r.findings)} Befunde`)
    qc.invalidateQueries()
  }
  const sync = useMutation({
    mutationFn: () => api.post<{ users: number; groups: number; findings: number }>('/ad/sync'),
    onSuccess: done,
    onError: (e) => toast.error(String(e instanceof Error ? e.message : e)),
  })
  const imp = useMutation({
    mutationFn: (f: File) => api.post<{ users: number; groups: number; findings: number }>('/ad/import', f),
    onSuccess: done,
    onError: (e) => toast.error(String(e instanceof Error ? e.message : e)),
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={6} />

  return (
    <>
      <PageHeader
        title="Active Directory"
        description={
          data.loaded
            ? `${data.domain ?? 'Domäne'} · Stand ${relative(data.synced_at)} (${dateTime(data.synced_at)}) · Quelle ${data.source === 'ldap' ? 'LDAP' : 'Import'}`
            : 'Noch keine AD-Daten geladen'
        }
        actions={
          <>
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) imp.mutate(f)
                e.target.value = ''
              }}
            />
            <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={imp.isPending}>
              <FileUp className="size-4" /> JSON importieren
            </Button>
            <Button size="sm" onClick={() => sync.mutate()} disabled={sync.isPending || !data.ldap_configured} title={data.ldap_configured ? '' : 'LDAP nicht konfiguriert'}>
              <RefreshCw className={cn('size-4', sync.isPending && 'animate-spin')} /> LDAP synchronisieren
            </Button>
          </>
        }
      />

      {!data.loaded ? (
        <EmptyState title="Keine AD-Daten">
          Konfigurieren Sie LDAP im Server (<code>[ldap]</code> bzw. <code>PC_LDAP_*</code>) oder exportieren Sie die Daten
          auf einem Domänencontroller mit <code>tools\Export-ADData.ps1</code> und importieren Sie die JSON-Datei.
        </EmptyState>
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-4">
            <Card>
              <CardContent className="flex flex-col items-center gap-2">
                <ScoreGauge score={data.score} label="AD-Bewertung" />
                <SeverityDots counts={data.findings} />
              </CardContent>
            </Card>
            <div className="grid grid-cols-2 gap-4 lg:col-span-3 lg:grid-cols-3">
              <StatCard title="Benutzer" value={num(data.users)} icon={<Users className="size-4" />} />
              <StatCard title="Gruppen" value={num(data.groups)} icon={<UsersRound className="size-4" />} />
              <StatCard title="Computer" value={num(data.computers)} />
              <StatCard title="Deaktivierte Benutzer" value={num(data.disabled_users)} icon={<UserX className="size-4" />} tone={data.disabled_users ? 'warn' : undefined} />
              <StatCard title="Inaktive Benutzer" value={num(data.inactive_users)} icon={<UserRoundX className="size-4" />} tone={data.inactive_users ? 'warn' : undefined} />
              <StatCard title="Leere Gruppen" value={num(data.empty_groups)} />
            </div>
          </div>
          <Tabs defaultValue="users">
            <TabsList>
              <TabsTrigger value="users">Benutzer</TabsTrigger>
              <TabsTrigger value="groups">Gruppen</TabsTrigger>
              <TabsTrigger value="findings">AD-Befunde</TabsTrigger>
            </TabsList>
            <TabsContent value="users">
              <UsersTab />
            </TabsContent>
            <TabsContent value="groups">
              <GroupsTab />
            </TabsContent>
            <TabsContent value="findings">
              <Card>
                <CardContent>
                  <FindingsTable filter={{ scope: 'ad' }} showSystem={false} />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </>
  )
}

function Filters({
  q,
  setQ,
  status,
  setStatus,
  options,
}: {
  q: string
  setQ: (v: string) => void
  status: string
  setStatus: (v: string) => void
  options: [string, string][]
}) {
  return (
    <div className="mb-3 flex flex-wrap gap-2">
      <div className="relative w-full sm:w-72">
        <Search className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
        <Input placeholder="Suchen…" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <Select value={status} onValueChange={setStatus}>
        <SelectTrigger className="w-44">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">Alle</SelectItem>
          {options.map(([v, l]) => (
            <SelectItem key={v} value={v}>
              {l}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

function UsersTab() {
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('all')
  const { data, isLoading } = useQuery({
    queryKey: ['ad-users', q, status],
    queryFn: () => api.get<AdUserRow[]>(`/ad/users${qs({ q, status })}`),
    placeholderData: (p) => p,
  })
  return (
    <Card>
      <CardHeader>
        <CardTitle>Benutzerkonten</CardTitle>
        <CardDescription>{data ? `${num(data.length)} Konten` : ''}</CardDescription>
      </CardHeader>
      <CardContent>
        <Filters
          q={q}
          setQ={setQ}
          status={status}
          setStatus={setStatus}
          options={[
            ['active', 'Aktiv'],
            ['inactive', 'Inaktiv'],
            ['disabled', 'Deaktiviert'],
          ]}
        />
        {isLoading || !data ? (
          <Loading />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Benutzer</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden md:table-cell">Letzte Anmeldung</TableHead>
                <TableHead className="hidden lg:table-cell">Erstellt</TableHead>
                <TableHead className="text-right">Gruppen</TableHead>
                <TableHead className="text-right">Direkte ACEs</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.slice(0, 500).map((u) => (
                <TableRow key={u.sid}>
                  <TableCell className="max-w-72">
                    <PrincipalLink p={{ sid: u.sid, name: u.name, kind: 'user', status: u.status, in_ad: true, description: null }} />
                    <div className="text-muted-foreground truncate text-xs">{u.display_name ?? u.upn}</div>
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={u.status} />
                  </TableCell>
                  <TableCell className="hidden md:table-cell">{date(u.last_logon)}</TableCell>
                  <TableCell className="hidden lg:table-cell">{date(u.created)}</TableCell>
                  <TableCell className="text-right tabular-nums">{num(u.groups)}</TableCell>
                  <TableCell className={cn('text-right tabular-nums', u.explicit_aces > 0 && 'text-sev-medium font-medium')}>
                    {num(u.explicit_aces)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

function GroupsTab() {
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('all')
  const { data, isLoading } = useQuery({
    queryKey: ['ad-groups', q, status],
    queryFn: () => api.get<AdGroupRow[]>(`/ad/groups${qs({ q, status })}`),
    placeholderData: (p) => p,
  })
  return (
    <Card>
      <CardHeader>
        <CardTitle>Gruppen</CardTitle>
        <CardDescription>{data ? `${num(data.length)} Gruppen` : ''}</CardDescription>
      </CardHeader>
      <CardContent>
        <Filters
          q={q}
          setQ={setQ}
          status={status}
          setStatus={setStatus}
          options={[
            ['ok', 'OK'],
            ['empty', 'Leer'],
            ['orphaned', 'Verwaist'],
            ['unused', 'Ungenutzt'],
          ]}
        />
        {isLoading || !data ? (
          <Loading />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Gruppe</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden md:table-cell">Bereich</TableHead>
                <TableHead className="text-right">Mitglieder</TableHead>
                <TableHead className="hidden text-right md:table-cell">Benutzer (transitiv)</TableHead>
                <TableHead className="text-right">Berechtigungen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.slice(0, 500).map((g) => (
                <TableRow key={g.sid}>
                  <TableCell className="max-w-80">
                    <PrincipalLink p={{ sid: g.sid, name: g.name, kind: 'group', status: 'active', in_ad: true, description: null }} />
                    {g.description && <div className="text-muted-foreground truncate text-xs">{g.description}</div>}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={cn('font-normal', groupStatus[g.status].cls)}>
                      {groupStatus[g.status].label}
                    </Badge>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                    {g.scope ?? '–'}
                    {!g.is_security && <span className="text-muted-foreground"> (Verteiler)</span>}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{num(g.members)}</TableCell>
                  <TableCell className="hidden text-right tabular-nums md:table-cell">{num(g.transitive_users)}</TableCell>
                  <TableCell className="text-right tabular-nums">{num(g.explicit_aces)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
