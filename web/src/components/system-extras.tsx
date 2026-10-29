import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileLock2, Play } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, Loading, PrincipalLink, RightsBadge, Spinner, StatusBadge } from '@/components/common'
import { api, type Principal } from '@/lib/api'
import { relative } from '@/lib/format'

interface ScanRequest {
  requested_at: string | null
  picked_at: string | null
  last_scan_received: string | null
}

/** „Jetzt scannen“: Auftrag, den der Client-Dienst beim nächsten Abfragen abholt. */
export function ScanNowButton({ systemId }: { systemId: number }) {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['scan-request', systemId],
    queryFn: () => api.get<ScanRequest | null>(`/systems/${systemId}/scan-request`),
    refetchInterval: (q) => (q.state.data?.requested_at ? 15_000 : false),
  })
  const req = useMutation({
    mutationFn: () => api.post<ScanRequest>(`/systems/${systemId}/scan-request`),
    onSuccess: () => {
      toast.success('Scan angefordert – der Client-Dienst holt den Auftrag innerhalb weniger Minuten ab')
      qc.invalidateQueries({ queryKey: ['scan-request', systemId] })
    },
    onError: (e) => toast.error(String(e instanceof Error ? e.message : e)),
  })
  const pending = data?.requested_at
  const label = !pending
    ? null
    : data?.picked_at
      ? `Scan läuft seit ${relative(data.picked_at)}`
      : `angefordert ${relative(pending)}`
  return (
    <span className="flex items-center gap-2">
      {label && <span className="text-muted-foreground text-xs">{label}</span>}
      <Button
        variant="outline"
        size="sm"
        disabled={req.isPending || !!pending}
        onClick={() => req.mutate()}
        title="Funktioniert, wenn der Client als Dienst läuft (fragt alle task_poll_minutes nach Aufträgen)"
      >
        {req.isPending ? <Spinner /> : <Play className="size-4" />} Jetzt scannen
      </Button>
    </span>
  )
}

interface LocalAdmin {
  principal: Principal
  members: Principal[]
}

export function LocalAdminsTab({ systemId }: { systemId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ['local-admins', systemId],
    queryFn: () => api.get<LocalAdmin[]>(`/systems/${systemId}/local-admins`),
  })
  if (isLoading || !data) return <Loading />
  if (data.length === 0)
    return (
      <EmptyState title="Keine Daten">
        Die Mitglieder der lokalen Administratoren werden ab Client-Version 0.2 übermittelt.
      </EmptyState>
    )
  return (
    <Card>
      <CardHeader>
        <CardTitle>Lokale Administratoren</CardTitle>
        <CardDescription>Direkte Mitglieder der Gruppe Administratoren (S-1-5-32-544) und deren Benutzer</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Mitglied</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="hidden md:table-cell">Enthaltene Benutzer</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((a) => (
              <TableRow key={a.principal.sid}>
                <TableCell className="max-w-72">
                  <PrincipalLink p={a.principal} showSid />
                </TableCell>
                <TableCell>
                  <StatusBadge status={a.principal.status} />
                </TableCell>
                <TableCell className="text-muted-foreground hidden text-xs whitespace-normal md:table-cell">
                  {a.members.length > 0 ? a.members.map((m) => m.name).join(', ') : '–'}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

interface FileEntry {
  name: string
  path: string
  protected: boolean
  owner: Principal | null
  aces: { principal: Principal; ace_type: string; rights_label: string; inherited: boolean }[]
}

/** Dateien eines Ordners mit eigenen Berechtigungen (Dateiebene). */
export function FolderFiles({ systemId, localId }: { systemId: number; localId: number }) {
  const { data } = useQuery({
    queryKey: ['folder-files', systemId, localId],
    queryFn: () => api.get<FileEntry[]>(`/systems/${systemId}/folders/${localId}/files`),
  })
  if (!data || data.length === 0) return null
  return (
    <div className="space-y-2">
      <h4 className="flex items-center gap-2 text-sm font-medium">
        <FileLock2 className="size-4" /> Dateien mit eigenen Berechtigungen ({data.length})
      </h4>
      <div className="divide-y rounded-md border">
        {data.map((f) => (
          <div key={f.path} className="space-y-1 px-3 py-2 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs break-all">{f.name}</span>
              {f.protected && <Badge variant="outline">Vererbung unterbrochen</Badge>}
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              {f.aces
                .filter((a) => !a.inherited)
                .map((a, i) => (
                  <span key={i} className="flex items-center gap-1.5">
                    <PrincipalLink p={a.principal} />
                    <RightsBadge label={a.rights_label} deny={a.ace_type === 'deny'} />
                  </span>
                ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
