import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search, ServerCog } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, GradeBadge, Loading, PageHeader, SeverityDots } from '@/components/common'
import { api, type SystemSummary } from '@/lib/api'
import { dateTime, duration, num, relative } from '@/lib/format'

export default function SystemsPage() {
  const [q, setQ] = useState('')
  const { data, isLoading, error } = useQuery({ queryKey: ['systems'], queryFn: () => api.get<SystemSummary[]>('/systems') })
  if (error) return <ErrorState error={error} />

  const rows = (data ?? []).filter(
    (s) => !q || `${s.hostname} ${s.domain ?? ''} ${s.os_name ?? ''}`.toLowerCase().includes(q.toLowerCase()),
  )

  return (
    <>
      <PageHeader title="Systeme" description="Alle Server, die Scan-Ergebnisse geliefert haben" />
      <div className="relative max-w-sm">
        <Search className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
        <Input placeholder="System suchen…" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {isLoading ? (
        <Loading />
      ) : rows.length === 0 ? (
        <EmptyState title="Keine Systeme">Sobald ein Client einen Report sendet, erscheint das System hier.</EmptyState>
      ) : (
        <Card className="py-0">
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-14 pl-4">Note</TableHead>
                  <TableHead>System</TableHead>
                  <TableHead className="hidden lg:table-cell">Betriebssystem</TableHead>
                  <TableHead className="hidden md:table-cell">Letzter Scan</TableHead>
                  <TableHead className="text-right">Ordner</TableHead>
                  <TableHead className="hidden text-right xl:table-cell">Explizit</TableHead>
                  <TableHead className="hidden text-right xl:table-cell">Freigaben</TableHead>
                  <TableHead className="hidden text-right md:table-cell">Fehler</TableHead>
                  <TableHead>Befunde</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="pl-4">
                      <GradeBadge score={s.score} />
                    </TableCell>
                    <TableCell>
                      <Link to={`/systems/${s.id}`} className="flex items-center gap-2 font-medium hover:underline">
                        {s.hostname}
                        {s.is_dc && (
                          <Badge variant="secondary" className="gap-1">
                            <ServerCog className="size-3" /> DC
                          </Badge>
                        )}
                      </Link>
                      <div className="text-muted-foreground text-xs">{s.domain ?? 'Arbeitsgruppe'}</div>
                    </TableCell>
                    <TableCell className="hidden lg:table-cell">
                      <div>{s.os_name}</div>
                      <div className="text-muted-foreground text-xs">{s.os_version}</div>
                    </TableCell>
                    <TableCell className="hidden md:table-cell" title={dateTime(s.last_scan_at)}>
                      <div>{relative(s.last_scan_at)}</div>
                      <div className="text-muted-foreground text-xs">Dauer {duration(s.duration_ms)}</div>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{num(s.folders_scanned)}</TableCell>
                    <TableCell className="hidden text-right tabular-nums xl:table-cell">{num(s.explicit_folders)}</TableCell>
                    <TableCell className="hidden text-right tabular-nums xl:table-cell">{num(s.shares)}</TableCell>
                    <TableCell className="hidden text-right tabular-nums md:table-cell">{num(s.errors)}</TableCell>
                    <TableCell>
                      <SeverityDots counts={s.findings} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </>
  )
}
