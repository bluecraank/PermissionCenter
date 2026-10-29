import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Loading, PageHeader, PrincipalLink, StatusBadge } from '@/components/common'
import { api, qs, type PrincipalRow } from '@/lib/api'
import { kindLabel, num, statusLabel } from '@/lib/format'

export default function PrincipalsPage() {
  const [q, setQ] = useState('')
  const [kind, setKind] = useState('all')
  const [status, setStatus] = useState('all')
  const { data, isLoading, error } = useQuery({
    queryKey: ['principals', q, kind, status],
    queryFn: () => api.get<{ total: number; items: PrincipalRow[] }>(`/principals${qs({ q, kind, status, limit: 500 })}`),
    placeholderData: (p) => p,
  })

  return (
    <>
      <PageHeader
        title="Benutzer & Gruppen"
        description="Alle Prinzipale aus Berechtigungen und Active Directory – mit Status und Verbreitung"
      />
      <div className="flex flex-wrap gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
          <Input placeholder="Name, SID, Beschreibung…" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Select value={kind} onValueChange={setKind}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Arten</SelectItem>
            {Object.entries(kindLabel).map(([k, l]) => (
              <SelectItem key={k} value={k}>
                {l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Status</SelectItem>
            {Object.entries(statusLabel).map(([k, l]) => (
              <SelectItem key={k} value={k}>
                {l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {error ? (
        <ErrorState error={error} />
      ) : isLoading || !data ? (
        <Loading />
      ) : data.items.length === 0 ? (
        <EmptyState title="Keine Treffer" />
      ) : (
        <Card className="py-0">
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">Name</TableHead>
                  <TableHead>Art</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="hidden lg:table-cell">SID</TableHead>
                  <TableHead className="text-right">Explizite ACEs</TableHead>
                  <TableHead className="hidden text-right md:table-cell">Systeme</TableHead>
                  <TableHead className="hidden pr-4 text-right md:table-cell">Freigaben</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((p) => (
                  <TableRow key={p.sid}>
                    <TableCell className="max-w-72 pl-4">
                      <PrincipalLink p={p} />
                      {p.description && <div className="text-muted-foreground truncate text-xs">{p.description}</div>}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-normal">
                        {kindLabel[p.kind] ?? p.kind}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={p.status} />
                    </TableCell>
                    <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">{p.sid}</TableCell>
                    <TableCell className="text-right tabular-nums">{num(p.explicit_aces)}</TableCell>
                    <TableCell className="hidden text-right tabular-nums md:table-cell">{num(p.systems)}</TableCell>
                    <TableCell className="hidden pr-4 text-right tabular-nums md:table-cell">{num(p.share_aces)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {data.total > data.items.length && (
              <p className="text-muted-foreground p-3 text-center text-xs">
                {num(data.items.length)} von {num(data.total)} angezeigt – Suche verfeinern
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </>
  )
}
