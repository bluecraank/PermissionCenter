import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronLeft, ChevronRight, Lightbulb } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Loading, SeverityBadge } from '@/components/common'
import { api, qs, type Finding } from '@/lib/api'
import { num } from '@/lib/format'
import { cn } from '@/lib/utils'

export interface FindingFilter {
  system_id?: number
  severity?: string
  rule?: string
  sid?: string
  scope?: string
  q?: string
}

const PAGE = 50

export function FindingsTable({ filter, showSystem = true }: { filter: FindingFilter; showSystem?: boolean }) {
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState<number | null>(null)
  const key = JSON.stringify(filter)
  const [lastKey, setLastKey] = useState(key)
  if (key !== lastKey) {
    setLastKey(key)
    setPage(0)
  }
  const { data, isLoading, error } = useQuery({
    queryKey: ['findings', filter, page],
    queryFn: () =>
      api.get<{ total: number; items: Finding[] }>(`/findings${qs({ ...filter, limit: PAGE, offset: page * PAGE })}`),
    placeholderData: (prev) => prev,
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading />
  if (data.total === 0) return <EmptyState title="Keine Befunde">Für diese Auswahl wurden keine Probleme gefunden.</EmptyState>
  const pages = Math.ceil(data.total / PAGE)

  return (
    <div className="space-y-3">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8" />
            <TableHead className="w-24">Schwere</TableHead>
            <TableHead>Befund</TableHead>
            {showSystem && <TableHead className="hidden md:table-cell">System</TableHead>}
            <TableHead className="hidden text-right sm:table-cell">Betroffen</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.items.map((f) => (
            <Fragment key={f.id}>
              <TableRow className="cursor-pointer" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <TableCell>
                  <ChevronDown className={cn('size-4 transition-transform', expanded !== f.id && '-rotate-90')} />
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={f.severity} />
                </TableCell>
                <TableCell className="max-w-xl">
                  <div className="truncate font-medium">{f.title}</div>
                  <div className="text-muted-foreground truncate font-mono text-xs">{f.path ?? f.rule_title}</div>
                </TableCell>
                {showSystem && (
                  <TableCell className="hidden md:table-cell">
                    {f.system_id ? (
                      <Link to={`/systems/${f.system_id}`} className="hover:underline" onClick={(e) => e.stopPropagation()}>
                        {f.hostname}
                      </Link>
                    ) : (
                      <span className="text-muted-foreground">Active Directory</span>
                    )}
                  </TableCell>
                )}
                <TableCell className="hidden text-right tabular-nums sm:table-cell">{num(f.affected)}</TableCell>
              </TableRow>
              {expanded === f.id && (
                <TableRow className="hover:bg-transparent">
                  <TableCell />
                  <TableCell colSpan={showSystem ? 4 : 3} className="space-y-3 pb-4 whitespace-normal">
                    {f.detail && <pre className="bg-muted rounded-md p-3 font-mono text-xs whitespace-pre-wrap">{f.detail}</pre>}
                    {f.recommendation && (
                      <div className="flex gap-2 text-sm">
                        <Lightbulb className="text-sev-medium mt-0.5 size-4 shrink-0" />
                        <span>{f.recommendation}</span>
                      </div>
                    )}
                    <div className="flex flex-wrap gap-2">
                      {f.sid && (
                        <Button size="sm" variant="outline" asChild>
                          <Link to={`/principals/${encodeURIComponent(f.sid)}`}>Prinzipal anzeigen</Link>
                        </Button>
                      )}
                      <Button size="sm" variant="outline" asChild>
                        <Link to={`/findings?rule=${f.rule}`}>Alle Befunde dieser Regel</Link>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </Fragment>
          ))}
        </TableBody>
      </Table>
      {pages > 1 && (
        <div className="flex items-center justify-end gap-2 text-sm">
          <span className="text-muted-foreground">
            {num(page * PAGE + 1)}–{num(Math.min((page + 1) * PAGE, data.total))} von {num(data.total)}
          </span>
          <Button size="icon" variant="outline" disabled={page === 0} onClick={() => setPage(page - 1)}>
            <ChevronLeft className="size-4" />
          </Button>
          <Button size="icon" variant="outline" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>
            <ChevronRight className="size-4" />
          </Button>
        </div>
      )}
    </div>
  )
}
