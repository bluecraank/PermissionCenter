import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Pencil, Plus } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Loading, PageHeader } from '@/components/common'
import { OwnerDialog } from '@/components/owner'
import { api, type DataOwner, type SystemSummary } from '@/lib/api'
import { dateTime, num } from '@/lib/format'

export default function OwnersPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ['owners', 'list'], queryFn: () => api.get<DataOwner[]>('/owners') })
  const { data: systems } = useQuery({ queryKey: ['systems'], queryFn: () => api.get<SystemSummary[]>('/systems') })
  const [edit, setEdit] = useState<DataOwner | null>(null)
  const [newSys, setNewSys] = useState<string>('')
  const [newPath, setNewPath] = useState('')
  const [creating, setCreating] = useState(false)

  return (
    <>
      <PageHeader
        title="Dateneigentümer"
        description="Fachlich verantwortliche Personen je Ordner – gilt für den Ordner und alle Unterordner"
      />
      <Card>
        <CardContent className="flex flex-wrap items-center gap-2">
          <Select value={newSys} onValueChange={setNewSys}>
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
          <Input className="min-w-64 flex-1 font-mono" placeholder="D:\Daten\Vertrieb" value={newPath} onChange={(e) => setNewPath(e.target.value)} />
          <Button disabled={!newSys || !newPath.trim()} onClick={() => setCreating(true)}>
            <Plus className="size-4" /> Festlegen
          </Button>
          <p className="text-muted-foreground w-full text-xs">
            Tipp: Dateneigentümer lassen sich auch direkt im Verzeichnisbaum eines Systems festlegen.
          </p>
        </CardContent>
      </Card>

      {error ? (
        <ErrorState error={error} />
      ) : isLoading || !data ? (
        <Loading />
      ) : data.length === 0 ? (
        <EmptyState title="Noch keine Dateneigentümer">
          Legen Sie für die wichtigsten Ablagen (z. B. Abteilungsordner) fest, wer fachlich verantwortlich ist. Das erscheint
          in der Zugriffsprüfung und in den Exporten.
        </EmptyState>
      ) : (
        <Card>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>System</TableHead>
                  <TableHead>Pfad</TableHead>
                  <TableHead>Dateneigentümer</TableHead>
                  <TableHead className="hidden text-right md:table-cell">Befunde</TableHead>
                  <TableHead className="hidden lg:table-cell">Geändert</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((o) => (
                  <TableRow key={`${o.system_id}:${o.path}`}>
                    <TableCell>
                      <Link to={`/systems/${o.system_id}`} className="hover:underline">
                        {o.hostname}
                      </Link>
                    </TableCell>
                    <TableCell className="max-w-sm truncate font-mono text-xs" title={o.path}>
                      <Link to={`/access?system_id=${o.system_id}&path=${encodeURIComponent(o.path)}`} className="hover:underline">
                        {o.path}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <div>{o.owner}</div>
                      {o.email && <div className="text-muted-foreground text-xs">{o.email}</div>}
                      {o.note && <div className="text-muted-foreground text-xs italic">{o.note}</div>}
                    </TableCell>
                    <TableCell className="hidden text-right tabular-nums md:table-cell">{num(o.findings ?? 0)}</TableCell>
                    <TableCell className="text-muted-foreground hidden text-xs lg:table-cell">{dateTime(o.updated_at)}</TableCell>
                    <TableCell>
                      <Button size="icon" variant="ghost" onClick={() => setEdit(o)}>
                        <Pencil className="size-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
      {edit && (
        <OwnerDialog open onOpenChange={(v) => !v && setEdit(null)} systemId={edit.system_id} path={edit.path} initial={edit} />
      )}
      {creating && (
        <OwnerDialog
          open
          onOpenChange={(v) => {
            if (!v) {
              setCreating(false)
              setNewPath('')
            }
          }}
          systemId={Number(newSys)}
          path={newPath.trim()}
        />
      )}
    </>
  )
}
