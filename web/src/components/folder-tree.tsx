import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  AlertCircle,
  ChevronRight,
  Folder,
  FolderLock,
  FolderOpen,
  FolderSearch,
  HardDrive,
  Link2Off,
  Share2,
} from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { OwnerField } from '@/components/owner'
import { FolderFiles } from '@/components/system-extras'
import { EmptyState, Loading, PrincipalLink, RightsBadge, SeverityBadge, Spinner } from '@/components/common'
import { api, type Folder as FolderT, type FolderDetail } from '@/lib/api'
import { bytes, num } from '@/lib/format'
import { cn } from '@/lib/utils'

function TreeNode({
  systemId,
  folder,
  level,
  selected,
  onSelect,
}: {
  systemId: number
  folder: FolderT
  level: number
  selected: number | null
  onSelect: (id: number) => void
}) {
  const [open, setOpen] = useState(level === 0)
  const { data, isFetching } = useQuery({
    queryKey: ['folders', systemId, folder.local_id],
    queryFn: () => api.get<FolderT[]>(`/systems/${systemId}/folders?parent=${folder.local_id}`),
    enabled: open && folder.children > 0,
  })
  const Icon = folder.is_root
    ? HardDrive
    : folder.explicit || folder.protected
      ? FolderLock
      : open
        ? FolderOpen
        : Folder
  return (
    <div>
      <div
        className={cn(
          'hover:bg-accent flex cursor-pointer items-center gap-1 rounded-md py-1 pr-2 text-sm',
          selected === folder.local_id && 'bg-accent font-medium',
        )}
        style={{ paddingLeft: level * 14 + 4 }}
        onClick={() => onSelect(folder.local_id)}
      >
        <button
          className={cn('rounded p-0.5', folder.children === 0 && 'invisible')}
          onClick={(e) => {
            e.stopPropagation()
            setOpen(!open)
          }}
          aria-label={open ? 'Zuklappen' : 'Aufklappen'}
        >
          {isFetching ? (
            <Spinner className="size-3.5" />
          ) : (
            <ChevronRight className={cn('size-3.5 transition-transform', open && 'rotate-90')} />
          )}
        </button>
        <Icon className={cn('size-4 shrink-0', (folder.explicit || folder.protected) && 'text-sev-low')} />
        <span className="truncate">{folder.name}</span>
        <span className="ml-auto flex shrink-0 items-center gap-1">
          {folder.protected && !folder.is_root && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Link2Off className="text-sev-medium size-3.5" />
              </TooltipTrigger>
              <TooltipContent>Vererbung unterbrochen</TooltipContent>
            </Tooltip>
          )}
          {folder.error && <AlertCircle className="text-sev-high size-3.5" />}
          {folder.findings > 0 && (
            <Badge variant="outline" className="text-sev-high h-4 px-1 text-[10px]">
              {folder.findings}
            </Badge>
          )}
        </span>
      </div>
      {open &&
        data?.map((c) => (
          <TreeNode
            key={c.local_id}
            systemId={systemId}
            folder={c}
            level={level + 1}
            selected={selected}
            onSelect={onSelect}
          />
        ))}
      {open && folder.children === 0 && folder.subfolder_total > 0 && (
        <div className="text-muted-foreground py-0.5 text-xs" style={{ paddingLeft: (level + 1) * 14 + 28 }}>
          {num(folder.subfolder_total)} Unterordner erben die Rechte
        </div>
      )}
    </div>
  )
}

export function FolderDetailPanel({
  systemId,
  localId,
  onNavigate,
}: {
  systemId: number
  localId: number
  onNavigate: (id: number) => void
}) {
  const { data, isLoading } = useQuery({
    queryKey: ['folder', systemId, localId],
    queryFn: () => api.get<FolderDetail>(`/systems/${systemId}/folders/${localId}`),
  })
  if (isLoading || !data) return <Loading rows={6} />
  const explicit = data.aces.filter((a) => !a.inherited)
  const inherited = data.aces.filter((a) => a.inherited)
  return (
    <div className="space-y-4">
      <div>
        <div className="text-muted-foreground flex flex-wrap items-center gap-1 text-xs">
          {data.breadcrumbs.map((b) => (
            <span key={b.local_id} className="flex items-center gap-1">
              <button className="hover:underline" onClick={() => onNavigate(b.local_id)}>
                {b.name}
              </button>
              <ChevronRight className="size-3" />
            </span>
          ))}
        </div>
        <h3 className="mt-1 font-mono text-sm font-semibold break-all">{data.path}</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          {data.explicit && <Badge variant="secondary">Eigene Berechtigungen</Badge>}
          {data.protected && (
            <Badge className="bg-sev-medium/20 text-sev-medium border-sev-medium/40" variant="outline">
              Vererbung unterbrochen
            </Badge>
          )}
          {!data.explicit && !data.protected && <Badge variant="outline">Erbt Rechte</Badge>}
          {data.shares.map((s) => (
            <Badge key={s} variant="outline" className="gap-1">
              <Share2 className="size-3" />
              \\{s}
            </Badge>
          ))}
          {data.error && <Badge variant="destructive">{data.error}</Badge>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <Info k="Besitzer" v={data.owner ? <PrincipalLink p={data.owner} /> : '–'} />
        <Info k="Unterordner" v={num(data.subfolder_total)} />
        <Info k="Dateien" v={`${num(data.file_count)} (${bytes(data.file_bytes)})`} />
        <Info
          k="Strang-Ursprung"
          v={
            data.acl_source_local_id && data.acl_source_local_id !== data.local_id ? (
              <button
                className="truncate text-left hover:underline"
                onClick={() => onNavigate(data.acl_source_local_id!)}
              >
                {data.acl_source_path}
              </button>
            ) : (
              'dieser Ordner'
            )
          }
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-60 flex-1">
          <OwnerField systemId={systemId} path={data.path} />
        </div>
        <Button variant="outline" size="sm" asChild>
          <Link to={`/access?system_id=${systemId}&path=${encodeURIComponent(data.path)}`}>
            <FolderSearch className="size-4" /> Wer hat Zugriff?
          </Link>
        </Button>
      </div>

      {data.finding_list.length > 0 && (
        <div className="space-y-1">
          {data.finding_list.map((f) => (
            <div key={f.id} className="flex items-center gap-2 text-sm">
              <SeverityBadge severity={f.severity} />
              <span>{f.title}</span>
            </div>
          ))}
        </div>
      )}

      <AceTable title="Explizite Berechtigungen" aces={explicit} />
      <FolderFiles systemId={systemId} localId={localId} />
      {inherited.length > 0 && <AceTable title="Geerbte Berechtigungen" aces={inherited} muted />}
    </div>
  )
}

function Info({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-muted-foreground text-xs">{k}</div>
      <div className="truncate">{v}</div>
    </div>
  )
}

export function AceTable({ title, aces, muted }: { title: string; aces: FolderDetail['aces']; muted?: boolean }) {
  return (
    <div>
      <h4 className="mb-1 text-sm font-medium">
        {title} <span className="text-muted-foreground font-normal">({aces.length})</span>
      </h4>
      {aces.length === 0 ? (
        <p className="text-muted-foreground text-sm">Keine</p>
      ) : (
        <Table className={cn(muted && 'opacity-80')}>
          <TableHeader>
            <TableRow>
              <TableHead>Prinzipal</TableHead>
              <TableHead>Recht</TableHead>
              <TableHead className="hidden lg:table-cell">Gilt für</TableHead>
              <TableHead className="hidden xl:table-cell">Maske</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {aces.map((a, i) => (
              <TableRow key={i}>
                <TableCell className="max-w-64">
                  <PrincipalLink p={a.principal} />
                </TableCell>
                <TableCell>
                  <RightsBadge label={a.rights_label} deny={a.ace_type === 'deny'} />
                </TableCell>
                <TableCell className="text-muted-foreground hidden text-xs lg:table-cell">{a.applies_to}</TableCell>
                <TableCell className="text-muted-foreground hidden font-mono text-xs xl:table-cell">{a.mask}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}

export function FolderBrowser({ systemId }: { systemId: number }) {
  const [selected, setSelected] = useState<number | null>(null)
  const { data, isLoading } = useQuery({
    queryKey: ['folders', systemId, 'root'],
    queryFn: () => api.get<FolderT[]>(`/systems/${systemId}/folders`),
  })
  if (isLoading) return <Loading />
  if (!data || data.length === 0) return <EmptyState title="Keine Ordnerdaten" />
  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <Card className="py-3 lg:col-span-2">
        <CardHeader className="px-4">
          <CardTitle className="text-base">Verzeichnisstränge</CardTitle>
          <CardDescription>
            Gemeldet werden Ordner mit eigenen Rechten sowie deren Pfad. Alle anderen erben exakt.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-2">
          <ScrollArea className="h-[65vh]">
            {data.map((r) => (
              <TreeNode
                key={r.local_id}
                systemId={systemId}
                folder={r}
                level={0}
                selected={selected}
                onSelect={setSelected}
              />
            ))}
          </ScrollArea>
        </CardContent>
      </Card>
      <Card className="lg:col-span-3">
        <CardContent>
          {selected === null ? (
            <EmptyState title="Ordner auswählen">
              Wählen Sie links einen Ordner, um dessen Berechtigungen zu sehen.
            </EmptyState>
          ) : (
            <FolderDetailPanel systemId={systemId} localId={selected} onNavigate={setSelected} />
          )}
        </CardContent>
      </Card>
    </div>
  )
}
