import { Fragment, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bug, FileSearch, FolderTree, Layers, Lock, ShieldAlert, Target, Unlink } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { EmptyState, ErrorState, Loading, PageHeader, StatCard } from '@/components/common'
import { api, qs } from '@/lib/api'
import { dateTime, num, relative } from '@/lib/format'
import { cn } from '@/lib/utils'

// ---------------------------------------------------------------------------
// Typen

interface GpoPerm {
  sid: string
  name: string
  domain: string
  sid_type: string
  permission: string
  denied: boolean
  inherited: boolean
}
interface GpoLink {
  som_name: string
  som_path: string
  enabled: boolean
  enforced: boolean
}
interface GpoSetting {
  scope: string
  area: string
  name: string
  detail: string
  weakness?: { id: string; title: string; why: string; fix: string; evidence: string } | null
}
interface GpoFinding {
  severity: 'warn' | 'info'
  code: string
  text: string
}
interface Gpo {
  id: string
  name: string
  domain: string
  created: string
  modified: string
  owner: string
  wmi_filter: string
  computer_enabled: boolean
  user_enabled: boolean
  computer_version: string
  user_version: string
  links: GpoLink[]
  permissions: GpoPerm[]
  settings_count: number
  settings?: GpoSetting[]
  targeting: { kind: 'broad' | 'targeted' | 'nobody'; apply: GpoPerm[]; deny: GpoPerm[] }
  findings: GpoFinding[]
}
interface GpoGroup {
  sid: string
  name: string
  members: { name: string; sam: string; class: string }[]
  truncated: boolean
}
interface GpoOverview {
  loaded: boolean
  domain: string | null
  host: string | null
  synced_at: string | null
  gpos: Gpo[]
  groups: Record<string, GpoGroup>
}
interface SearchResult {
  total: number
  gpos: number
  areas: string[]
  rows: { gpo_id: string; gpo_name: string; scope: string; area: string; name: string; detail: string; weakness?: GpoSetting['weakness'] }[]
}

interface DuplicateItem {
  scope: string
  area: string
  name: string
  kind: 'duplicate' | 'conflict'
  overlap: 'no' | 'maybe' | 'yes'
  link_relation: LinkRelation
  filter_relation: keyof typeof FILTER_RELATION
  enforced_count: number
  winner: string | null
  effect: string | null
  gpos: {
    gpo_id: string
    gpo_name: string
    detail: string
    enforced: boolean
    links: { path: string; enabled: boolean; enforced: boolean }[]
    filter_kind: string
    filter: string[]
  }[]
}
type LinkRelation = 'same' | 'partial' | 'nested' | 'none'
interface DuplicatesResult {
  total: number
  conflicts: number
  items: DuplicateItem[]
}

const OVERLAP = {
  yes: { label: 'Überlappung: ja', cls: 'text-sev-high border-sev-high/50' },
  maybe: { label: 'Überlappung: möglich', cls: 'text-sev-medium border-sev-medium/50' },
  no: { label: 'Überlappung: nein', cls: 'text-muted-foreground' },
} as const

const LINK_RELATION: Record<LinkRelation, { label: string; cls: string }> = {
  same: { label: 'Gleiche OUs', cls: 'text-sev-high border-sev-high/50' },
  partial: { label: 'Teilweise gleiche OUs', cls: 'text-sev-high border-sev-high/50' },
  nested: { label: 'Verschachtelte OUs', cls: 'text-sev-medium border-sev-medium/50' },
  none: { label: 'Getrennte OUs', cls: 'text-muted-foreground' },
}

const FILTER_RELATION = {
  same: { label: 'Gleicher Filter', cls: 'text-sev-high border-sev-high/50' },
  shared: { label: 'Filter teilweise gleich', cls: 'text-sev-medium border-sev-medium/50' },
  broad_targeted: { label: 'Breit und gezielt', cls: 'text-sev-medium border-sev-medium/50' },
  different: { label: 'Anderer Filter', cls: 'text-muted-foreground' },
  none: { label: 'Filter: niemand', cls: 'text-muted-foreground' },
} as const

const KIND = {
  broad: { label: 'Alle / breit', cls: '' },
  targeted: { label: 'Gezielt zugewiesen', cls: 'text-ok border-ok/40' },
  nobody: { label: 'Niemand', cls: 'text-sev-medium border-sev-medium/50' },
} as const

const PERM: Record<string, { k: string; label: string }> = {
  GpoApply: { k: 'A', label: 'Lesen + Übernehmen' },
  GpoRead: { k: 'R', label: 'Nur lesen' },
  GpoEdit: { k: 'E', label: 'Bearbeiten' },
  GpoEditDeleteModifySecurity: { k: 'F', label: 'Bearbeiten, Löschen, Sicherheit ändern' },
}
const PERM_CLS: Record<string, string> = {
  A: 'bg-ok text-white',
  R: 'bg-sev-low/40',
  E: 'bg-sev-medium/60',
  F: 'bg-sev-high text-white',
  D: 'bg-foreground text-background outline-2 outline-sev-high',
  '?': 'bg-muted',
}
const permKey = (p: GpoPerm) => (p.denied ? 'D' : (PERM[p.permission]?.k ?? '?'))
const isAdminSid = (s: string) => s === 'S-1-5-18' || s === 'S-1-3-0' || s === 'S-1-5-9' || /^S-1-5-21-.*-(512|519)$/.test(s)

const warns = (g: Gpo) => g.findings.filter((f) => f.severity === 'warn')
const has = (g: Gpo, code: string) => g.findings.some((f) => f.code === code)

const FLAGS: [string, string][] = [
  ['warn', 'Irgendeine Warnung'],
  ['unlinked', 'Nicht verknüpft'],
  ['links_disabled', 'Verknüpfungen deaktiviert'],
  ['empty', 'Leer'],
  ['disabled', 'Komplett deaktiviert'],
  ['orphan_sid', 'Verwaiste SIDs'],
  ['wmi', 'WMI-Filter'],
  ['deny', 'Verweigern-Ausnahme'],
  ['enforced', 'Erzwungen'],
  ['stale', 'Lange unverändert'],
  ['ms16_072', 'MS16-072'],
  ['version_mismatch', 'Versionsabweichung'],
]

function PermChip({ p }: { p: GpoPerm }) {
  const k = permKey(p)
  return (
    <span
      className={cn('inline-block min-w-5 rounded px-1 text-center text-xs font-semibold', PERM_CLS[k])}
      title={(p.denied ? 'Verweigert: ' : '') + (PERM[p.permission]?.label ?? p.permission)}
    >
      {k}
    </span>
  )
}

function Hl({ text, terms }: { text: string; terms: string[] }) {
  const t = terms.filter(Boolean)
  if (!t.length) return <>{text}</>
  const re = new RegExp('(' + t.map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')', 'gi')
  return (
    <>
      {text.split(re).map((part, i) =>
        i % 2 ? (
          <mark key={i} className="bg-yellow-300/60 text-inherit dark:bg-yellow-600/50">
            {part}
          </mark>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        ),
      )}
    </>
  )
}

function KindBadge({ g }: { g: Gpo }) {
  const k = KIND[g.targeting.kind]
  return (
    <Badge variant="outline" className={cn('font-normal', k.cls)}>
      {k.label}
    </Badge>
  )
}

// ---------------------------------------------------------------------------
// Seite

export default function GpoPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ['gpo'], queryFn: () => api.get<GpoOverview>('/gpo') })
  const [tab, setTab] = useState('list')
  const [filter, setFilter] = useState({ q: '', kind: 'all', flag: 'all' })
  const [openId, setOpenId] = useState<string | null>(null)

  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={6} />
  if (!data.loaded)
    return (
      <>
        <PageHeader title="Gruppenrichtlinien" description="Noch keine GPO-Daten übertragen" />
        <EmptyState title="Keine Gruppenrichtlinien vorhanden">
          Auf einem Domänencontroller als Administrator <code>gpo-client.exe --server https://&lt;server&gt;:8080 --token &lt;token&gt;</code> ausführen.
        </EmptyState>
      </>
    )

  const gpos = data.gpos
  const count = (f: (g: Gpo) => boolean) => gpos.filter(f).length
  const goList = (patch: Partial<typeof filter>) => {
    setFilter({ q: '', kind: 'all', flag: 'all', ...patch })
    setTab('list')
  }

  return (
    <>
      <PageHeader
        title="Gruppenrichtlinien"
        description={`${data.domain ?? 'Domäne'} · ${num(gpos.length)} GPOs · Stand ${relative(data.synced_at)} (${dateTime(data.synced_at)})${data.host ? ' · von ' + data.host : ''}`}
      />
      <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <button className="text-left" onClick={() => goList({})}>
          <StatCard title="GPOs gesamt" value={num(gpos.length)} icon={<Layers className="size-4" />} />
        </button>
        <button className="text-left" onClick={() => goList({ kind: 'targeted' })}>
          <StatCard title="Gezielt zugewiesen" value={num(count((g) => g.targeting.kind === 'targeted'))} icon={<Target className="size-4" />} />
        </button>
        <button className="text-left" onClick={() => goList({ flag: 'unlinked' })}>
          <StatCard title="Nicht verknüpft" value={num(count((g) => has(g, 'unlinked')))} icon={<Unlink className="size-4" />} tone={count((g) => has(g, 'unlinked')) ? 'warn' : undefined} />
        </button>
        <button className="text-left" onClick={() => goList({ flag: 'warn' })}>
          <StatCard title="Mit Warnungen" value={num(count((g) => warns(g).length > 0))} icon={<ShieldAlert className="size-4" />} tone={count((g) => warns(g).length > 0) ? 'warn' : undefined} />
        </button>
      </div>

      <Tabs value={tab} onValueChange={setTab} className="mt-4">
        <TabsList>
          <TabsTrigger value="list">GPOs</TabsTrigger>
          <TabsTrigger value="settings">Einstellungssuche</TabsTrigger>
          <TabsTrigger value="duplicates">Doppelt / Konflikte</TabsTrigger>
          <TabsTrigger value="targets">Zuweisungen</TabsTrigger>
          <TabsTrigger value="matrix">Berechtigungsmatrix</TabsTrigger>
          <TabsTrigger value="tree">Verknüpfungen</TabsTrigger>
        </TabsList>
        <TabsContent value="list">
          <ListTab gpos={gpos} filter={filter} setFilter={setFilter} open={setOpenId} />
        </TabsContent>
        <TabsContent value="settings">
          <SettingsTab open={setOpenId} />
        </TabsContent>
        <TabsContent value="duplicates">
          <DuplicatesTab open={setOpenId} />
        </TabsContent>
        <TabsContent value="targets">
          <TargetsTab gpos={gpos} groups={data.groups} open={setOpenId} />
        </TabsContent>
        <TabsContent value="matrix">
          <MatrixTab gpos={gpos} open={setOpenId} />
        </TabsContent>
        <TabsContent value="tree">
          <TreeTab gpos={gpos} open={setOpenId} />
        </TabsContent>
      </Tabs>

      <GpoSheet id={openId} onClose={() => setOpenId(null)} />
    </>
  )
}

// ---------------------------------------------------------------------------
// Liste

function ListTab({
  gpos,
  filter,
  setFilter,
  open,
}: {
  gpos: Gpo[]
  filter: { q: string; kind: string; flag: string }
  setFilter: (f: { q: string; kind: string; flag: string }) => void
  open: (id: string) => void
}) {
  const rows = useMemo(() => {
    const terms = filter.q.toLowerCase().split(/\s+/).filter(Boolean)
    return gpos.filter((g) => {
      if (filter.kind !== 'all' && g.targeting.kind !== filter.kind) return false
      if (filter.flag === 'warn' ? !warns(g).length : filter.flag !== 'all' && !has(g, filter.flag)) return false
      const hay = [g.name, g.id, g.owner, ...g.links.map((l) => l.som_path), ...g.permissions.map((p) => p.name)].join(' ').toLowerCase()
      return terms.every((t) => hay.includes(t))
    })
  }, [gpos, filter])
  const terms = filter.q.split(/\s+/)

  return (
    <div className="mt-3 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input className="w-72" placeholder="Name, GUID, Verknüpfung, Trustee …" value={filter.q} onChange={(e) => setFilter({ ...filter, q: e.target.value })} />
        <Select value={filter.kind} onValueChange={(v) => setFilter({ ...filter, kind: v })}>
          <SelectTrigger className="w-52">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Zuweisungen</SelectItem>
            {Object.entries(KIND).map(([k, v]) => (
              <SelectItem key={k} value={k}>
                {v.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filter.flag} onValueChange={(v) => setFilter({ ...filter, flag: v })}>
          <SelectTrigger className="w-56">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Befunde</SelectItem>
            {FLAGS.map(([k, l]) => (
              <SelectItem key={k} value={k}>
                {l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-muted-foreground text-sm">{num(rows.length)} Treffer</span>
      </div>
      <Card className="py-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Zuweisung</TableHead>
              <TableHead>Verknüpft mit</TableHead>
              <TableHead>Geändert</TableHead>
              <TableHead>Befunde</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((g) => (
              <TableRow key={g.id} className="cursor-pointer align-top" onClick={() => open(g.id)}>
                <TableCell className="font-medium whitespace-normal">
                  <Hl text={g.name} terms={terms} />
                </TableCell>
                <TableCell className="whitespace-normal">
                  <KindBadge g={g} />
                  {g.targeting.kind === 'targeted' && <div className="text-muted-foreground mt-1 text-xs">{g.targeting.apply.map((p) => p.name).join(', ')}</div>}
                </TableCell>
                <TableCell className="whitespace-normal">
                  {g.links.length === 0 && <span className="text-muted-foreground">–</span>}
                  {g.links.map((l, i) => (
                    <div key={i} className={cn('text-sm break-all', !l.enabled && 'text-muted-foreground')}>
                      {l.som_path}
                      {l.enforced ? ' ⚑' : ''}
                      {l.enabled ? '' : ' (aus)'}
                    </div>
                  ))}
                </TableCell>
                <TableCell className="text-muted-foreground">{g.modified.slice(0, 10)}</TableCell>
                <TableCell className="whitespace-normal">
                  {warns(g).map((f, i) => (
                    <Badge key={i} variant="outline" className="text-sev-medium border-sev-medium/50 mr-1 font-normal" title={f.text}>
                      {f.code}
                    </Badge>
                  ))}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Einstellungssuche

function SettingsTab({ open }: { open: (id: string) => void }) {
  const [q, setQ] = useState('')
  const [scope, setScope] = useState('all')
  const [area, setArea] = useState('all')
  const { data, error, isFetching } = useQuery({
    queryKey: ['gpo-search', q, scope, area],
    queryFn: () => api.get<SearchResult>('/gpo/search' + qs({ q, scope, area })),
    placeholderData: (prev) => prev,
  })
  const inc = q.toLowerCase().split(/\s+/).filter((t) => t && !t.startsWith('-'))
  return (
    <div className="mt-3 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input className="w-96" autoFocus placeholder="Suchbegriffe (UND), -ausschluss, z. B.  firewall -domain" value={q} onChange={(e) => setQ(e.target.value)} />
        <Select value={scope} onValueChange={setScope}>
          <SelectTrigger className="w-48">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Computer + Benutzer</SelectItem>
            <SelectItem value="Computer">Computer</SelectItem>
            <SelectItem value="Benutzer">Benutzer</SelectItem>
          </SelectContent>
        </Select>
        <Select value={area} onValueChange={setArea}>
          <SelectTrigger className="w-56">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Bereiche</SelectItem>
            {(data?.areas ?? []).map((a) => (
              <SelectItem key={a} value={a}>
                {a}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {data && (
          <span className="text-muted-foreground text-sm">
            {num(data.total)} Einstellungen in {num(data.gpos)} GPOs{data.total > data.rows.length ? ` (zeige ${data.rows.length})` : ''}
            {isFetching ? ' …' : ''}
          </span>
        )}
      </div>
      {error ? (
        <ErrorState error={error} />
      ) : (
        <Card className="py-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>GPO</TableHead>
                <TableHead>Bereich</TableHead>
                <TableHead>Einstellung</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.rows ?? []).map((r, i) => (
                <TableRow key={i} className="cursor-pointer align-top" onClick={() => open(r.gpo_id)}>
                  <TableCell className="font-medium whitespace-normal">{r.gpo_name}</TableCell>
                  <TableCell className="text-muted-foreground whitespace-normal">
                    {r.scope} / {r.area}
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    <Hl text={r.name} terms={inc} />
                    {r.weakness && (
                      <div className="text-sev-medium mt-1 flex items-center gap-1 text-xs font-medium" title={r.weakness.why}>
                        <Bug className="size-3.5 shrink-0" /> Typische Schwachstelle: {r.weakness.title}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground font-mono text-xs break-words whitespace-normal">
                    <Hl text={r.detail} terms={inc} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Doppelte und widersprüchliche Einstellungen

function DuplicatesTab({ open }: { open: (id: string) => void }) {
  const [kind, setKind] = useState('all')
  const [onlyOverlap, setOnlyOverlap] = useState(true)
  const [relation, setRelation] = useState('all')
  const [onlyEnforced, setOnlyEnforced] = useState(false)
  const { data, error, isLoading } = useQuery({
    queryKey: ['gpo-duplicates'],
    queryFn: () => api.get<DuplicatesResult>('/gpo/duplicates'),
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={4} />
  const items = data.items.filter(
    (d) =>
      (kind === 'all' || d.kind === kind) &&
      (!onlyOverlap || d.overlap !== 'no') &&
      (relation === 'all' || d.link_relation === relation) &&
      (!onlyEnforced || d.enforced_count > 0),
  )
  return (
    <div className="mt-3 space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <Select value={kind} onValueChange={setKind}>
          <SelectTrigger className="w-48">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle</SelectItem>
            <SelectItem value="conflict">Konflikte</SelectItem>
            <SelectItem value="duplicate">Duplikate</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={onlyOverlap} onChange={(e) => setOnlyOverlap(e.target.checked)} />
          nur überlappende
        </label>
        <Select value={relation} onValueChange={setRelation}>
          <SelectTrigger className="w-52">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Verknüpfungen</SelectItem>
            <SelectItem value="same">{LINK_RELATION.same.label}</SelectItem>
            <SelectItem value="partial">{LINK_RELATION.partial.label}</SelectItem>
            <SelectItem value="nested">{LINK_RELATION.nested.label}</SelectItem>
            <SelectItem value="none">{LINK_RELATION.none.label}</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={onlyEnforced} onChange={(e) => setOnlyEnforced(e.target.checked)} />
          nur mit erzwungener GPO
        </label>
        <span className="text-muted-foreground text-sm">
          {num(items.length)} von {num(data.total)} Einstellungen ({num(data.conflicts)} Konflikte gesamt)
        </span>
      </div>
      {items.length === 0 ? (
        <EmptyState title="Keine Treffer">Für diese Auswahl gibt es keine mehrfach gesetzten Einstellungen.</EmptyState>
      ) : (
        items.map((d) => (
          <Card key={`${d.scope}|${d.area}|${d.name}`} className="gap-2 py-3">
            <CardHeader className="px-4">
              <div className="flex flex-wrap items-center gap-2">
                <CardTitle className="text-sm break-words">{d.name}</CardTitle>
                <Badge variant="outline" className={d.kind === 'conflict' ? 'text-sev-high border-sev-high/50' : ''}>
                  {d.kind === 'conflict' ? 'Konflikt' : 'Duplikat'}
                </Badge>
                <Badge variant="outline" className={OVERLAP[d.overlap].cls}>
                  {OVERLAP[d.overlap].label}
                </Badge>
                <Badge variant="outline" className={LINK_RELATION[d.link_relation].cls}>
                  {LINK_RELATION[d.link_relation].label}
                </Badge>
                <Badge variant="outline" className={FILTER_RELATION[d.filter_relation].cls}>
                  {FILTER_RELATION[d.filter_relation].label}
                </Badge>
                {d.enforced_count > 0 ? (
                  <Badge className="bg-sev-medium text-white">
                    <Lock className="size-3" /> {d.enforced_count} von {d.gpos.length} erzwungen
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-muted-foreground">
                    Nicht erzwungen
                  </Badge>
                )}
              </div>
              <div className="text-muted-foreground text-xs">
                {d.scope} / {d.area}
              </div>
              {d.effect && (
                <p className="mt-1 text-sm">
                  <span className="font-medium">Voraussichtlich wirksam: </span>
                  {d.effect}
                </p>
              )}
            </CardHeader>
            <CardContent className="space-y-1 px-2">
              {d.gpos.map((g) => (
                <button
                  key={g.gpo_id}
                  onClick={() => open(g.gpo_id)}
                  className="hover:bg-accent/50 grid w-full gap-x-3 gap-y-1 rounded px-2 py-1.5 text-left text-sm md:grid-cols-[14rem_1fr_1fr]"
                >
                  <span className="min-w-0">
                    <span className="block font-medium break-words">{g.gpo_name}</span>
                    {d.winner === g.gpo_id && (
                      <Badge variant="outline" className="text-ok border-ok/40 mt-0.5">
                        Setzt sich durch
                      </Badge>
                    )}
                  </span>
                  <span className="text-muted-foreground min-w-0 font-mono text-xs break-words">{g.detail}</span>
                  <span className="min-w-0 space-y-1 text-xs">
                    {g.links.length === 0 && <span className="text-muted-foreground block">Nicht verknüpft</span>}
                    {g.links.map((l) => (
                      <span
                        key={l.path}
                        className={cn('flex flex-wrap items-center gap-1.5 break-all', !l.enabled && 'text-muted-foreground line-through')}
                      >
                        {l.path}
                        {l.enforced && l.enabled && (
                          <Badge className="bg-sev-medium px-1.5 py-0 text-white">
                            <Lock className="size-3" /> Erzwungen
                          </Badge>
                        )}
                      </span>
                    ))}
                    <span className="text-muted-foreground block">
                      Filter:{' '}
                      {g.filter_kind === 'targeted'
                        ? g.filter.join(', ')
                        : g.filter_kind === 'nobody'
                          ? 'niemand'
                          : 'alle / breit'}
                    </span>
                  </span>
                </button>
              ))}
            </CardContent>
          </Card>
        ))
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Zuweisungen

function TargetsTab({ gpos, groups, open }: { gpos: Gpo[]; groups: Record<string, GpoGroup>; open: (id: string) => void }) {
  const byTarget = useMemo(() => {
    const m = new Map<string, { p: GpoPerm; gpos: Gpo[] }>()
    for (const g of gpos.filter((g) => g.targeting.kind === 'targeted'))
      for (const p of g.targeting.apply) {
        const e = m.get(p.sid) ?? { p, gpos: [] }
        e.gpos.push(g)
        m.set(p.sid, e)
      }
    return [...m.values()].sort((a, b) => b.gpos.length - a.gpos.length)
  }, [gpos])
  return (
    <div className="mt-3 space-y-3">
      <p className="text-muted-foreground text-sm">
        GPOs, die über die Sicherheitsfilterung nur bestimmten Benutzern, Computern oder Gruppen zugewiesen sind (kein „Authentifizierte Benutzer“, „Domänen-Benutzer“ oder „Domänencomputer“ mit Übernehmen-Recht).
      </p>
      {byTarget.length === 0 && <EmptyState title="Keine gezielt zugewiesenen GPOs gefunden" />}
      {byTarget.map(({ p, gpos }) => {
        const grp = groups[p.sid]
        return (
          <Card key={p.sid}>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                {p.name || p.sid}
                <Badge variant="secondary" className="font-normal">
                  {p.sid_type}
                </Badge>
                <span className="text-muted-foreground font-mono text-xs font-normal">{p.sid}</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {grp && grp.members.length > 0 && (
                <details>
                  <summary className="text-muted-foreground cursor-pointer text-sm">
                    {grp.members.length}
                    {grp.truncated ? '+' : ''} Mitglieder (rekursiv)
                  </summary>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {grp.members.map((m, i) => (
                      <Badge key={i} variant="secondary" className="font-normal">
                        {m.class === 'computer' ? '💻' : m.class === 'user' ? '👤' : '👥'} {m.name}
                      </Badge>
                    ))}
                  </div>
                </details>
              )}
              {gpos.map((g) => (
                <button key={g.id} onClick={() => open(g.id)} className="hover:bg-accent/50 flex w-full flex-wrap justify-between gap-2 rounded px-2 py-1 text-left text-sm">
                  <span>{g.name}</span>
                  <span className="text-muted-foreground">{g.links.map((l) => l.som_path).join(', ') || 'nicht verknüpft'}</span>
                </button>
              ))}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Matrix

function MatrixTab({ gpos, open }: { gpos: Gpo[]; open: (id: string) => void }) {
  const [hide, setHide] = useState(true)
  const [q, setQ] = useState('')
  const { cols, rows } = useMemo(() => {
    const c = new Map<string, { name: string; n: number }>()
    for (const g of gpos)
      for (const p of g.permissions) {
        if (hide && isAdminSid(p.sid)) continue
        const e = c.get(p.sid) ?? { name: p.name || p.sid, n: 0 }
        e.n++
        c.set(p.sid, e)
      }
    return {
      cols: [...c.entries()].sort((a, b) => b[1].n - a[1].n),
      rows: gpos.filter((g) => g.name.toLowerCase().includes(q.toLowerCase())),
    }
  }, [gpos, hide, q])
  return (
    <div className="mt-3 space-y-3">
      <div className="flex flex-wrap items-center gap-4">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={hide} onChange={(e) => setHide(e.target.checked)} /> Standard-Admins/System ausblenden
        </label>
        <Input className="w-64" placeholder="GPO filtern" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="text-muted-foreground flex items-center gap-1 text-xs">
          {['A', 'R', 'E', 'F', 'D'].map((k) => (
            <span key={k} className={cn('rounded px-1.5 font-semibold', PERM_CLS[k])}>
              {k}
            </span>
          ))}
          Übernehmen · Lesen · Bearbeiten · Voll · Verweigert
        </span>
      </div>
      <Card className="overflow-auto py-0">
        <table className="w-full text-xs">
          <thead>
            <tr>
              <th className="bg-card sticky left-0 p-2 text-left">GPO</th>
              {cols.map(([sid, c]) => (
                <th key={sid} className="h-40 p-1 align-bottom font-normal" style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}>
                  {c.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => (
              <tr key={g.id} className="border-t">
                <td className="bg-card sticky left-0 p-2">
                  <button className="text-left hover:underline" onClick={() => open(g.id)}>
                    {g.name}
                  </button>
                </td>
                {cols.map(([sid]) => (
                  <td key={sid} className="p-1 text-center">
                    {g.permissions.filter((p) => p.sid === sid).map((p, i) => (
                      <PermChip key={i} p={p} />
                    ))}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Verknüpfungsbaum

interface TreeNode {
  kids: Map<string, TreeNode>
  gpos: { g: Gpo; l: GpoLink }[]
}

function TreeTab({ gpos, open }: { gpos: Gpo[]; open: (id: string) => void }) {
  const root = useMemo(() => {
    const r: TreeNode = { kids: new Map(), gpos: [] }
    for (const g of gpos)
      for (const l of g.links) {
        let n = r
        for (const part of (l.som_path || l.som_name).split('/')) {
          if (!n.kids.has(part)) n.kids.set(part, { kids: new Map(), gpos: [] })
          n = n.kids.get(part)!
        }
        n.gpos.push({ g, l })
      }
    return r
  }, [gpos])
  const unlinked = gpos.filter((g) => g.links.length === 0)
  const draw = (n: TreeNode, top = false) => (
    <ul className={cn('space-y-1', !top && 'border-border ml-3 border-l border-dashed pl-4')}>
      {[...n.kids.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([name, c]) => (
          <li key={name}>
            <span className="inline-flex items-center gap-1 font-medium">
              <FolderTree className="text-muted-foreground size-3.5" /> {name}
            </span>
            {c.gpos.map(({ g, l }) => (
              <button key={g.id} onClick={() => open(g.id)} className="text-primary ml-2 text-sm hover:underline">
                {g.name}
                {l.enforced ? ' ⚑' : ''}
                {l.enabled ? '' : ' (aus)'}
                {g.targeting.kind === 'targeted' ? ' 🎯' : ''}
              </button>
            ))}
            {c.kids.size > 0 && draw(c)}
          </li>
        ))}
    </ul>
  )
  return (
    <div className="mt-3 space-y-3">
      <Card>
        <CardContent>{root.kids.size ? draw(root, true) : <EmptyState title="Keine Verknüpfungen" />}</CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileSearch className="size-4" /> Nicht verknüpfte GPOs ({unlinked.length})
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-1">
          {unlinked.length === 0 && <span className="text-muted-foreground text-sm">keine</span>}
          {unlinked.map((g) => (
            <button key={g.id} onClick={() => open(g.id)}>
              <Badge variant="outline" className="text-sev-medium border-sev-medium/50 font-normal">
                {g.name}
              </Badge>
            </button>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Detail

function GpoSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data, error } = useQuery({
    queryKey: ['gpo', id],
    queryFn: () => api.get<Gpo>(`/gpo/${id}`),
    enabled: !!id,
  })
  const [sq, setSq] = useState('')
  const terms = sq.toLowerCase().split(/\s+/).filter(Boolean)
  const settings = (data?.settings ?? []).filter((s) => terms.every((t) => (s.name + ' ' + s.detail).toLowerCase().includes(t)))
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full overflow-auto sm:max-w-3xl">
        <SheetHeader>
          <SheetTitle>{data?.name ?? 'GPO'}</SheetTitle>
          <SheetDescription className="font-mono text-xs">{id ? `{${id}}` : ''}</SheetDescription>
        </SheetHeader>
        {error && <ErrorState error={error} />}
        {!data && !error && <Loading rows={5} />}
        {data && (
          <div className="space-y-4 px-4 pb-6">
            <Tabs defaultValue="over">
              <TabsList>
                <TabsTrigger value="over">Übersicht</TabsTrigger>
                <TabsTrigger value="perm">Berechtigungen ({data.permissions.length})</TabsTrigger>
                <TabsTrigger value="set">Einstellungen ({data.settings?.length ?? 0})</TabsTrigger>
              </TabsList>
              <TabsContent value="over" className="space-y-4">
                <Table>
                  <TableBody>
                    {(
                      [
                        ['Domäne', data.domain],
                        ['Besitzer', data.owner],
                        ['Erstellt / Geändert', `${data.created} / ${data.modified}`],
                        ['Computer', `${data.computer_enabled ? 'aktiv' : 'deaktiviert'} · ${data.computer_version}`],
                        ['Benutzer', `${data.user_enabled ? 'aktiv' : 'deaktiviert'} · ${data.user_version}`],
                        ['WMI-Filter', data.wmi_filter || '–'],
                      ] as [string, string][]
                    ).map(([k, v]) => (
                      <TableRow key={k}>
                        <TableCell className="text-muted-foreground w-44">{k}</TableCell>
                        <TableCell className="whitespace-normal">{v}</TableCell>
                      </TableRow>
                    ))}
                    <TableRow>
                      <TableCell className="text-muted-foreground">Zuweisung</TableCell>
                      <TableCell className="whitespace-normal">
                        <KindBadge g={data} /> {data.targeting.apply.map((p) => p.name).join(', ')}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="text-muted-foreground">Verknüpfungen</TableCell>
                      <TableCell className="whitespace-normal">
                        {data.links.length === 0 && '–'}
                        {data.links.map((l, i) => (
                          <div key={i} className={cn(!l.enabled && 'text-muted-foreground')}>
                            {l.som_path}
                            {l.enforced ? ' ⚑ erzwungen' : ''}
                            {l.enabled ? '' : ' (deaktiviert)'}
                          </div>
                        ))}
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
                <div className="space-y-1">
                  <div className="font-medium">Befunde</div>
                  {data.findings.length === 0 && <span className="text-muted-foreground text-sm">keine</span>}
                  {data.findings.map((f, i) => (
                    <div key={i} className="text-sm">
                      <Badge variant="outline" className={cn('mr-2 font-normal', f.severity === 'warn' && 'text-sev-medium border-sev-medium/50')}>
                        {f.code}
                      </Badge>
                      {f.text}
                    </div>
                  ))}
                </div>
              </TabsContent>
              <TabsContent value="perm">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Trustee</TableHead>
                      <TableHead>Typ</TableHead>
                      <TableHead>Recht</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.permissions.map((p, i) => (
                      <TableRow key={i}>
                        <TableCell className="whitespace-normal">
                          {p.name || p.sid}
                          <div className="text-muted-foreground font-mono text-xs">{p.sid}</div>
                        </TableCell>
                        <TableCell>{p.sid_type}</TableCell>
                        <TableCell className="whitespace-normal">
                          <PermChip p={p} /> {p.denied ? 'Verweigert – ' : ''}
                          {PERM[p.permission]?.label ?? p.permission}
                          {p.inherited ? ' (geerbt)' : ''}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TabsContent>
              <TabsContent value="set" className="space-y-3">
                <Input placeholder="In dieser GPO suchen" value={sq} onChange={(e) => setSq(e.target.value)} />
                <Table className="table-fixed">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-24">Bereich</TableHead>
                      <TableHead>Einstellung</TableHead>
                      <TableHead className="w-1/3">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {settings.map((s, i) => (
                      <TableRow key={i} className="align-top">
                        <TableCell className="text-muted-foreground whitespace-normal">
                          {s.scope} / {s.area}
                        </TableCell>
                        <TableCell className="whitespace-normal [overflow-wrap:anywhere]">
                          <Hl text={s.name} terms={terms} />
                          {s.weakness && (
                            <div className="border-sev-medium/50 mt-1 rounded-md border p-2 text-xs">
                              <div className="text-sev-medium flex items-center gap-1 font-medium">
                                <Bug className="size-3.5 shrink-0" /> Typische Schwachstelle: {s.weakness.title}
                              </div>
                              <p className="text-muted-foreground mt-0.5">{s.weakness.why}</p>
                              <p className="mt-0.5">{s.weakness.fix}</p>
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground font-mono text-xs whitespace-normal [overflow-wrap:anywhere]">
                          <Hl text={s.detail} terms={terms} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}
