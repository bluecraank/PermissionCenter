import { useMemo, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ClipboardCopy,
  Clock,
  Download,
  FileCode2,
  Info,
  RefreshCw,
  RotateCcw,
  ShieldOff,
  SkipForward,
  Target,
  XCircle,
} from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Progress } from '@/components/ui/progress'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { EmptyState, ErrorState, Loading, PageHeader, SeverityBadge, Spinner } from '@/components/common'
import { api, qs, type AssistDetail, type AssistItem, type AssistOverview, type SystemSummary } from '@/lib/api'
import { dateTime, num, relative, severityColor } from '@/lib/format'
import { cn } from '@/lib/utils'

/** Kopiert Text – auch ohne sicheren Kontext (HTTP), in dem navigator.clipboard fehlt. */
async function copyText(text: string) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.select()
  const ok = document.execCommand('copy')
  document.body.removeChild(ta)
  if (!ok) throw new Error('Kopieren nicht möglich')
}

function downloadScript(name: string, body: string) {
  // UTF-8 mit BOM, damit Windows PowerShell 5.1 Umlaute korrekt liest
  const blob = new Blob(['﻿' + body], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-muted-foreground text-xs font-semibold tracking-wide uppercase">{title}</h3>
      {children}
    </section>
  )
}

function ScriptBlock({ script }: { script: NonNullable<AssistDetail['guide']['script']> }) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <FileCode2 className="text-muted-foreground size-4" />
        <span className="font-mono">{script.file_name}</span>
        <Badge variant={script.kind === 'change' ? 'secondary' : 'outline'}>
          {script.kind === 'change' ? 'Probelauf, dann -Apply' : 'Nur lesend'}
        </Badge>
        <div className="ml-auto flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              copyText(script.body.replace(/\r\n/g, '\n')).then(
                () => toast.success('Skript kopiert'),
                (e) => toast.error(String(e)),
              )
            }
          >
            <ClipboardCopy className="size-4" /> Kopieren
          </Button>
          <Button size="sm" variant="outline" onClick={() => downloadScript(script.file_name, script.body)}>
            <Download className="size-4" /> Herunterladen
          </Button>
        </div>
      </div>
      <p className="text-muted-foreground flex items-start gap-1.5 text-xs">
        <Target className="mt-0.5 size-3.5 shrink-0" /> Ausführen auf: {script.target}
      </p>
      <pre className="bg-muted max-h-80 overflow-auto rounded-md p-3 font-mono text-xs leading-relaxed">{script.body}</pre>
    </div>
  )
}

function AcceptDialog({
  open,
  onOpenChange,
  title,
  onConfirm,
  busy,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  title: string
  onConfirm: (note: string) => void
  busy: boolean
}) {
  const [note, setNote] = useState('')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Als Ausnahme akzeptieren</DialogTitle>
          <DialogDescription>
            „{title}“ bleibt sichtbar, zählt aber nicht mehr in die Bewertung. Die Begründung wird für spätere Audits
            gespeichert.
          </DialogDescription>
        </DialogHeader>
        <Textarea
          autoFocus
          rows={4}
          placeholder="Begründung, z. B. „Vertraulicher Bereich der Geschäftsführung, Unterbrechung gewollt – freigegeben von …“"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Abbrechen
          </Button>
          <Button disabled={!note.trim() || busy} onClick={() => onConfirm(note.trim())}>
            {busy && <Spinner />} Ausnahme speichern
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function StepCard({
  item,
  index,
  total,
  ldapConfigured,
  onPrev,
  onSkip,
}: {
  item: AssistItem
  index: number
  total: number
  ldapConfigured: boolean
  onPrev: () => void
  onSkip: () => void
}) {
  const qc = useQueryClient()
  const [acceptOpen, setAcceptOpen] = useState(false)
  const { data, isLoading, error } = useQuery({
    queryKey: ['assist', 'detail', item.fingerprint],
    queryFn: () => api.get<AssistDetail>(`/assist/${item.fingerprint}`),
  })
  const update = useMutation({
    mutationFn: (body: { status: 'fixed' | 'accepted' | 'open'; note?: string }) =>
      api.post(`/assist/${item.fingerprint}`, body),
    onSuccess: (_, body) => {
      setAcceptOpen(false)
      toast.success(body.status === 'fixed' ? 'Als erledigt markiert – der nächste Scan prüft es' : 'Ausnahme gespeichert')
      qc.invalidateQueries()
    },
    onError: (e) => toast.error(String(e instanceof Error ? e.message : e)),
  })
  const sync = useMutation({
    mutationFn: () => api.post('/ad/sync'),
    onSuccess: () => {
      toast.success('AD abgeglichen und neu analysiert')
      qc.invalidateQueries()
    },
    onError: (e) => toast.error(String(e instanceof Error ? e.message : e)),
  })
  const g = data?.guide

  return (
    <Card className="gap-4">
      <CardHeader className="gap-2">
        <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-sm">
          <span className="text-foreground font-medium">
            Schritt {num(index + 1)} von {num(total)}
          </span>
          <SeverityBadge severity={item.severity} />
          <Badge variant="outline">
            {item.system_id ? (
              <Link to={`/systems/${item.system_id}`} className="hover:underline">
                {item.hostname}
              </Link>
            ) : (
              'Active Directory'
            )}
          </Badge>
          {item.rule_title && <span>{item.rule_title}</span>}
        </div>
        <CardTitle className="text-xl leading-snug">{item.title}</CardTitle>
        {data?.rule && <CardDescription>{data.rule.description}</CardDescription>}
      </CardHeader>
      <CardContent className="space-y-6">
        {item.assist_status === 'failed' && (
          <Alert variant="destructive">
            <XCircle />
            <AlertTitle>Noch nicht behoben</AlertTitle>
            <AlertDescription>
              Am {dateTime(item.updated_at)} als erledigt markiert, nach den Daten vom {dateTime(item.data_at)} aber
              weiterhin vorhanden. Bitte Schritte und Skriptausgabe prüfen.
            </AlertDescription>
          </Alert>
        )}
        {error && <ErrorState error={error} />}
        {isLoading || !g ? (
          <Loading rows={5} />
        ) : (
          <>
            <Section title="So gehst du vor">
              <ol className="space-y-2">
                {g.steps.map((s, i) => (
                  <li key={i} className="flex gap-3 text-sm">
                    <span className="bg-primary text-primary-foreground flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold">
                      {i + 1}
                    </span>
                    <span className="pt-0.5">{s}</span>
                  </li>
                ))}
              </ol>
            </Section>
            {g.warning && (
              <Alert>
                <AlertTriangle className="text-sev-medium" />
                <AlertTitle>Vor dem Ausführen beachten</AlertTitle>
                <AlertDescription>{g.warning}</AlertDescription>
              </Alert>
            )}
            {g.objects.length > 0 && (
              <Section title={`Betroffen (${num(g.objects_total)})`}>
                <div className="max-h-56 divide-y overflow-auto rounded-md border text-sm">
                  {g.objects.map((o, i) => (
                    <div key={i} className="flex flex-col gap-0.5 px-3 py-1.5 sm:flex-row sm:items-center sm:gap-3">
                      <span className="min-w-0 flex-1 truncate font-mono text-xs" title={o.label}>
                        {o.label}
                      </span>
                      <span className="text-muted-foreground shrink-0 text-xs">{o.info}</span>
                    </div>
                  ))}
                </div>
                {g.objects_total > g.objects.length && (
                  <p className="text-muted-foreground text-xs">
                    Angezeigt und im Skript enthalten: die ersten {num(g.objects.length)}. Nach dem Ausführen und einem
                    neuen Scan erscheinen die übrigen erneut.
                  </p>
                )}
              </Section>
            )}
            {g.script && (
              <Section title="Skript">
                <ScriptBlock script={g.script} />
              </Section>
            )}
            <p className="text-muted-foreground flex items-start gap-2 text-sm">
              <Info className="mt-0.5 size-4 shrink-0" />
              {g.verify}
            </p>
          </>
        )}
      </CardContent>
      <CardFooter className="flex flex-wrap gap-2 border-t pt-4">
        <Button variant="ghost" onClick={onPrev} disabled={index === 0}>
          <ArrowLeft className="size-4" /> Zurück
        </Button>
        <Button variant="ghost" onClick={onSkip} disabled={total <= 1}>
          <SkipForward className="size-4" /> Später
        </Button>
        {!item.system_id && ldapConfigured && (
          <Button variant="outline" onClick={() => sync.mutate()} disabled={sync.isPending}>
            {sync.isPending ? <Spinner /> : <RefreshCw className="size-4" />} AD jetzt abgleichen
          </Button>
        )}
        <div className="ml-auto flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => setAcceptOpen(true)}>
            <ShieldOff className="size-4" /> Ausnahme…
          </Button>
          <Button onClick={() => update.mutate({ status: 'fixed' })} disabled={update.isPending}>
            {update.isPending ? <Spinner /> : <CheckCircle2 className="size-4" />} Erledigt
          </Button>
        </div>
      </CardFooter>
      <AcceptDialog
        key={String(acceptOpen)}
        open={acceptOpen}
        onOpenChange={setAcceptOpen}
        title={item.title}
        busy={update.isPending}
        onConfirm={(note) => update.mutate({ status: 'accepted', note })}
      />
    </Card>
  )
}

function QueueList({ items, current, onSelect }: { items: AssistItem[]; current: number; onSelect: (i: number) => void }) {
  const shown = items.slice(0, 300)
  return (
    <Card className="gap-2 py-4">
      <CardHeader className="px-4">
        <CardTitle className="text-sm">Reihenfolge</CardTitle>
        <CardDescription>Höchste Schwere und größter Hebel zuerst</CardDescription>
      </CardHeader>
      <CardContent className="max-h-[70vh] overflow-auto px-2">
        {shown.map((it, i) => (
          <button
            key={it.fingerprint}
            onClick={() => onSelect(i)}
            className={cn(
              'hover:bg-accent flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-sm',
              i === current && 'bg-accent',
            )}
          >
            <span className="text-muted-foreground w-6 shrink-0 pt-0.5 text-right text-xs tabular-nums">{i + 1}</span>
            <span className="mt-1.5 size-2 shrink-0 rounded-full" style={{ background: severityColor[it.severity] }} />
            <span className="min-w-0 flex-1">
              <span className={cn('block truncate', i === current && 'font-medium')}>{it.title}</span>
              <span className="text-muted-foreground block truncate text-xs">
                {it.hostname ?? 'Active Directory'}
                {it.assist_status === 'failed' && <span className="text-sev-high"> · nicht bestätigt</span>}
              </span>
            </span>
          </button>
        ))}
        {items.length > shown.length && (
          <p className="text-muted-foreground px-2 py-2 text-xs">… und {num(items.length - shown.length)} weitere</p>
        )}
      </CardContent>
    </Card>
  )
}

function DoneList({ data }: { data: AssistOverview }) {
  const qc = useQueryClient()
  const reopen = useMutation({
    mutationFn: (fp: string) => api.post(`/assist/${fp}`, { status: 'open' }),
    onSuccess: () => {
      toast.success('Wieder offen')
      qc.invalidateQueries()
    },
  })
  const pending = data.items.filter((i) => i.assist_status === 'pending')
  const accepted = data.items.filter((i) => i.assist_status === 'accepted')
  const row = (it: AssistItem, extra: ReactNode, action: string) => (
    <div key={it.fingerprint} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={it.severity} />
          <span className="truncate font-medium">{it.title}</span>
        </div>
        <div className="text-muted-foreground mt-1 text-xs">
          {it.hostname ?? 'Active Directory'} · {extra}
        </div>
      </div>
      <Button size="sm" variant="ghost" onClick={() => reopen.mutate(it.fingerprint)} disabled={reopen.isPending}>
        <RotateCcw className="size-4" /> {action}
      </Button>
    </div>
  )
  return (
    <div className="space-y-4">
      <Card className="gap-2">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Clock className="text-sev-low size-4" /> Warten auf Bestätigung ({num(pending.length)})
          </CardTitle>
          <CardDescription>Als erledigt markiert – der nächste Scan bzw. AD-Abgleich prüft das Ergebnis.</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          {pending.length === 0 ? (
            <p className="text-muted-foreground text-sm">Nichts ausstehend.</p>
          ) : (
            pending.map((it) => row(it, <>markiert {relative(it.updated_at)}</>, 'Wieder öffnen'))
          )}
        </CardContent>
      </Card>
      <Card className="gap-2">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldOff className="text-muted-foreground size-4" /> Ausnahmen ({num(accepted.length)})
          </CardTitle>
          <CardDescription>Bewusst akzeptierte Befunde – zählen nicht in die Bewertung.</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          {accepted.length === 0 ? (
            <p className="text-muted-foreground text-sm">Keine Ausnahmen.</p>
          ) : (
            accepted.map((it) =>
              row(
                it,
                <>
                  {dateTime(it.updated_at)} · <span className="text-foreground">{it.note}</span>
                </>,
                'Aufheben',
              ),
            )
          )}
        </CardContent>
      </Card>
      <Card className="gap-2">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <CheckCircle2 className="text-ok size-4" /> Behoben ({num(data.summary.resolved)})
          </CardTitle>
          <CardDescription>Durch Scan bzw. AD-Abgleich bestätigt.</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          {data.resolved.length === 0 ? (
            <p className="text-muted-foreground text-sm">Noch nichts bestätigt.</p>
          ) : (
            data.resolved.map((r) => (
              <div key={r.fingerprint} className="flex flex-col gap-1 py-2 text-sm sm:flex-row sm:items-center sm:gap-3">
                <CheckCircle2 className="text-ok hidden size-4 shrink-0 sm:block" />
                <span className="min-w-0 flex-1 truncate">{r.title}</span>
                <span className="text-muted-foreground shrink-0 text-xs">
                  {r.hostname ?? 'Active Directory'} · {dateTime(r.resolved_at)}
                </span>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  )
}

export default function AssistPage() {
  const qc = useQueryClient()
  const [params] = useSearchParams()
  const [scope, setScope] = useState(params.get('scope') ?? 'all')
  const [withInfo, setWithInfo] = useState(true)
  const [pos, setPos] = useState(0)
  // Direkter Einstieg über ?f=<Kennung> (z. B. aus der Befundliste)
  const [jump, setJump] = useState(params.get('f'))

  const systems = useQuery({ queryKey: ['systems'], queryFn: () => api.get<SystemSummary[]>('/systems') })
  const filter = scope.startsWith('sys:') ? { system_id: scope.slice(4) } : { scope }
  const { data, isLoading, error } = useQuery({
    queryKey: ['assist', 'overview', filter],
    queryFn: () => api.get<AssistOverview>(`/assist${qs(filter)}`),
  })
  const analyze = useMutation({
    mutationFn: () => api.post('/analyze'),
    onSuccess: () => {
      toast.success('Analyse neu berechnet')
      qc.invalidateQueries()
    },
  })

  const queue = useMemo(
    () =>
      (data?.items ?? []).filter(
        (i) => (i.assist_status === 'open' || i.assist_status === 'failed') && (withInfo || i.severity !== 'info'),
      ),
    [data, withInfo],
  )

  if (jump && queue.length > 0) {
    setJump(null)
    const i = queue.findIndex((q) => q.fingerprint === jump)
    if (i >= 0) setPos(i)
  }

  const current = queue.length ? Math.min(pos, queue.length - 1) : 0

  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={8} />

  const s = data.summary
  const total = s.open + s.failed + s.pending + s.accepted + s.resolved
  const done = s.pending + s.accepted + s.resolved

  return (
    <>
      <PageHeader
        title="Audit-Assist"
        description="Alle offenen Befunde Schritt für Schritt beheben – wichtigste zuerst"
        actions={
          <>
            <Select
              value={scope}
              onValueChange={(v) => {
                setScope(v)
                setPos(0)
              }}
            >
              <SelectTrigger className="w-52">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Alle Bereiche</SelectItem>
                <SelectItem value="system">Alle Dateisysteme</SelectItem>
                <SelectItem value="ad">Active Directory</SelectItem>
                {systems.data?.map((y) => (
                  <SelectItem key={y.id} value={`sys:${y.id}`}>
                    {y.hostname}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant={withInfo ? 'secondary' : 'outline'} onClick={() => setWithInfo(!withInfo)}>
              {withInfo ? 'Mit Info-Befunden' : 'Ohne Info-Befunde'}
            </Button>
            <Button variant="outline" onClick={() => analyze.mutate()} disabled={analyze.isPending}>
              {analyze.isPending ? <Spinner /> : <RefreshCw className="size-4" />} Neu analysieren
            </Button>
          </>
        }
      />

      <Card className="gap-3 py-4">
        <CardContent className="space-y-3 px-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className="text-sm font-medium">
              {num(done)} von {num(total)} erledigt
            </span>
            <span className="text-muted-foreground text-xs">Stand der Analyse: {dateTime(data.analysis_at)}</span>
          </div>
          <Progress value={(done / Math.max(1, total)) * 100} />
          <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
            <span>
              <strong className="tabular-nums">{num(s.open)}</strong> offen
            </span>
            {s.failed > 0 && (
              <span className="text-sev-high">
                <strong className="tabular-nums">{num(s.failed)}</strong> nicht bestätigt
              </span>
            )}
            <span className="text-muted-foreground">
              <strong className="text-foreground tabular-nums">{num(s.pending)}</strong> warten auf Scan
            </span>
            <span className="text-muted-foreground">
              <strong className="text-foreground tabular-nums">{num(s.accepted)}</strong> Ausnahmen
            </span>
            <span className="text-muted-foreground">
              <strong className="text-ok tabular-nums">{num(s.resolved)}</strong> behoben
            </span>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="assist">
        <TabsList>
          <TabsTrigger value="assist">Assistent ({num(queue.length)})</TabsTrigger>
          <TabsTrigger value="done">Erledigt & Ausnahmen</TabsTrigger>
        </TabsList>
        <TabsContent value="assist" className="mt-4">
          {queue.length === 0 ? (
            <EmptyState title="Keine offenen Befunde">
              <CheckCircle2 className="text-ok mx-auto mb-2 size-6" />
              {s.pending > 0
                ? `${num(s.pending)} Befunde warten auf die Bestätigung durch den nächsten Scan bzw. AD-Abgleich.`
                : 'Für diese Auswahl ist alles erledigt.'}
            </EmptyState>
          ) : (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
              <StepCard
                key={queue[current].fingerprint}
                item={queue[current]}
                index={current}
                total={queue.length}
                ldapConfigured={data.ldap_configured}
                onPrev={() => setPos(Math.max(0, current - 1))}
                onSkip={() => setPos((current + 1) % queue.length)}
              />
              <QueueList items={queue} current={current} onSelect={setPos} />
            </div>
          )}
        </TabsContent>
        <TabsContent value="done" className="mt-4">
          <DoneList data={data} />
        </TabsContent>
      </Tabs>
    </>
  )
}
