import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Pencil, UserRoundCheck } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Spinner } from '@/components/common'
import { api, qs, type DataOwner } from '@/lib/api'

export function OwnerDialog({
  open,
  onOpenChange,
  systemId,
  path,
  initial,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  systemId: number
  path: string
  initial?: Partial<DataOwner> | null
}) {
  const qc = useQueryClient()
  const [owner, setOwner] = useState(initial?.owner ?? '')
  const [email, setEmail] = useState(initial?.email ?? '')
  const [note, setNote] = useState(initial?.note ?? '')
  const save = useMutation({
    mutationFn: () => fetch('/api/v1/owners', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ system_id: systemId, path, owner, email, note }),
    }).then(async (r) => {
      if (!r.ok) throw new Error((await r.json()).error ?? r.statusText)
    }),
    onSuccess: () => {
      toast.success('Dateneigentümer gespeichert')
      qc.invalidateQueries({ queryKey: ['owners'] })
      onOpenChange(false)
    },
    onError: (e) => toast.error(String(e instanceof Error ? e.message : e)),
  })
  const remove = useMutation({
    mutationFn: () => api.delete(`/owners${qs({ system_id: systemId, path })}`),
    onSuccess: () => {
      toast.success('Eintrag entfernt')
      qc.invalidateQueries({ queryKey: ['owners'] })
      onOpenChange(false)
    },
  })
  const own = initial && !initial.inherited && initial.owner
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Dateneigentümer festlegen</DialogTitle>
          <DialogDescription className="font-mono text-xs break-all">{path}</DialogDescription>
        </DialogHeader>
        <p className="text-muted-foreground text-sm">
          Die fachlich verantwortliche Person entscheidet, wer auf die Daten zugreifen darf. Der Eintrag gilt auch für
          alle Unterordner, bis dort ein eigener Eintrag gesetzt ist.
        </p>
        <div className="space-y-3">
          <Input autoFocus placeholder="Name bzw. Abteilung, z. B. „Leitung Vertrieb – M. Muster“" value={owner} onChange={(e) => setOwner(e.target.value)} />
          <Input type="email" placeholder="E-Mail (optional)" value={email} onChange={(e) => setEmail(e.target.value)} />
          <Textarea rows={3} placeholder="Notiz (optional), z. B. Zweck der Ablage" value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
        <DialogFooter className="gap-2">
          {own && (
            <Button variant="ghost" className="mr-auto" onClick={() => remove.mutate()} disabled={remove.isPending}>
              Entfernen
            </Button>
          )}
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Abbrechen
          </Button>
          <Button disabled={!owner.trim() || save.isPending} onClick={() => save.mutate()}>
            {save.isPending && <Spinner />} Speichern
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Wirksamer Dateneigentümer eines Ordners mit Bearbeiten-Knopf. */
export function OwnerField({ systemId, path }: { systemId: number; path: string }) {
  const [open, setOpen] = useState(false)
  const { data } = useQuery({
    queryKey: ['owners', 'effective', systemId, path],
    queryFn: () => api.get<DataOwner | null>(`/owners${qs({ system_id: systemId, path })}`),
  })
  return (
    <div className="flex items-start gap-2 rounded-md border px-3 py-2 text-sm">
      <UserRoundCheck className="text-muted-foreground mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="text-muted-foreground text-xs">Dateneigentümer</div>
        {data ? (
          <div className="truncate">
            {data.owner}
            {data.email && (
              <a className="text-muted-foreground ml-1 hover:underline" href={`mailto:${data.email}`}>
                &lt;{data.email}&gt;
              </a>
            )}
            {data.inherited && (
              <span className="text-muted-foreground block truncate text-xs" title={data.path}>
                festgelegt für {data.path}
              </span>
            )}
          </div>
        ) : (
          <div className="text-muted-foreground">nicht festgelegt</div>
        )}
      </div>
      <Button size="icon" variant="ghost" className="size-7" title="Dateneigentümer festlegen" onClick={() => setOpen(true)}>
        <Pencil className="size-3.5" />
      </Button>
      {open && (
        <OwnerDialog
          open
          onOpenChange={setOpen}
          systemId={systemId}
          path={path}
          initial={data && !data.inherited ? data : null}
        />
      )}
    </div>
  )
}
