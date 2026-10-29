# PermissionCenter – Web-Oberfläche

React 19 + Vite + Tailwind CSS 4 + shadcn/ui (Radix UI), Graphen mit Cytoscape.js.

```bash
npm ci
npm run dev     # Entwicklung, /api wird an http://localhost:8080 weitergeleitet (PC_API überschreibt)
npm run build   # Ergebnis in dist/, wird beim Bau von pc-server eingebettet
```

UI-Komponenten liegen unter `src/components/ui` (shadcn, per `npx shadcn@latest add …` ergänzbar),
Seiten unter `src/pages`, API-Typen in `src/lib/api.ts`.
