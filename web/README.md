# SOC console

Next.js console of the Agentic SOC: stream health, the incident queue, incident timelines with
the agent's tool trace and the evidence behind every verdict, approve/reject controls for held
containment actions, analyst feedback, live metrics and the hash-chained audit log.

Built with Next.js (App Router), Tailwind CSS, [Tabler icons](https://tabler.io/icons),
[framer-motion](https://motion.dev), TanStack Query, Recharts, Radix UI primitives, cmdk
(⌘K command palette) and sonner (toasts).

## Run

The console talks to the FastAPI backend (`agentic_soc.api`):

```bash
# from the repository root: a live demo (simulator + pipeline + API) ...
uv run soc demo --speed 120
# ... or a recorded run (read-only, replayed in the activity feed)
uv run soc api --run data/soc-runs/agent-seed201

cd web
npm install
npm run dev            # http://localhost:3000, API at http://127.0.0.1:8000/api
```

Set `NEXT_PUBLIC_API_URL` to use another API address. With `NEXT_PUBLIC_DATA=static` the
console reads a recorded run exported as JSON under `public/data/` instead of the API, which is
how the GitHub Pages demo is built (`STATIC_EXPORT=1 NEXT_PUBLIC_BASE_PATH=/repo npm run build`).

## Layout

- `src/app/`: pages (overview, incidents, incident, entities, entity, actions, metrics, audit)
- `src/components/shell/`: sidebar, top bar (simulation clock, live/replay status), command palette
- `src/components/soc/`, `src/components/incident/`: SOC widgets (risk gauge, kill chain, alert lanes,
  agent trace, evidence explorer, approvals)
- `src/components/ui/`: design-system primitives
- `src/lib/`: API client (live or static), React Query hooks, live events (SSE or replay), formatting
