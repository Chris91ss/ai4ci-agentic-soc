# SOC console

Next.js console of the Agentic SOC: stream health, the incident queue, incident timelines with
the agent's tool trace and the evidence behind every verdict, approve/reject controls for held
containment actions, analyst feedback, live metrics with the drift monitor, the evaluation results
(agent against the baselines, detectors, drift and load) and the hash-chained audit log.

Built with Next.js (App Router), Tailwind CSS, [Tabler icons](https://tabler.io/icons),
[framer-motion](https://motion.dev), TanStack Query, Recharts, Radix UI primitives, cmdk
(⌘K command palette) and sonner (toasts).

## Run

The console talks to the FastAPI backend (`agentic_soc.api`):

```bash
# from the repository root: a live demo (simulator + pipeline + API) ...
uv run soc demo --speed 120
# ... the same with the agent on the local LLM, the clock paused while it investigates ...
uv run soc demo --llm ollama:gpt-oss:20b --pause-for-agent
# ... or a recorded run (read-only, replayed in the activity feed)
uv run soc api --run data/soc-runs/agent-seed201

cd web
npm install
npm run dev            # http://localhost:3000, API at http://127.0.0.1:8000/api
```

Set `NEXT_PUBLIC_API_URL` to use another API address.

## Static demo (GitHub Pages)

With `NEXT_PUBLIC_DATA=static` the console reads a recorded run exported as JSON under
`public/data/` instead of the API, and replays its pipeline log; approvals and feedback are
read-only. The Pages workflow (`.github/workflows/pages.yml`) builds it on every push to `main`
that touches `web/`; Pages has to be enabled once, with GitHub Actions as the source
(repository Settings → Pages):

```bash
# from the repository root: the demo run (scenario S1 with retraining), exported with
# docs/evaluation into web/public/data
uv run soc run --scenario config/scenarios/s1-remote-work.yaml --hours 72 --seed 301 \
  --retrain-on-drift --out data/soc-runs/s1-retrain-seed301
uv run soc export --run data/soc-runs/s1-retrain-seed301

cd web
STATIC_EXPORT=1 NEXT_PUBLIC_DATA=static npm run build   # the site, in out/
npx serve out                                          # preview on http://localhost:3000
```

The workflow builds with `NEXT_PUBLIC_BASE_PATH=/ai4ci-agentic-soc`, the path Pages serves the
site under. The export keeps every incident with its evidence and agent trace, and the entities
of triaged incidents and of containment actions with their newest events.

## The README's images

`npm run capture` regenerates the repository README's screenshots and gallery (`docs/assets/`), the demo GIF
and the link preview (`public/social.png`, from `scripts/social-card.html`) from the static
build, in headless Chrome. It uses puppeteer-core with the installed Chrome (`CHROME_PATH` to
point elsewhere), and ffmpeg for the GIF:

```bash
STATIC_EXPORT=1 NEXT_PUBLIC_DATA=static npm run build
npm run capture                           # all of them
node scripts/capture.mjs gallery social   # or some: shots, gallery, tour, social
```

## Layout

- `src/app/`: pages (overview, incidents, incident, entities, entity, actions, metrics, evaluation, audit)
- `src/components/shell/`: sidebar, top bar (simulation clock, live/replay status), command palette
- `src/components/soc/`, `src/components/incident/`: SOC widgets (risk gauge, kill chain, alert lanes,
  agent trace, evidence explorer, approvals)
- `src/components/evaluation/`: evaluation views (end to end, detectors, S1 drift, S2 load, local LLM)
- `src/components/ui/`: design-system primitives
- `src/lib/`: API client (live or static), React Query hooks, live events (SSE or replay), formatting
- `scripts/`: `capture.mjs` and the link preview's card
