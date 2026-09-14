# forescout-lookup

Two tools for a Forescout Enterprise Manager:

- **Host lookup web app** (`app.py`) — self-serve IP/host lookup across appliances, deployed via `webapp-query.py`.
- **ForeScout Tech Support Collector** — a self-contained log-collection tool. **To deploy it, don't run `Deploy.sh` from this repo root.** Go to [`dist/ForeScoutTechSupport/`](dist/ForeScoutTechSupport/) — that folder has everything it needs (including the pre-built `image.tar`) and its own README. Also available as a single `ForeScoutTechSupport.zip` download from this repo's [Releases](../../releases) page if you don't want the whole source repo.

Everything else here (`app.py`, `forescout_client.py`, templates, `build-dist.sh`) is the source this Tech Support Collector package is built from.
