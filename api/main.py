import os, psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

app = FastAPI(title="PBPEF Dashboard API", version="0.1.0")

# Allow your local Next.js to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def db():
    if not DB_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/runs")
def list_runs(limit: int = 50, offset: int = 0):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            select run_id, created_at, task_type, domain, policy_profile,
                   alpha,beta,gamma,delta,total_energy,policy_pass
            from runs
            order by created_at desc
            limit %s offset %s
        """, (limit, offset))
        return {"items": cur.fetchall()}

@app.get("/runs/{run_id}")
def get_run(run_id: str):
    with db() as conn, conn.cursor() as cur:
        cur.execute("select * from runs where run_id=%s", (run_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "run not found")
        return row

@app.get("/runs/{run_id}/trace")
def get_trace(run_id: str):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            select operator, t_start, t_end, delta_e, energy_before, energy_after,
                   state_diff_keys, metrics, warnings, tags, attempt_index, id
            from spans
            where run_id=%s
            order by t_start asc, id asc
        """, (run_id,))
        return {"spans": cur.fetchall()}

@app.get("/runs/{run_id}/sensitivity")
def get_sensitivity(run_id: str):
    with db() as conn, conn.cursor() as cur:
        cur.execute("select * from sensitivity_runs where run_id=%s", (run_id,))
        summary = cur.fetchone()
        if not summary:
            return {"summary": None, "metrics": []}
        cur.execute("""
            select metric, prior_mu, prior_var, oat_mu, oat_var, posterior_mu, posterior_var
            from sensitivity_metrics where run_id=%s
        """, (run_id,))
        return {"summary": summary, "metrics": cur.fetchall()}

@app.get("/runs/{run_id}/evidence")
def get_evidence(run_id: str):
    with db() as conn, conn.cursor() as cur:
        cur.execute("select profile_id, environment, overall_pass, gates, metrics, artifacts, governance, content_credentials from evidence_bundles where run_id=%s", (run_id,))
        row = cur.fetchone()
        return row or {}
