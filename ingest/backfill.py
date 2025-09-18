import os, glob, json
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from pathlib import Path
import re
from datetime import datetime, timezone

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")
TRACE_DIR = os.getenv("TRACE_DIR") or os.path.join(os.getcwd(), "traces")

def load_json(p):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def iter_spans(spans_path):
    with open(spans_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            yield json.loads(line)

def sidecar(sum_path: Path, kind: str) -> Path:
    """
    Build sibling file paths from a summary path.

    kind: "spans" | "sensitivity" | "bundle"
    """
    repl = {
        "spans": ".spans.jsonl",
        "sensitivity": ".sensitivity.json",
        "bundle": ".bundle.json",
        "evidence": ".bundle.json",
        "manifest": ".manifest.json",
        "review queue": ".review.json"
        
    }[kind]
    # Replace the tail ".summary.json" on the file name only
    return sum_path.with_name(sum_path.name.replace(".summary.json", repl))

def main():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()

    pattern = str(Path(TRACE_DIR) / "run_*_*.summary.json")
    # RECURSIVE: find all summaries under TRACE_DIR
    files = sorted(Path(TRACE_DIR).rglob("run_*_*.summary.json"))

    print(f"Found {len(files)} summaries in {TRACE_DIR}")

    def infer_created_at(path: Path) -> datetime:
        """Prefer run_id timestamp; fallback to file mtime."""
        m = re.search(r"run_(\d{8}-\d{6})_", path.name)
        if m:
            ts = datetime.strptime(m.group(1), "%Y%m%d-%H%M%S")
            return ts.replace(tzinfo=timezone.utc)
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

    for sum_path in files:
        summary = load_json(sum_path)
        run_id = summary.get("run_id") or sum_path.name.replace(".summary.json", "")
        # 1) insert run if not exists
        cur.execute("select 1 from runs where run_id=%s", (run_id,))
        if not cur.fetchone():
            created_at = infer_created_at(Path(sum_path))
            cur.execute("""
                insert into runs(run_id, created_at, task_type, domain, user_tier, policy_profile,
                                 alpha,beta,gamma,delta,total_energy, policy_pass,
                                 failed_gates, cost, latency, safety, true_cost)
                values (%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s)
            """, (
                run_id, created_at,
                summary.get("task_type"), summary.get("domain"),
                summary.get("user_tier"), summary.get("policy_profile"),
                summary["metrics"]["alpha"], summary["metrics"]["beta"],
                summary["metrics"]["gamma"], summary["metrics"]["delta"],
                summary["metrics"].get("total_energy"),
                summary.get("policy_gates",{}).get("policy_pass"),
                json.dumps(summary.get("policy_gates",{}).get("failed_gates")),
                json.dumps(summary.get("cost")), json.dumps(summary.get("latency")),
                json.dumps(summary.get("safety")), json.dumps(summary.get("true_cost"))
            ))
            print(f"Inserted run {run_id}")
        else:
            print(f"Run {run_id} exists, skipping runs insert")

        # 2) spans
        spans_path = sidecar(sum_path, "spans")
        if spans_path.exists():
            cur.execute("select 1 from spans where run_id=%s limit 1", (run_id,))
            if not cur.fetchone():
                rows = []
                for s in iter_spans(spans_path):
                    rows.append((
                        run_id, s.get("operator"), s.get("t_start"), s.get("t_end"),
                        json.dumps(s.get("energy_before")), json.dumps(s.get("energy_after")),
                        json.dumps(s.get("delta_e")), json.dumps(s.get("state_before")),
                        json.dumps(s.get("state_after")), json.dumps(s.get("state_diff_keys")),
                        json.dumps(s.get("metrics")), json.dumps(s.get("warnings")),
                        json.dumps(s.get("tags")), s.get("attempt_index")
                    ))
                execute_values(cur, """
                    insert into spans(run_id, operator, t_start, t_end, energy_before, energy_after, delta_e,
                                      state_before, state_after, state_diff_keys, metrics, warnings, tags, attempt_index)
                    values %s
                """, rows)
                print(f"Inserted {len(rows)} spans for {run_id}")
            else:
                print(f"Spans for {run_id} exist, skipping")

        # 3) sensitivity (optional)
        sens_path  = sidecar(sum_path, "sensitivity")
        if sens_path.exists():
            sens = load_json(sens_path)

            cur.execute("select 1 from sensitivity_runs where run_id=%s", (run_id,))
            if not cur.fetchone():
                meta = sens.get("meta") or {}
                # mode fallback logic
                mode = (
                    meta.get("mode")
                    or ("hybrid" if ("posterior" in sens and "oat" in sens and "prior" in sens)
                        else "measured" if "oat" in sens
                        else "prior" if "prior" in sens
                        else "unknown")
                )

                summary_block = sens.get("summary") or {}
                top_metric = summary_block.get("top_metric") or {}
                # key exists but may be null -> coerce to {}
                dir_rec = (summary_block.get("directional_recommendation") or {}) 

                # counts
                probes_list = ((sens.get("oat") or {}).get("probes") or [])
                interact_flag = 1 if sens.get("interactions") else 0
                seq_flag = 1 if sens.get("sequence") else 0

                cur.execute("""
                    insert into sensitivity_runs(
                      run_id, mode, top_metric_name, top_metric_mu,
                      priority_metric, priority_reason, recommendation_family, recommendation_direction,
                      expected_delta, budget_used, probes, interact, seq_orders,
                      has_prior, has_measured, has_posterior
                    ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    run_id, mode, top_metric.get("name"), top_metric.get("mu"),
                    summary_block.get("priority_metric"),
                    summary_block.get("priority_reason"),
                    dir_rec.get("family"),          # may be None → DB NULL (ok)
                    dir_rec.get("need"),            # may be None → DB NULL (ok)
                    dir_rec.get("expected_delta"),  # may be None → DB NULL (ok)
                    meta.get("budget_used") or 0,
                    len(probes_list), interact_flag, seq_flag,
                    ("prior" in sens), ("oat" in sens), ("posterior" in sens)
                ))

                # helper to read mu/var safely
                def get_mu_var(block, metric):
                    if not block:
                        return (None, None)
                    per_metric = block.get("per_metric") or {}
                    entry = per_metric.get(metric) or {}
                    return (entry.get("mu"), entry.get("var"))

                # per-metric rows
                for m in ["alpha", "beta", "gamma", "delta"]:
                    pmu, pvar = get_mu_var(sens.get("prior"), m)
                    omu, ovar = get_mu_var(sens.get("oat"), m)
                    smu, svar = get_mu_var(sens.get("posterior"), m)
                    cur.execute("""
                        insert into sensitivity_metrics(
                          run_id, metric, prior_mu, prior_var, oat_mu, oat_var, posterior_mu, posterior_var
                        ) values (%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (run_id, m, pmu, pvar, omu, ovar, smu, svar))

                print(f"Inserted sensitivity summary for {run_id}")


        # 4) evidence bundle (optional)
        bundle_path = sidecar(sum_path, "bundle")
        if bundle_path.exists():
            cur.execute("select 1 from evidence_bundles where run_id=%s", (run_id,))
            if not cur.fetchone():
                b = load_json(bundle_path)
                cur.execute("""
                    insert into evidence_bundles(run_id, profile_id, environment, overall_pass,
                        gates, metrics, artifacts, governance, content_credentials)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    run_id, b.get("profile_id"), b.get("environment"), b.get("gates",{}).get("overall_pass"),
                    json.dumps(b.get("gates")), json.dumps(b.get("metrics")), json.dumps(b.get("artifacts")),
                    json.dumps(b.get("governance")), json.dumps(b.get("content_credentials"))
                ))
                print(f"Inserted evidence bundle for {run_id}")

    conn.commit()
    cur.close(); conn.close()
    print("Backfill complete.")

if __name__ == "__main__":
    main()
