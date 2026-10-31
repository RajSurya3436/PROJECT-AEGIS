# Demo runbook

A 15-minute walkthrough of the blueprint's demo story, then the Wazuh and evaluation extras.
Everything uses synthetic data; nothing leaves the machine.

## Before you start (once)

```powershell
cd "C:\path\to\Agentic SOC Project"
.\.venv\Scripts\python scripts\check_ollama.py      # want: reachable_model_present
```

- Ollama running with `qwen3:8b` (`ollama pull qwen3:8b` once). Without it, steps 1-4 and 9
  still work; the AI steps say *AI unavailable*.
- For a clean slate, stop the app and delete `data\agentic_soc.db` (it is recreated).
- Agent steps take 1-4 minutes each on an 8 GB GPU. If a run times out, set
  `AGENT_CONTEXT_TOKENS=8192` in `.env` so the model fits the GPU entirely.

Start the app **from the project folder** (so `.streamlit/config.toml` applies: local-only,
no telemetry):

```powershell
.\.venv\Scripts\python -m streamlit run app\main.py
```

Open http://127.0.0.1:8501.

## The story

1. **Load and replay.** *Data sources* → **Load demo dataset** loads the IOC list (or use
   *Replay*: speed 600x, **Start**, and watch alerts appear as data "arrives"). Say: *alerts come
   from deterministic Python rules over real records, never from the model.*
2. **Alert queue.** Five alerts. Open *Successful logon for dave from 203.0.113.45 after 12
   fails*: rule, version, severity, explanation, the exact matched events. Press
   **Investigate**.
3. **Investigation.** *Investigations* → *Timeline* (related events within ±30 min, alert matches
   marked) and *Evidence* (provenance per item; *missing telemetry* gaps recorded up front).
4. **Ask (read-only).** *Chat* → Ask: *"Could this be legitimate? Find evidence for and against
   compromise."* The answer is labelled *For compromise / Against compromise* and lists the
   lookups it made; nothing is written.
5. **Redirect.** *Chat* → Investigate, target *log investigator*: *"Search the same user's events
   for 30 minutes before and after."* Watch *Agents*: each tool call, refusal and step.
   Point out: agents can only use allowlisted tools and only cite events a tool returned.
6. **Threat intel.** The orchestrator usually sends threat intel to the IPs. Demo IPs are
   documentation addresses, so providers are never contacted (*skipped*) and the local IOC
   match is recorded instead.
7. **Verifier.** The assessment shows disposition, confidence, supporting/contradicting
   evidence, gaps and *adjusted by checks* (e.g. high confidence capped because telemetry is
   missing). It is a proposal: **Close investigation with this assessment** is a separate,
   human step.
8. **Response.** *Response* tab → **Propose response with AI**. Each proposal shows risk,
   reversibility and policy notes; anything aimed outside the investigation's own entities is
   **blocked by policy**. Approve a high-impact one, then **Simulate**: it records what *would*
   happen; there is no firewall/EDR/identity integration.
9. **Report and audit.** *Report* tab → download Markdown or JSON (instructions, assessment,
   recommendations, simulated actions, next steps, audit trail). Then the *Audit log* page:
   filter *Response* or *Agent tool calls*.

Without the UI, the same story runs from the command line:
`.\.venv\Scripts\python scripts\run_agent_demo.py` (Ask, redirect, verifier, plan, simulate,
report, audit; about 4-6 minutes).

## Extras

- **Wazuh.** *Data sources* → *Live inputs* → *Follow a file*: leave the path empty (bundled
  sample), layout **Wazuh alerts**, **Follow this file**, **Poll now**. Seven alerts appear,
  including two from Wazuh's own high-level rules. Append lines to a followed file to show live
  following.
- **HTTP receiver.** *Live inputs* → *HTTP receiver* → **Start receiver**, then run the
  `curl.exe` command shown. Mention it listens on 127.0.0.1 only and refuses browser requests.
- **Evaluation.** `.\.venv\Scripts\python scripts\run_eval.py --detection-only` (seconds), or
  without the flag to grade the model's verdicts against ground truth (about 20-30 minutes);
  see [evaluation.md](evaluation.md).

## If something goes wrong

- *AI unavailable*: start Ollama, check with `scripts\check_ollama.py`.
- *A run says waiting*: the agents asked you a question; answer in Investigate mode.
- *A run is interrupted after a restart*: **Resume from checkpoint** on the Agents tab.
- More in the README's *Troubleshooting*.
