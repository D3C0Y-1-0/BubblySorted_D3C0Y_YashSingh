# Bank Contract

Conditions the demo bank (Phase 8) must meet. Copied from `plan/claudesPLAN.md`.


**Per service.** Each service is **one folder directly under `bank/`**: transaction/Java, account/Rust, support/PHP and notifications/Node, plus an optional Python service.
1. A pinned manifest and lockfile with the seeded version:
   - log4j-core 2.14.1
   - regex 1.5.4
   - a phpmailer pre-fix release
   - lodash 4.17.15 + jsonwebtoken 8.5.1

   Each version is checked on osv.dev.
2. The vulnerable package is imported **and called** in source. User input never reaches the vulnerable path (for example, log4j logs only constants and runs with `-Dlog4j2.formatMsgNoLookups=true`). The data is fake.
3. `GET /health` returns `200 {"status":"ok"}`.
4. The `test_cmd` that `init` guesses passes offline in under 60s on the seeded version.
5. A `Dockerfile` and `hedwig.requests.json` with ≥3 requests. Replaying the recorded requests on two builds of the same code shows zero diffs.
6. Access logs are written to `<svc>/logs/access.log`.

**Estate:**

7. `cd bank && hedwig init` detects exactly the 4 or 5 services with correct languages. After editing tier/allow:
   - transaction: critical, `[open_fix_pr, auto_merge_if_verified, rollback]`
   - account: high, `[open_fix_pr]`
   - support: medium, `[open_fix_pr]`
   - notifications: low, `[open_fix_pr, auto_merge_if_verified, takedown]`
8. `docker compose up` starts all services, the gateway and the tablet page. `make demo-reset` restores the seeded state.
9. The tablet page has a tile per service. Only the failing service's tile greys out.
10. Each service is deployed on Render as a Docker web service, always-on, with a health check path.

**Expected Hedwig outcomes:** a pytest e2e file plus a live run.

| Check | Expected |
|---|---|
| `hedwig scan bank/ --json` | All seeded CVEs found, each with reasoning |
| PR adding a vulnerable dependency, merged over the bot's red check | PM emailed the PDF, fix PR opened, verified fix merged into local main, that service rebuilt and active |
| account finding | Bot PR, `hedwig:needs-review`, not merged |
| PR adding vulnerable phpmailer to support | Red check. Admin merge → PDF emailed to PM → fix PR |
| `simulate-attack notifications --compromise` | Evidence 4 → notifications suspended, only the offers tile greys out |
| `hedwig dash` | transaction patched, notifications asleep, account/support awaiting human |


