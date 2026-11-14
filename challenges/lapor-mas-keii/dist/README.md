# Lapor Mas Keii — portal tugas kampus

A campus assignment portal. A student uploads a *tugas*; before anything else
its text is screened by the dosen's on-box **AI-detector**. A tugas that reads
as genuine human writing is admitted for full handling — attaching the berkas,
revising it, viewing, grading — while a tugas the detector rates as AI-written
is **quarantined** and grade-docked, handled only minimally. Students can also
appeal ("ini tulisan saya, bukan AI") by resubmitting.

## Port & access

- **24000** — the service (line-oriented text protocol over TCP)
- **24022** — SSH (user `ctfuser`, password from the Services panel)

## Protocol

One command per line. Two commands carry a length-prefixed payload: the `<len>`
bytes follow immediately after the command's newline.

| command | meaning |
| --- | --- |
| `SUBMIT <student> <words> <late> <draft> <len>` + `<len>` bytes | upload a tugas; the detector screens the text once |
| `ATTACH <id> <len>` + `<len>` bytes | attach/replace the tugas's uploaded berkas (admitted tugas only) |
| `REVISE <id> <offset> <bit>` | set one correction/annotation bit of the berkas (admitted tugas only) |
| `VIEW <id>` | print the tugas header and its berkas |
| `SCORE <id>` | print the tugas's numeric detector telemetry |
| `GRADE <id>` | compute the final nilai (with AI-docking) |
| `RETRACT <id>` | withdraw a tugas and release its berkas |
| `ROSTER` | list the live tugas |
| `QUIT` | close the session |

## Source & patching

- `src/` — the C service (`lmk.c`, `detector.c`), owned by `ctfuser`. Edit it,
  then restart the service from the panel; the entrypoint rebuilds it with `make`
  before launching. Mitigation flags in the `Makefile` are locked — leave them.
- `guard/guard.conf` — the detector's threshold and keyword rules, editable.
  Tune these if AI-written tugas are getting through; over-tightening will
  quarantine genuine tugas and cost you SLA.
- `guard/detector.bin` — the pinned detector weights, read-only.

The service runs as the unprivileged `svc` account, so a bug in it does not hand
out a shell as the account that edits and restarts it.
