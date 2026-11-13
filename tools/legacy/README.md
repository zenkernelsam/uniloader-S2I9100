# Historical I9100 experiments

These are the previously loose project-root `tools/` and `out/` scripts, retained
in the loader repository so every source and patch is recoverable in Git.
Original bytes and path inventory are archived under
`research/archive/maintenance-20261113/legacy-tools-original/` and
`legacy-code-relocation.json`.

This directory is historical source, not the current device workflow. Some old
scripts hard-code COM11, obsolete directory layouts or snapshot-specific addresses
and have superseded serial open/timeout handling. Read them for reference; use
`scripts/i9100/prepare-automation.py`, `odin-loop.py` and `forensic-session.py`
for current iteration. Read the project AGENTS.md and AUTOMATION-RUNBOOK.md first.

Old QEMU, USB and SD experiments have not been silently merged into the working
kernel. The original development branch is `i9100-original`; current work is
`i9100-neighbor-base`. No third I9100 repository is needed.
