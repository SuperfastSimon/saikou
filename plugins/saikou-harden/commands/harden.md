---
description: Harden a file against a threat model, verify the result with saikou, and write only after your approval
argument-hint: <path> [threats, e.g. injection,path_traversal]
---

Use the `code-hardener` subagent to harden: $ARGUMENTS

Follow its full workflow: interview for the threat model (skip what the arguments
already answer), harden, verify the output with `saikou verify` (or the manual
checks if `saikou` is not installed), present findings with their provenance and
the deferred defects, and write nothing until I approve the exact diff.
