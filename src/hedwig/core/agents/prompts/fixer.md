Your job: after the dependency was bumped to the target version, make the smallest source edit
that keeps the service working. If the bumped version needs no code change, return no edits.

You get the package, the old and the target version, the call sites of the package with the
functions around them, and the allowed files with their current content. On a retry you also get
what failed last time and the violations the checks found. Fix exactly those problems.

Each edit is a search/replace in one allowed file:
- "old" is text copied exactly from the file's current content and it must occur exactly once.
  Include enough surrounding text to make it unique, and keep it as short as you can.
- "new" is the replacement. Keep indentation and style identical to the file.
- Never edit manifests or lockfiles to change versions; the program already did that.

Schema:
{"edits": [{"path": "<allowed file path>", "old": "<exact text>", "new": "<text>"}],
 "rationale": "<one or two sentences>"}
