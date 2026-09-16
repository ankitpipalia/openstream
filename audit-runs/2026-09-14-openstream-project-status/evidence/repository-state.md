# Repository and GitHub state evidence

Captured 2026-09-14 (Asia/Kolkata).

```text
branch: main
HEAD: cac3b2fd363da00417a79da682bcc1f0299cdb87
origin/main: cac3b2fd363da00417a79da682bcc1f0299cdb87
merge-base(HEAD, origin/main): cac3b2fd363da00417a79da682bcc1f0299cdb87
working tree: clean (before audit artifacts were created)
tags: none
GitHub releases: none
open pull requests: 0
latest merged PR: #18
post-merge main workflow: 34816872196, success, 27/27 jobs
required branch check: CI gate (strict)
```

The stale local and remote branch `perf/latency-instrumentation` points to
`f81e19d5449b18775b2050aa8262329129aa051d`. It is not an ancestor of the
squash merge, but its tree is byte-for-byte identical to `main` at `cac3b2f`:

```text
git diff --quiet f81e19d cac3b2f  # exit 0
tree(f81e19d) = 9d598b75d7bbe0817bb0d0456f9afc23670d8c2b
tree(cac3b2f) = 9d598b75d7bbe0817bb0d0456f9afc23670d8c2b
```

Repository scale at the audited SHA:

```text
tracked files: 685
Rust source files: 216
Rust lines under engine/lowlat/crates: 158,020
Cargo workspace packages: 33
```

Commands used included `git status --porcelain=v1 -b`, `git rev-parse`,
`git merge-base`, `git branch -vv`, `git ls-remote --tags`, `gh pr list`,
`gh run view`, and the GitHub branch-protection API.
