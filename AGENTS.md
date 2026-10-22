# Repository instructions

## Formatting before commit

- Format all code before committing it, using the formatter appropriate to its
  language: `clang-format` for C and C++, `rustfmt` for Rust, and an established
  language-specific formatter for other languages.
- Use the repository's formatter configuration when one exists. Verify that
  every code file included in a commit passes its formatter's check mode before
  staging and committing.
- Format Makefiles with `mbake` 1.4.6 using `.bake.toml`.
- Keep repository-wide formatting changes separate from functional changes.
  Make formatting-only changes in atomic commits, one language per commit.
- Preserve historical evidence artifacts and their recorded source hashes;
  formatting a source file does not rewrite evidence from earlier revisions.

## Commit workflow

- Stage each completed semantic changeset with `git add file1 file2 ...` using
  explicit file names.
- Commit it with `red -m --staged --run file1 file2 ...` using the same file list,
  verify the resulting commit, and push it.
- After every commit, run `make install -j 20` to build and install the plugin.
  Verify installation before reporting the changeset complete.
- Keep reported paths repository-relative; do not include personal absolute
  paths in committed files, tool output, or user-facing messages.

## Sources and references

This repository is public. Everything committed here (code, comments, tests,
docs, commit messages) may cite only public sources: released IDA versions,
the SDK headers and documentation shipped with them, and behaviour you can
observe by running a released build.

Other repositories and source trees on this machine are not public sources,
even when you read them to understand a problem. What you learn there may guide
a fix, but it must not appear in this repository. In particular, never write:

- commit hashes, branch names or commit dates from another project;
- names of beta, release-candidate, nightly or internal builds;
- function, file, variable or enumerator names, assertion or error numbers,
  or message strings that do not appear in a released SDK header or a
  released build;
- explanations of why another product behaves as it does, beyond what its
  observable behaviour shows.

State the observable behaviour and the release it applies to:

- Wrong: `// upstream commit 1a2b3c4 (2025-03-14, first in 4.1 beta 2) renumbered
  FOO_RETRY because its dispatcher table ...`
- Right: `// 4.1 and later use a different FOO_RETRY value; ask the loaded
  library which one it expects.`

Tests follow the same rule: use version strings and messages a released build
produces, or neutral placeholders.

Before committing, read the staged diff for anything on the list above.
`git diff --cached | grep -inE 'commit [0-9a-f]{7,}|beta|nightly|[^a-z]rc[0-9]'`
catches the most common slips; it does not replace reading the diff.
