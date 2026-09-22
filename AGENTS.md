# Repository instructions

## Formatting before commit

- Format all code before committing it, using the formatter appropriate to its
  language: `clang-format` for C and C++, `rustfmt` for Rust, and an established
  language-specific formatter for other languages.
- Use the repository's formatter configuration when one exists. Verify that
  every code file included in a commit passes its formatter's check mode before
  staging and committing.
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
