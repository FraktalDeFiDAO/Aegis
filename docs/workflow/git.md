# Git and release workflow

The default branch is `master`. Work on a named feature/fix/release branch, fetch
origin before comparing, and open a pull request into master. Preserve unrelated
work in a separate commit or checkout; do not reset, clean, force-push, or rewrite
shared history as routine cleanup.

Before pushing, inspect the staged diff, run `git diff --cached --check`, and run
CI-equivalent build, test and vet commands. Connector releases also need the
isolated Chromium integration suite and extension ZIP verification documented in
[the store checklist](../chrome-web-store/README.md). Generated ZIPs, binaries,
Python caches, and local graph output stay out of source control.

Push with `git push -u origin BRANCH`, verify the remote SHA, and link a PR.
Review CI and scope before merging. Configure required reviews and CI checks for
master in GitHub settings. This document does not itself enforce protection.

Keep the package manifest version, content-script guard, integration expectation,
and release notes aligned. Tag and publish only the reviewed commit after public
release gates pass. Upload ZIPs/checksums as release assets; do not treat an
unreviewed candidate artifact as a public release.
