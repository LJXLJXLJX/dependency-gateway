# config/

Server-side source configuration directory.

- `sources.json`: the Dependency Gateway source manifest (10 ecosystems, 14 source kinds),
  defining each source's upstream address, ecosystem, kind, path validation and publish policy.
  Loaded by the server; changes must follow the review process in `docs/operator-guide.md`.
  Conda sources admit defaults (`main`/`r`) and conda-forge on `linux-64`/`noarch`, with
  TUNA direct as primary and a pinned official fallback through the configured proxy.

This directory may contain Git-ignored local override configs (such as `*.local.json`); real
credentials must not be committed.
