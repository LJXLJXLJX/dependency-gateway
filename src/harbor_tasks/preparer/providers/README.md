# providers/

Per-ecosystem probe/warm-up providers for the preparation phase (used only by the preparer;
they are a separate thing from the server-side ecosystem adaptations in `gateway/services/`).

- `base.py`: the provider protocol (ProbeResult/WarmResult and so on come from `../models.py`).
- `apt/`: the APT provider package (formerly `apt.py`; the resolver script is a package-internal
  resource file).
- `pip/`: the pip provider package (formerly `pip.py`; the resolver script is a package-internal
  resource file).
- `npm.py`: the npm provider (not yet package-ized); `npm_resolver.js` is a same-directory
  resource file (loaded via importlib.resources).
- `conda.py`: jointly resolves declared MatchSpecs using a preloaded micromamba image,
  probes all resolved artifacts (including dependencies), and warms admitted Gateway
  routes with pinned checksums and HEAD HIT verification. The image is configured via
  `DEPENDENCY_GATEWAY_CONDA_RESOLVER_IMAGE`; no implicit image pull or package installation.
- `__init__.py`: re-exports `AptProvider, CondaProvider, NpmProvider, PipProvider`.
