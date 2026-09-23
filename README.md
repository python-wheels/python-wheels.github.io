# python-wheels.github.io

This repo is just the landing page and [PEP 503](https://peps.python.org/pep-0503/)
simple package index for **python-wheels** — it exists to give
`--extra-index-url` a short, native `.io` URL to point at. There's no code
here beyond `index.html` and the generated `simple/` index.

If you're looking for the actual project, you probably want one of these:

- **[python-wheels/python-wheels](https://github.com/python-wheels/python-wheels)**
  — the `python-wheels` CLI. Wraps `pip install`, resolves the right wheel
  for your platform, and verifies its build + upstream-source attestations
  before installing. *(In progress.)*
- **[patrickryankenneth/python-wheels-builds](https://github.com/patrickryankenneth/python-wheels-builds)**
  — where wheels actually get built. CI checks out a pinned upstream commit,
  builds it unmodified, and attaches Sigstore-signed attestations proving
  what was built and where it came from. This is also where to look at the
  build workflow itself, or file an issue about a specific package/wheel.

## What lives here

```
index.html      human-readable landing page (python-wheels.github.io)
simple/         PEP 503 index that pip reads via --extra-index-url
```

The `simple/` index is regenerated from releases published in
`python-wheels-builds` — it isn't edited by hand and won't explain *how* a
wheel was verified. For that, see `python-wheels-builds`.

## Using it

```bash
pip install --extra-index-url https://python-wheels.github.io/simple/ <package>
```

Or, once the CLI is out:

```bash
python-wheels install <package>
```
