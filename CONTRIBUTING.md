# Contributing to nftgeo

Contributions are welcome, especially focused bug reports, test cases, docs
fixes, and small pull requests that are easy to review.

## Ground rules

- Keep production secrets, private server names, SSH details, and API keys out
  of commits, issues, logs, screenshots, and test fixtures.
- For security-sensitive issues, use [SECURITY.md](SECURITY.md) instead of a
  public issue.
- Prefer small PRs with one clear behavior change.
- Match the existing shell style and Go style.
- Add or update tests when behavior changes.

## Development setup

Requirements:

- Go, matching the version in `go.mod` or newer.
- POSIX shell tools.
- `nftables` for optional real `nft -c` validation.
- `shellcheck` for linting shell scripts.
- `nfpm` only if you build packages.

Basic workflow:

```sh
git clone https://github.com/dzaczek/nftgeo.git
cd nftgeo
make test
make lint
```

## Test commands

```sh
go test ./ui/
sh tests/render/run.sh
sh tests/migrate/run.sh
make test
make lint
```

Optional checks:

```sh
sudo sh tests/render/nft-check.sh
make build
make package
```

`nft-check.sh` needs Linux with `nft` available. `make package` needs `nfpm`.

## Render test fixtures

Most engine behavior is covered by fixtures in `tests/render/cases/`.

Each case may contain:

- `rules.conf` - required input policy.
- `assert` - required assertions.
- `config` - optional config overrides.
- `groups.d/*.conf` - optional object definitions.
- `whitelist.conf`, `whitelist-hosts.conf`, `ingress.conf`, `ingress.d/*.conf`
  - optional related inputs.

Assertion prefixes:

```text
+ text   generated output must contain text
- text   generated output must not contain text
! text   render is expected to fail and stderr must contain text
~ text   render succeeds and stderr must contain warning text
```

Run fixtures with:

```sh
sh tests/render/run.sh
```

## Pull request checklist

Before opening a PR:

- Run `make test`.
- Run `make lint` when touching shell or Go code.
- Add a render fixture or Go test for changed behavior.
- Update docs when user-facing syntax, config, CLI output, or safety behavior
  changes.
- Remove local hostnames, IPs, tokens, and debug-only files.

In the PR description, include:

- What changed.
- Why it changed.
- How it was tested.
- Any compatibility or migration notes.

## Documentation

Keep `README.md` short and introductory. Put detailed behavior in
`docs/REFERENCE.md`, quick command snippets in `CHEATSHEET.md`, testing
instructions in `TESTING.md`, and service examples under `examples/`.
