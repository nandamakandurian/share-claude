# share-claude

A small CLI for moving a **Claude Code account credential** in an AES-256 encrypted ZIP. The archive contains only `claudeAiOauth`; it does not include Claude's connected-service (`mcpOAuth`) credentials, settings, projects, or chat history.

## Install

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/). On macOS, Xcode Command Line Tools must provide `swiftc` for Keychain access. On the sending and receiving machines, from this directory:

```sh
uv tool install .
```

For development, use `uv run share-claude ...` instead. The first macOS command compiles a small local Keychain helper and caches it under `~/.cache/share-claude/`.

## Commands

```sh
share-claude share -o claude-auth.zip
share-claude use claude-auth.zip
share-claude restore
```

`share` asks for a passcode of at least 16 characters twice and creates an AES-256 encrypted ZIP. It refuses to overwrite an existing archive. Give the recipient the archive and passcode through separate channels.

`use` asks for the archive passcode. If a Claude credential is already present or Claude reports an active login, it asks whether to replace it. Answering no leaves everything as it was. Answering yes saves the original credential before importing. A second import is refused until the backup is restored.

`restore` restores the original credential and removes its backup without asking for a passcode. On macOS, the original credential is backed up in Keychain under `share-claude-original-credentials`, with a marker at `~/.claude/.share-claude-backup.json`. On Linux, the backup is a mode-`0600` file at `~/.claude/.share-claude-backup.json` beside `.credentials.json`. Other entries in the current credential store, including MCP credentials, are preserved.

Close running Claude Code sessions before `use` or `restore`: a running session may refresh its OAuth token and overwrite the credential you just installed. Environment-based Claude authentication must be unset before either command. Custom `CLAUDE_CONFIG_DIR` is supported for file-based storage, but not for macOS Keychain storage.

The archive is a copy of a reusable credential. Removing the recipient from ZeroTier or deleting the archive later does not revoke a copy they already obtained. Revocation must happen at the Claude account or session level.

## Verify

```sh
uv run python -m unittest discover -s tests -v
```
