# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**stui** is a terminal UI for browsing and downloading files from AWS S3 with full SSO support. Written in Go using the Bubbletea (Charm) TUI framework and AWS SDK v2.

## Build & Run Commands

```bash
# Build
go build -o stui ./cmd/stui

# Install from source
go install github.com/natevick/stui/cmd/stui@latest

# Run
./stui                                    # interactive profile picker
./stui --profile my-profile               # specific profile
./stui --profile my-profile --bucket foo  # jump to bucket
./stui --demo                             # mock data, no AWS needed

# Test
go test ./...                             # all tests
go test ./internal/security               # single package
go test ./internal/bookmarks              # single package

# Cross-compile (outputs to dist/)
GOOS=darwin GOARCH=arm64 go build -o dist/stui-darwin-arm64 ./cmd/stui
```

There is no Makefile, linter config, or CI pipeline. Tests currently only exist for `internal/security` and `internal/bookmarks`.

## Architecture

The app follows Bubbletea's **Model → Update → View** pattern.

### Root TUI (`internal/tui/`)

- `model.go` — Root `Model` struct, `New()` constructor, `Init()` command. Holds all sub-view models, AWS client, download manager, bookmark store.
- `update.go` — Central message dispatcher. Routes messages to the active view and handles cross-view transitions.
- `view.go` — Renders the active view with header tabs, content area, and status bar.
- `messages.go` — All message types used for inter-component communication.
- `keys.go` — Key bindings (`KeyMap`). `styles.go` — Lipgloss styles and color palette.

### Views (`internal/views/`)

Each view is a self-contained Bubbletea component with its own `Model`, `Update`, and `View`:

| View | Purpose |
|------|---------|
| `profiles` | AWS profile picker (reads ~/.aws/config) |
| `buckets` | S3 bucket list |
| `browser` | File/folder browser with multi-select |
| `download` | Download progress display |
| `bookmarksview` | Saved S3 locations |

Views signal intentions to the root model via an **action pattern**: the root calls `view.ConsumeAction()` which returns an action enum plus associated data. This keeps views decoupled from each other.

### Core Packages (`internal/`)

- **`aws/`** — AWS client init, SSO/profile support, S3 operations (list buckets, list objects, download).
- **`download/`** — Download manager with worker pool (5 workers), supports single file, prefix, multi-select, and sync (MD5 comparison). Progress via callbacks.
- **`bookmarks/`** — JSON-based persistent storage at `~/.config/stui/bookmarks.json`. UUID-keyed entries.
- **`security/`** — Input validation (regex-based), path traversal protection (`SafePath`), error sanitization (strips AWS account IDs, ARNs, access keys from error messages).

### Entry Point

`cmd/stui/main.go` — Parses flags, validates inputs via security package, creates root TUI model, runs Bubbletea program with alt-screen and mouse support. Version injected via `ldflags`.

## Key Patterns

- **Message-based communication**: All async operations (AWS calls, downloads) return `tea.Cmd` functions that produce typed messages. No direct state mutation across boundaries.
- **Context cancellation**: Root model holds a `context.Context` for cancelling downloads and AWS calls.
- **Security-first file operations**: All download paths validated through `security.SafePath()`. Downloaded files get 0600 permissions, directories 0750, config files 0600.
- **Demo mode**: `--demo` flag populates mock data so the full UI can run without AWS credentials.
