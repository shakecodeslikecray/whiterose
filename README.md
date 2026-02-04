# whiterose

[![npm version](https://img.shields.io/npm/v/@shakecodeslikecray/whiterose.svg)](https://www.npmjs.com/package/@shakecodeslikecray/whiterose)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm%20NC%201.0-blue.svg)](LICENSE)

> "I've been staring at your code for a long time."

AI-powered bug hunter that uses your existing LLM subscription. No API keys needed. No extra costs.

```
██╗    ██╗██╗  ██╗██╗████████╗███████╗██████╗  ██████╗ ███████╗███████╗
██║    ██║██║  ██║██║╚══██╔══╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝
██║ █╗ ██║███████║██║   ██║   █████╗  ██████╔╝██║   ██║███████╗█████╗
██║███╗██║██╔══██║██║   ██║   ██╔══╝  ██╔══██╗██║   ██║╚════██║██╔══╝
╚███╔███╔╝██║  ██║██║   ██║   ███████╗██║  ██║╚██████╔╝███████║███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
```

---

## Table of Contents

- [Why whiterose?](#why-whiterose)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Architecture](#architecture)
  - [Three-Layer Architecture](#three-layer-architecture)
  - [19-Pass Pipeline](#19-pass-pipeline)
  - [LSP-Compliant Provider Abstraction](#lsp-compliant-provider-abstraction)
  - [Static Analysis Integration](#static-analysis-integration)
- [Configuration](#configuration)
- [Bug Categories](#bug-categories)
- [Output Formats](#output-formats)
- [Contributing](#contributing)
- [License](#license)

---

## Why whiterose?

You're already paying for Claude Code Max, Cursor, Codex, or similar AI coding tools. Why pay again for bug detection APIs?

whiterose piggybacks on your existing subscription to find bugs in your code. **Zero additional cost.**

| Feature | whiterose | Traditional SAST |
|---------|-----------|------------------|
| Cost | $0 (uses existing subscription) | $100-500/mo |
| Setup | `npm install -g` | Complex integrations |
| False positives | Low (LLM understands context) | High (pattern matching) |
| Fix generation | Yes (agentic) | No |
| Provider lock-in | None (works with any LLM CLI) | Vendor-specific |

---

## Installation

```bash
npm install -g @shakecodeslikecray/whiterose
```

### Prerequisites

You need at least one LLM CLI tool installed:

| Provider | Installation | Status |
|----------|-------------|--------|
| Claude Code | `npm install -g @anthropic-ai/claude-code` | ✅ Ready |
| Codex | `npm install -g @openai/codex` | ✅ Ready |
| Gemini | `npm install -g @google/gemini-cli` | ✅ Ready |
| Aider | `pip install aider-chat` | ✅ Ready |

---

## Quick Start

```bash
# Interactive menu (recommended)
whiterose

# Or use commands directly:
whiterose init              # Initialize (explores codebase, generates understanding)
whiterose scan              # Scan for bugs (19-pass pipeline)
whiterose scan --quick      # Quick scan (single pass, for pre-commit)
whiterose fix               # Fix bugs interactively
```

**Example output:**

```
┌  whiterose - thorough scan
│
◇  Found 64 files to scan
◇  Static analysis: 37 signals found

════ CORE SCANNER (PIPELINE MODE) ════
  Provider: claude-code
  Passes: 19 (9 unit → 5 integration → 5 E2E)
  Findings flow: Unit → Integration → E2E

════ PHASE 1: UNIT ANALYSIS ════
  Looking for: injection, null refs, auth bypass, etc.
  [Batch 1/2] injection, auth-bypass, null-safety, type-safety, resource-leaks
    ✓ injection: 2 bugs
    ✓ auth-bypass: 0 bugs
    ✓ null-safety: 1 bugs
    ...

════ PHASE 2: INTEGRATION ANALYSIS ════
  Building on 5 unit findings
  Looking for: auth flows, data flows, trust boundaries
    ✓ auth-flow-trace: 1 bugs
    ...

════ PHASE 3: E2E ANALYSIS ════
  Building on 5 unit + 2 integration findings
  Looking for: attack chains, privilege escalation
    ✓ attack-chain-analysis: 1 bugs
    ...

════ SCAN COMPLETE ════
  Duration: 4m 32s
  Unit: 5 → Integration: 2 → E2E: 1
  Final bugs: 7
```

---

## Commands

### `whiterose init`

First-time setup. Explores your codebase and generates understanding.

```bash
whiterose init
```

Creates `.whiterose/` directory with:
- `config.yml` - Configuration
- `intent.md` - Behavioral contracts (editable)
- `cache/understanding.json` - AI-generated codebase understanding

### `whiterose scan`

Find bugs using the 19-pass pipeline.

```bash
whiterose scan                    # Incremental scan (changed files only)
whiterose scan --full             # Full scan (all files)
whiterose scan --quick            # Quick scan (single pass, fast)
whiterose scan --provider codex   # Use specific provider
whiterose scan --json             # JSON output
whiterose scan --ci               # CI mode (exit 1 if bugs found)
whiterose scan src/api/           # Scan specific path
```

### `whiterose fix`

Interactive TUI for reviewing and fixing bugs.

```bash
whiterose fix                     # Interactive dashboard
whiterose fix WR-001              # Fix specific bug by ID
whiterose fix --dry-run           # Preview without applying
whiterose fix --provider claude-code  # Use specific provider

# External bug sources:
whiterose fix --sarif ./semgrep.sarif      # Import from SARIF
whiterose fix --github https://github.com/owner/repo/issues/123
whiterose fix --describe                    # Manually describe a bug
```

**Agentic Fix:** whiterose uses an agentic approach - the LLM reads the code, explores context, and applies fixes directly. It can also detect false positives during fix and notify you.

### `whiterose refresh`

Rebuild codebase understanding from scratch.

### `whiterose status`

Show current status (provider, cache, last scan).

---

## Architecture

This section explains how whiterose works internally. **Critical reading for contributors.**

### Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LAYER 0: UNDERSTANDING                           │
│                         (whiterose init)                            │
│                                                                     │
│  Input:                           Output:                           │
│  - README.md, package.json        - .whiterose/intent.md            │
│  - CONTRIBUTING.md                - .whiterose/cache/understanding  │
│  - Existing documentation         - Project type, framework, etc.   │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    LAYER 1: BUG FINDING                             │
│                        (whiterose scan)                             │
│                                                                     │
│  1. Load understanding from Layer 0                                 │
│  2. Run static analysis (tsc, eslint)                               │
│  3. Run 19-pass LLM pipeline (Unit → Integration → E2E)             │
│  4. Deduplicate and merge findings                                  │
│  5. Output reports (SARIF, Markdown, JSON)                          │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    LAYER 2: BUG FIXING                              │
│                         (whiterose fix)                             │
│                                                                     │
│  1. Load bugs from scan results (or external sources)               │
│  2. Interactive TUI for review                                      │
│  3. Agentic fix (LLM explores and fixes)                            │
│  4. False positive detection during fix                             │
│  5. Commit changes                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 19-Pass Pipeline

whiterose runs **19 specialized passes** organized into 3 phases, with findings flowing through:

```
Static Analysis (tsc/eslint)
           │
           ▼
     staticResults ─────────────────────────────────────┐
           │                                            │
           ▼                                            │
════ PHASE 1: UNIT ANALYSIS (9 passes) ════            │
│                                                      │
│  Each pass focuses on ONE bug category:              │
│  1. injection      - SQL, XSS, command injection     │
│  2. auth-bypass    - Missing/broken auth checks      │
│  3. null-safety    - Null/undefined dereference      │
│  4. type-safety    - Type coercion bugs              │
│  5. resource-leaks - Unclosed handles, listeners     │
│  6. async-issues   - Missing await, race conditions  │
│  7. data-validation - Input validation gaps          │
│  8. secrets-exposure - Hardcoded secrets, leaks      │
│  9. logic-errors   - Off-by-one, wrong operators     │
│                                                      │
│  Runs in batches of 5 (parallel within batch)        │
└──────────────────────────────────────────────────────┘
           │
           ▼
      unitFindings ─────────────────────────────┐
           │                                    │
           ▼                                    ▼
════ PHASE 2: INTEGRATION ANALYSIS (5 passes) ════
│  Input: staticResults + unitFindings         │
│                                              │
│  Prompt includes previous findings:          │
│  "## PREVIOUS FINDINGS TO BUILD ON           │
│   - [high] SQL injection at api.ts:42        │
│   - [medium] Missing auth at routes.ts:15"   │
│                                              │
│  Passes:                                     │
│  1. auth-flow-trace      - Auth across files │
│  2. data-flow-trace      - Data propagation  │
│  3. validation-boundary  - Trust boundaries  │
│  4. error-propagation    - Error handling    │
│  5. trust-boundary-trace - Security bounds   │
└──────────────────────────────────────────────┘
           │
           ▼
   integrationFindings ─────────────────┐
           │                            │
           ▼                            ▼
════ PHASE 3: E2E ANALYSIS (5 passes) ════
│  Input: staticResults + unitFindings │
│         + integrationFindings        │
│                                      │
│  Builds attack chains from ALL       │
│  previous findings.                  │
│                                      │
│  Passes:                             │
│  1. attack-chain-analysis            │
│  2. privilege-escalation-trace       │
│  3. session-lifecycle-trace          │
│  4. user-journey-simulation          │
│  5. api-contract-verification        │
└──────────────────────────────────────┘
           │
           ▼
════ POST-PROCESSING ════
│  1. Combine all findings             │
│  2. Deduplicate (file:line:category) │
│  3. Merge similar (within 5 lines)   │
└──────────────────────────────────────┘
           │
           ▼
      Final Bugs
```

### LSP-Compliant Provider Abstraction

whiterose follows the **Liskov Substitution Principle** - all providers are interchangeable and get the same 19-pass scanning.

```
┌─────────────────────────────────────────────────────────────────┐
│                      CoreScanner                                 │
│  src/core/scanner.ts                                            │
│  ─────────────────────────────────────────────────────────────  │
│  • 19-pass pipeline logic                                       │
│  • Batching (5 parallel, 2s delay)                              │
│  • Phase dependencies (Unit → Integration → E2E)                │
│  • Deduplication & merging                                      │
│  • Progress callbacks                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ executor.runPrompt(prompt)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│               PromptExecutor (interface)                         │
│  src/core/scanner.ts                                            │
│  ─────────────────────────────────────────────────────────────  │
│  interface PromptExecutor {                                     │
│    name: string;                                                │
│    isAvailable(): Promise<boolean>;                             │
│    runPrompt(prompt: string, options: PromptOptions):           │
│      Promise<PromptResult>;                                     │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ claude   │  │  codex   │  │  gemini  │  │  aider   │
   │  -code   │  │          │  │          │  │          │
   └──────────┘  └──────────┘  └──────────┘  └──────────┘
   executors/    executors/    executors/    executors/
```

**Adding a new provider is trivial** - just implement the `PromptExecutor` interface (~30 lines).

### Static Analysis Integration

Static analysis runs **first**, deterministically, before any LLM passes:

```typescript
// In scan.ts
staticResults = await runStaticAnalysis(cwd, filesToScan, config);

// Passed to CoreScanner
const bugs = await scanner.scan({
  files: filesToScan,
  understanding,
  staticResults,  // ← Every pass sees this
});
```

Each LLM pass receives static analysis signals in its prompt:

```
## STATIC ANALYSIS SIGNALS (from tsc/eslint)
- typescript: src/api.ts:42 - TS2532: Object is possibly 'undefined'
- eslint: src/db.ts:15 - @typescript-eslint/no-explicit-any

NOTE: Static tools already verified control flow. Don't report issues they would catch.
```

This reduces false positives - the LLM knows what tsc/eslint already flagged.

---

## Configuration

`.whiterose/config.yml`:

```yaml
version: "1"
provider: claude-code  # or codex, gemini, aider

include:
  - "**/*.ts"
  - "**/*.tsx"
  - "**/*.js"
  - "**/*.jsx"

exclude:
  - node_modules
  - dist
  - "**/*.test.*"
  - "**/*.spec.*"

priorities:
  src/api/checkout.ts: critical
  src/auth/: high

categories:
  - injection
  - auth-bypass
  - null-reference
  - logic-error
  - async-issue
  - resource-leak
  - data-validation
  - secrets-exposure

minConfidence: low  # low, medium, high

staticAnalysis:
  typescript: true
  eslint: true

output:
  sarif: true
  markdown: true
  sarifPath: .whiterose/reports
  markdownPath: BUGS.md
```

---

## Bug Categories

whiterose looks for bugs in these categories:

| Category | Description | Example |
|----------|-------------|---------|
| `injection` | SQL, XSS, command injection | `db.query("SELECT * FROM users WHERE id=" + userId)` |
| `auth-bypass` | Missing/broken authentication | Route handler without auth middleware |
| `null-reference` | Null/undefined dereference | `user.profile.name` when `profile` might be null |
| `logic-error` | Off-by-one, wrong operators | `i <= arr.length` instead of `i < arr.length` |
| `async-issue` | Missing await, race conditions | `const data = fetchData(); use(data);` |
| `resource-leak` | Unclosed handles, listeners | `db.connect()` without `db.close()` |
| `data-validation` | Input validation gaps | Missing sanitization on user input |
| `secrets-exposure` | Hardcoded secrets | `const API_KEY = "sk-..."` |
| `type-coercion` | Loose equality bugs | `if (value == null)` when 0 is valid |
| `boundary-error` | Edge case handling | Empty array, zero values |
| `concurrency` | Thread safety issues | Shared state without locks |
| `intent-violation` | Violates documented behavior | Code contradicts README/docs |

---

## Output Formats

### SARIF

Standard format for static analysis tools. Works with:
- VS Code (SARIF Viewer extension)
- GitHub Code Scanning
- Azure DevOps

### Markdown

Two formats:
- `bugs.md` - Technical (for developers)
- `bugs-human.md` - Tester-friendly (for QA)

### JSON

Full bug data with code paths, evidence, and confidence scores.

---

## Contributing

### Project Structure

```
whiterose/
├── src/
│   ├── cli/
│   │   ├── index.ts              # CLI entry point
│   │   └── commands/
│   │       ├── init.ts           # whiterose init
│   │       ├── scan.ts           # whiterose scan
│   │       └── fix.ts            # whiterose fix
│   │
│   ├── core/
│   │   ├── scanner.ts            # CoreScanner + PromptExecutor interface
│   │   ├── multipass-scanner.ts  # Pass configurations (SCAN_PASSES)
│   │   ├── flow-analyzer.ts      # Flow pass configurations (FLOW_PASSES)
│   │   ├── fixer.ts              # Agentic fix logic
│   │   ├── config.ts             # Config loading
│   │   └── utils.ts              # Utilities
│   │
│   ├── providers/
│   │   ├── executors/            # LSP-compliant provider implementations
│   │   │   ├── index.ts          # getExecutor(), getAvailableExecutors()
│   │   │   ├── claude-code.ts    # ClaudeCodeExecutor
│   │   │   ├── codex.ts          # CodexExecutor
│   │   │   ├── gemini.ts         # GeminiExecutor
│   │   │   └── aider.ts          # AiderExecutor
│   │   │
│   │   ├── prompts/
│   │   │   ├── multipass-prompts.ts    # Unit pass prompts
│   │   │   ├── flow-analysis-prompts.ts # Integration/E2E prompts
│   │   │   └── adversarial.ts          # Validation prompts
│   │   │
│   │   └── detect.ts             # Provider detection
│   │
│   ├── analysis/
│   │   └── static.ts             # tsc/eslint integration
│   │
│   ├── tui/
│   │   ├── App.tsx               # Main TUI app
│   │   └── screens/              # TUI screens
│   │
│   ├── output/
│   │   ├── sarif.ts              # SARIF output
│   │   ├── markdown.ts           # Technical markdown
│   │   └── human-readable.ts     # Tester-friendly markdown
│   │
│   └── types.ts                  # TypeScript types (Zod schemas)
│
├── tsup.config.ts                # Build config
└── package.json
```

### Key Files for Contributors

| File | Purpose |
|------|---------|
| `src/core/scanner.ts` | **Start here.** CoreScanner orchestrates everything. |
| `src/core/multipass-scanner.ts` | Pass configurations for unit analysis |
| `src/core/flow-analyzer.ts` | Pass configurations for integration/E2E |
| `src/providers/executors/*.ts` | Provider implementations (simple!) |
| `src/providers/prompts/*.ts` | Prompt templates |

### Adding a New Provider

1. Create `src/providers/executors/your-provider.ts`:

```typescript
import { PromptExecutor, PromptOptions, PromptResult } from '../../core/scanner.js';

export class YourProviderExecutor implements PromptExecutor {
  name = 'your-provider';

  async isAvailable(): Promise<boolean> {
    // Check if CLI tool is installed
  }

  async runPrompt(prompt: string, options: PromptOptions): Promise<PromptResult> {
    // Run: your-cli -p "prompt"
    // Return: { output: stdout, error: stderr }
  }
}
```

2. Register in `src/providers/executors/index.ts`
3. Add to `ProviderType` in `src/types.ts`
4. Add detection in `src/providers/detect.ts`

### Adding a New Pass

1. Add pass config to `SCAN_PASSES` in `src/core/multipass-scanner.ts` (for unit passes) or `FLOW_PASSES` in `src/core/flow-analyzer.ts` (for integration/E2E)

2. Add to pipeline in `src/providers/prompts/flow-analysis-prompts.ts`:

```typescript
export function getFullAnalysisPipeline() {
  return [
    { phase: 'Unit Analysis', passes: [..., 'your-new-pass'] },
    // ...
  ];
}
```

### Building

```bash
npm run build    # Build
npm run dev      # Watch mode
npm test         # Run tests
```

---

## Philosophy

- **SRP**: whiterose finds bugs. It doesn't write tests, lint code, or format files.
- **Leverage, Don't Reinvent**: Uses existing AI agents (Claude Code, Codex) rather than building a custom agent loop.
- **LSP-Compliant**: All providers are interchangeable. Scanning logic lives in ONE place.
- **Transparency**: Shows exactly what's happening in real-time.
- **Grounded**: Every bug must have evidence and a code path trace.
- **Zero Cost**: Uses your existing LLM subscription.

---

## License

PolyForm Noncommercial 1.0.0

This software is free for non-commercial use. See [LICENSE](LICENSE) for details.

---

## Credits

Named after the [Mr. Robot](https://en.wikipedia.org/wiki/Mr._Robot) character who sees everything and orchestrates from the shadows.

---

**Copyright (c) 2024-2025 shakecodeslikecray (https://github.com/shakecodeslikecray)**
