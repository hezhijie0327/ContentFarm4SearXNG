# AGENTS.md

ContentFarm4SearXNG is a Python-based tool that generates hostname rules for the SearXNG search engine, fetching content farm filter lists from various sources and generating categorized YAML rule files. See [README.md](README.md) for usage and configuration.

## HANDOVER.md

When a multi-step task is interrupted, write progress to `HANDOVER.md` so the next session can pick up where you left off. Include: what was done, what remains, key decisions made, and the next concrete step. Delete the file when the task is complete.

## Behavioral Guidelines

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

**Additional rules:**
- Be concise in output but thorough in reasoning.
- Do not re-read files you have already read.
- User instructions always override this file.
- Don't wrestle with indentation in the Edit tool — focus on logic, let the project's formatter fix formatting. Use `sed` or `python3` freely when the Edit tool struggles with whitespace.

## Git commit convention

Every commit subject starts with a type prefix — `feat` / `fix` / `chore` / `docs` / `revert` / `refactor` / `perf` / `test` / `build` — optionally scoped: `fix(toolbar): ...`. Subject: imperative, lowercase start, no trailing period, aim ≤ 72 chars; detail goes in the body after a blank line (why, not what); breaking changes take `!` before the colon or a `BREAKING CHANGE:` body footer. Never rewrite pushed history.

- Commit incrementally — one logical change per commit, after lint and tests pass. Present changes for review before committing.
- PRs: link the issue, summarize the change and verification (tests/benchmarks), and include config/log/pprof evidence for bug fixes.

### Co-Author Format

- Always add co-author information. If closing an issue in commit text, verify against `main` first: `gh issue view <issue-id>`.
- Only ONE co-author line is allowed. If multiple agents contributed, aggregate into ONE entry.

Format: `Co-authored-by: <AgentName> <Email>`

Valid examples (choose EXACTLY ONE):

```
Co-authored-by: ZCode <noreply@z.ai>
```

## Documentation format

Family-wide Markdown rules, shared verbatim across all ZJ projects:

- **Language**: AGENTS.md, AUDIT.md, DESIGN.md and other agent-facing docs are English; README.md is Chinese (human-facing). Keep literal UI strings and code identifiers verbatim.
- **AGENTS.md skeleton** — generic sections first, then project; omit sections that don't apply, keep the order:
  `# AGENTS.md` → 1–2 sentence intro (what the project is + key doc links) → Behavioral Guidelines → Git commit convention → Documentation format → Project → Commands → Architecture → Conventions (Gotchas as a subsection) → project-specific sections → Key Docs.
- **README.md skeleton**: `# <project>` → badge block → one-line positioning + stack + key links → 特性 → 快速开始 → 配置 / 用法 → 文档 → License (omit as needed).
- **README badges** (shields.io, after the title, in order): Version (only where a real version exists, linked to the repo's GitHub releases), License (Apache 2.0 with Commons Clause — every project), primary-language badge (Go / TypeScript / Bash / Python / Docker), Biome for TypeScript projects; pure data/config repos get License only. Version links use the real GitHub repo name.
- **Formatting**: ATX headings (`#`), never skip a level; code fences always carry a language tag (`bash`, `go`, `json`, `text` for trees); tables for structured reference; no decorative emoji in headings or bullets; bold for key terms only.

## Project

ContentFarm4SearXNG is a Python-based tool that generates hostname rules for SearXNG. It fetches content farm filter lists from configured sources, applies the manual rules in `custom/classify.txt`, and writes categorized YAML rule files to `dist/` for SearXNG's hostnames plugin.

## Commands

### Main Commands

```bash
# Install dependencies
pip install requests pyyaml

# Run the build (fetch, classify, generate all outputs)
python3 build.py

# Running tests
python3 -m unittest discover -s tests -p "test_*.py"  # If test directory exists
```

### Single Test Execution

```bash
# Run a specific test file
python3 -m unittest tests/test_specific_file.py

# Run a specific test method
python3 -m unittest tests.test_specific_file.TestClass.test_method
```

## Architecture

1. **Fetch**: `_prefetch_sources()` downloads all enabled sources in a thread pool; per-source retries keep the 30s timeout / 3 attempts / 1s backoff policy.
2. **Parse**: each source is parsed by format (uBlock, v2ray, plain domain, CSV); path-specific rules follow `specific_path_action` (default `smart`: remove → low_priority).
3. **Classify**: `custom/classify.txt` rules are indexed once (exact domains in a dict, `*.` wildcards in a suffix list) and override source defaults; skip only blocks the source default.
4. **Compress**: domains are sorted by TLD, grouped, and merged with common prefix/suffix factoring; each batch (≤256 domains) is rendered once and split only if it exceeds 65536 characters.
5. **Output**: `dist/` receives the six YAML files; `hostnames-config.yml` references the other five.

## Conventions

### Python

1. **Imports**:
   - Use absolute imports: `import os`, `from typing import Dict, List, Set`
   - Group imports in order: standard library, third-party, local
   - One import per line for better readability

2. **Formatting**:
   - Use 4 spaces for indentation (never tabs)
   - Maximum line length: 100 characters
   - Follow PEP 8 style guidelines

3. **Type Annotations**:
   - Always include type hints for function signatures
   - Use appropriate types from the `typing` module
   - Example: `def function_name(param: str) -> bool:`

4. **Naming Conventions**:
   - Classes: PascalCase (e.g., `SearXNGHostnamesGenerator`)
   - Functions/variables: snake_case (e.g., `extract_hostname_from_url`)
   - Constants: UPPER_SNAKE_CASE (e.g., `DEFAULT_TIMEOUT`)
   - Private methods: prefix with underscore (e.g., `_deep_merge`)

5. **Error Handling**:
   - Use specific exceptions when possible
   - Include meaningful error messages
   - Log errors appropriately using print statements (as seen in current code)

6. **Documentation**:
   - Use docstrings for all public methods and classes
   - Include Args, Returns, and Raises sections in docstrings
   - Use inline comments sparingly and only for complex logic

7. **Configuration**:
   - All configuration should be in YAML format
   - Use deep merge for configuration inheritance
   - Provide sensible defaults for all configuration options

### YAML Configuration

1. Use 2 spaces for indentation
2. Include comments explaining configuration sections
3. Group related settings under logical keys
4. Use arrays for lists of items

### File Organization

```text
ContentFarm4SearXNG/
├── build.py                       # Main build script
├── custom/classify.txt            # Manual classification rules (input)
├── dist/                          # Generated YAML rule files (output)
│   ├── hostnames-config.yml       # Main configuration
│   ├── high-priority-hosts.yml    # High priority domains
│   ├── low-priority-hosts.yml     # Low priority domains
│   ├── low-priority-hosts-all.yml # Low priority + remove union
│   ├── remove-hosts.yml           # Domains to remove
│   └── rewrite-hosts.yml          # Domain replacement rules
└── .github/workflows/main.yml     # CI/CD workflow
```

## Dependencies

- Python 3.8+ (Python 3 is used in the GitHub workflow)
- requests: For HTTP requests to fetch rule sources
- pyyaml: For YAML configuration file processing

## Testing

The project does not currently have a dedicated test suite. When adding tests:

1. Create a `tests/` directory
2. Use the unittest module
3. Name test files with `test_` prefix
4. Test each major stage (fetch, parse, classify, regex generation, output)

## Release Process

The project uses GitHub Actions for automated releases:

1. Scheduled builds run twice daily (UTC 8:00 and 20:00)
2. Manual triggers are available via workflow_dispatch
3. After building, the changes are automatically pushed to the repository

## Key Implementation Details

1. **Domain Processing**: The generator supports multiple rule formats (uBlock, v2ray, CSV)
2. **Auto-classification**: Uses the indexed rules from `custom/classify.txt` to override source classifications (exact domains via dict, `*.` wildcards via suffix list)
3. **Optimization**: Sources are prefetched in parallel; domains are grouped by TLD and merged with common prefix/suffix factoring; batches are rendered once and only split when a rule exceeds the length limit
4. **Error Handling**: Continues processing even if some sources fail, with detailed error reporting
