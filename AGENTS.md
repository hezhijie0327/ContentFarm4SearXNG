# AGENTS.md

This file contains important information for agentic coding agents working in this repository.

## Project Overview

ContentFarm4SearXNG is a Python-based tool that generates hostname rules for SearXNG search engine. It fetches content farm filter lists from various sources, processes them, and generates categorized YAML rule files for SearXNG to filter out low-quality content farms while prioritizing reliable sources.

## Build/Test/Lint Commands

### Main Commands

```bash
# Install dependencies
pip install requests pyyaml argparse

# Run the hostname generator (main build process)
python3 hostname_generator.py

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

## Code Style Guidelines

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

```
ContentFarm4SearXNG/
├── hostname_generator.py          # Main generator script
├── auto_classify.txt              # Manual classification rules
├── .github/workflows/main.yml      # CI/CD workflow
└── rules/                          # Generated rule files
    ├── hostnames-config.yml        # Main configuration
    ├── high-priority-hosts.yml     # High priority domains
    ├── low-priority-hosts.yml      # Low priority domains
    ├── remove-hosts.yml            # Domains to remove
    └── rewrite-hosts.yml           # Domain replacement rules
```

## Dependencies

- Python 3.8+ (Python 3 is used in the GitHub workflow)
- requests: For HTTP requests to fetch rule sources
- pyyaml: For YAML configuration file processing
- argparse: For command line argument parsing

## Testing

The project does not currently have a dedicated test suite. When adding tests:

1. Create a `tests/` directory
2. Use the unittest module
3. Name test files with `test_` prefix
4. Test each major function in the hostname generator

## Release Process

The project uses GitHub Actions for automated releases:

1. Scheduled builds run twice daily (UTC 8:00 and 20:00)
2. Manual triggers are available via workflow_dispatch
3. After building, the changes are automatically pushed to the repository

## Key Implementation Details

1. **Domain Processing**: The generator supports multiple rule formats (uBlock, v2ray, CSV)
2. **Auto-classification**: Uses rules from `auto_classify.txt` to override source classifications
3. **Optimization**: Implements domain merging and regex optimization for performance
4. **Error Handling**: Continues processing even if some sources fail, with detailed error reporting