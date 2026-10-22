# Contributing to open-evidence

Thank you for your interest in contributing to `open-evidence`! We welcome bug reports, documentation improvements, and code contributions that advance the reliability of AI evidence.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/huangbuqubunao-alt/open-evidence.git
   cd open-evidence
   ```

2. Create and activate a virtual environment (Python 3.10+):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

## Code Quality Standards

Before submitting a Pull Request, ensure all checks pass:

- **Run unit tests**:
  ```bash
  pytest
  ```
- **Type checking**:
  ```bash
  mypy src/open_evidence tests
  ```
- **Formatting & linting**:
  ```bash
  ruff check .
  ruff format --check .
  ```

## Submitting Pull Requests

1. Fork the repo and create your branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Keep PRs focused on a single change with descriptive commit messages.
3. Ensure all new logic includes unit tests covering positive, edge-case, and adversarial inputs.
4. Open a PR with a clear summary of changes and reference any related issues.
