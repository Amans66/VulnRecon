# Contributing to VulnRecon

Thank you for your interest in improving VulnRecon!

## Developing New Plugins
1. Place plugin files inside the `plugins/` directory.
2. Ensure plugins return standardized `Finding` objects or dictionaries compatible with `core/response_analyzer.py:make_finding`.
3. Provide unit tests under `tests/`.
4. Run `python verify_plugins.py` to confirm syntax and load compatibility.

## Code Style & Testing
- Ensure all tests pass prior to submitting a PR:
  ```bash
  python -m pytest tests/ -v
  ```
- Avoid false-positive prone signatures; implement proper negative control controls using `core/validator.py`.
