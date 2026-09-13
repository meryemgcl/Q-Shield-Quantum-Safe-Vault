# Contributing to Q-Shield

Thank you for your interest in contributing to the **Q-Shield Post-Quantum Cryptography** project!

## Code of Conduct
We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors.

## Development Workflow
1. **Fork the repository** and create your branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. **Install development dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install flake8 mypy
   ```
3. **Ensure all tests pass**:
   ```bash
   python run_tests.py
   ```
4. **Commit using Conventional Commits**:
   - `feat(...)`: New feature or cryptographic primitive
   - `fix(...)`: Bug or security fix
   - `docs(...)`: Documentation updates
   - `test(...)`: Adding or updating tests
   - `chore(...)`: Tooling, CI, or dependency updates

5. **Submit a Pull Request (PR)** against the `main` branch.
