# Contributing to NetSentinel

Thank you for your interest in contributing to NetSentinel! We welcome contributions from the cybersecurity and open-source community.

## Code of Conduct

Please be respectful, constructive, and considerate when collaborating with others.

## How to Contribute

### 1. Fork and Clone

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/NOUFAN02/netsentinel.git
   cd netsentinel
   ```

### 2. Set Up Development Environment

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Initialize your local environment:

```bash
cp .env.example .env
python database/setup_db.py
```

### 3. Run Tests

Ensure all unit tests pass before making changes:

```bash
python -m unittest discover tests
# or with pytest:
pytest
```

### 4. Making Changes

- Create a feature branch: `git checkout -b feature/your-feature-name`
- Follow PEP 8 guidelines for Python code style.
- Add unit tests in `tests/` for any new logic or bug fixes.
- Ensure existing tests continue to pass.

### 5. Submit a Pull Request

- Push changes to your branch: `git push origin feature/your-feature-name`
- Open a Pull Request against the `main` branch.
- Provide a clear explanation of what changed and why.

## Reporting Issues

If you find a bug or have a feature idea, please open an issue in the GitHub repository detailing:
- Expected behavior vs. actual behavior
- Steps to reproduce
- Environment details (OS, Python version, Suricata version)
