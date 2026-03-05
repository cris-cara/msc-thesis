# msc-thesis
Master’s Thesis @ Reply Spike IAM 2025

## Usage
### Run Alice
```bash
uv run -m alice.__main__
```
### Run Bob
```bash
uv run -m bob.__main__
```

### Run tests
From the top level directory (```msc-thesis/```):
```bash
pytest -q .\test\test_*.py
```

Optionally, if you want to enable ```print()``` in tests:
```bash
pytest -q -s .\test\test_*.py
```