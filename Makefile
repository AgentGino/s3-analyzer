.PHONY: install test format lint clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

format:
	black src/ tests/
	isort src/ tests/

lint:
	black --check src/ tests/
	isort --check src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
