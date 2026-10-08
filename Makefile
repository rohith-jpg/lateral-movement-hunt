PYTHON ?= python

.PHONY: setup run test lint format check sample docker
setup:
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install --no-build-isolation -e .
run:
	$(PYTHON) -m lateral_hunt
test:
	$(PYTHON) -m unittest discover -s tests -v
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
format:
	$(PYTHON) -m ruff format .
check: lint test
sample:
	$(PYTHON) scripts/generate_sample.py
docker:
	docker build -t lateral-movement-hunt .
	docker run --rm lateral-movement-hunt
