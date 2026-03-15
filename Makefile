PYTHON := .venv/bin/python

test:
	$(PYTHON) -m pytest -q

# Example scan (edit TARGETS/PORTS as needed)
scan:
	PYTHONPATH=src $(PYTHON) -m recon.cli --targets "$(TARGETS)" --ports "$(PORTS)" --timeout $(TIMEOUT) --md --diff --banners

# Defaults for make scan
TARGETS ?= 10.0.0.0/30
PORTS ?= 22,80,443
TIMEOUT ?= 0.5
