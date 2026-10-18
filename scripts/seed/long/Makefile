PYTHON ?= python3
MODULES = strings numbers lists codec

.PHONY: check test lint dist clean $(addprefix check-,$(MODULES))

check: test lint

test:
	$(PYTHON) -m unittest discover -s tests -t .

lint:
	$(PYTHON) tools/lint.py textkit

$(addprefix check-,$(MODULES)): check-%:
	$(PYTHON) -m unittest tests.test_$*
	$(PYTHON) tools/lint.py textkit/$*.py

dist:
	$(PYTHON) tools/build.py

clean:
	rm -rf dist
