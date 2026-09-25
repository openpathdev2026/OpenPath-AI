.PHONY: test conformance unit install demo

# Full readiness gate: unit + conformance.
test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v

conformance:
	python3 -m unittest tests.conformance.test_conformance -v

unit:
	python3 -m unittest tests.unit.test_units -v

install:
	python3 -m pip install -e .

# Print the 13 question families.
demo:
	python3 -m openpath --list-families
