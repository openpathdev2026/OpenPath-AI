.PHONY: test conformance unit live install demo

# Full readiness gate: discovers all unit + conformance tests. The host-dependent
# live suite is discovered but skips itself via OPENPATH_LIVE=0.
test:
	OPENPATH_LIVE=0 python3 -m unittest discover -s tests -p 'test_*.py' -v

conformance:
	python3 -m unittest tests.conformance.test_conformance -v

unit:
	python3 -m unittest tests.unit.test_units -v

# Live checks against the real host filesystem (safe, read-only).
live:
	python3 -m unittest tests.live.test_live_host -v

install:
	python3 -m pip install -e .

# Print the 13 question families.
demo:
	python3 -m openpath --list-families
