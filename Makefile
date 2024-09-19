BASE=$(shell pwd)
BIN=$(BASE)/bin
DIST=$(BASE)/dist
CONFIGDIR=$(BASE)/config-jpd
PYFILES=$(wildcard *.py)
APPNAME=packetdb
APPMAIN=./app/main.py
MAIN=$(BASE)/app/main.py
PYTHON=python3
TEST_DIR=$(BASE)/test


check:
	mypy app/pql app/dbase app/packet app/api
	# mypy main.py pql/ dbase/ packet/ api/

run:
	# $(PYTHON) setup.py build_ext --inplace
	$(PYTHON) $(MAIN)

.PHONY: test
test:
	clear;cd $(TEST_DIR);pytest

.PHONY: test_verbose
test_verbose:
	clear;cd $(TEST_DIR);pytest -s

.PHONY: build
build:
	#pip freeze > requirements.txt
	pyinstaller --onefile --name $(APPNAME)-linux-arm64 $(APPMAIN)

clean:
	rm -rf ./dist
	rm -rf ./build
	rm -rf ./__pycache__

.PHONY: rebuild
rebuild: clean build
