BASE=$(shell pwd)
BIN=$(BASE)/bin
DIST=$(BASE)/dist
CONFIGDIR=$(BASE)/config-jpd
PYFILES=$(wildcard *.py)
APPNAME=pcapdbapi
MAIN=main.py
PYTHON=python3
TEST_DIR=$(BASE)/test


check:
	mypy main.py pql/ dbase/ packet/ api/

run:
	$(PYTHON) $(MAIN)

.PHONY: test
test:
	pytest $(TEST_DIR)

.PHONY: build
build:
	#pip freeze > requirements.txt
	pyinstaller --onefile --name $(APPNAME)-linux-amd64 $(MAIN)

clean:
	rm -rf ./dist
	rm -rf ./build
	rm -rf ./__pycache__

.PHONY: rebuild
rebuild: clean build
