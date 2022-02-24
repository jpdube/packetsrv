BASE=$(shell pwd)
BIN=$(BASE)/bin
DIST=$(BASE)/dist
CONFIGDIR=$(BASE)/config-jpd
PYFILES=$(wildcard *.py)
APPNAME=pcapdbapi
MAIN=main.py
PYTHON=python3

format:
	black .	
	black packet/	

check:
	mypy main.py

run:
	$(PYTHON) $(MAIN) "2022-02-12 15:30:00" "2022-02-12 16:00:00"

.PHONY: test
test:
	$(PYTHON) -m unittest

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
