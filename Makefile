PYTHON=python
ifeq ($(OS),Windows_NT)
  VENV=.venv
  BIN=$(VENV)\Scripts
  PIP=$(BIN)\pip
  PYTEST=$(BIN)\pytest
  MYPY=$(BIN)\mypy
  VENV_PYTHON = $(BIN)\$(PYTHON)
else
  VENV=venv
  BIN=$(VENV)/bin
  PIP=$(BIN)/pip
  PYTEST=$(BIN)/pytest
  MYPY=$(BIN)/mypy
  VENV_PYTHON = $(BIN)/$(PYTHON)
endif

# install
install_venv:
	$(PYTHON) -m venv --clear $(VENV)
	$(VENV_PYTHON) -m pip install --upgrade pip

install: install_venv
	$(PIP) install --upgrade -r ./requirements.txt

run:
	$(VENV_PYTHON) main.py $(VAR)

# unit testing
test:
	$(PYTEST) -v

# type annotations
mypy:
	$(MYPY) . --strict

# unit testing + type checking
check: test mypy

debug:
	$(VENV_PYTHON) -m pdb main.py $(VAR)
