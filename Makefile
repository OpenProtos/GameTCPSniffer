PYTHON=python
ifeq ($(OS),Windows_NT)
  SHELL := pwsh.exe
  VENV=.venv
  BIN=$(VENV)\Scripts
  PIP=$(BIN)\pip
  PYTEST=$(BIN)\pytest
  MYPY=$(BIN)\mypy
  VENV_PYTHON=$(BIN)\$(PYTHON)
  WHERE=where
  NULL_DEVICE=nul
  PROTOBUF_INSTALLATION=winget install protobuf
  RM=Remove-Item
else
  VENV=venv
  BIN=$(VENV)/bin
  PIP=$(BIN)/pip
  PYTEST=$(BIN)/pytest
  MYPY=$(BIN)/mypy
  VENV_PYTHON=$(BIN)/$(PYTHON)
  WHERE=which
  NULL_DEVICE=/dev/null
  PROTOBUF_INSTALLATION=sudo apt-get update && sudo apt-get install -y protobuf-compiler
  RM=rm
endif

# install
install_venv:
	$(PYTHON) -m venv --clear $(VENV)
	$(VENV_PYTHON) -m pip install --upgrade pip

install: install_venv
	$(PIP) install --upgrade -r ./requirements.txt
	@$(WHERE) protoc >$(NULL_DEVICE) 2>&1 && echo "Protobuf already installed" || (echo "Installing protobuf..." && $(PROTOBUF_INSTALLATION) && echo "Protobuf installation complete")

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

clean:
	$(RM) *_pb2.py
