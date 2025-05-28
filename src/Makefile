.PHONY: help install install-dev reinstall docker-build docker-run clean

help:
	@echo "Available targets:"
	@echo "  install       Create .venv and install Python dependencies"
	@echo "  install-dev   Create .venv and install Python dependencies with dev requirements (if any)"
	@echo "  reinstall     Delete .venv, recreate it, and install all dependencies"
	@echo "  docker-build  Build the Docker image"
	@echo "  docker-run    Run the Docker container"
	@echo "  clean         Remove Python cache files and .venv"

install: .venv
ifeq ($(OS),Windows_NT)
	.venv\Scripts\activate && pip install --upgrade pip && pip install -r requirements.txt
else
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt
endif

install-dev: .venv
ifeq ($(OS),Windows_NT)
	.venv\Scripts\activate && pip install --upgrade pip && pip install -r requirements.txt
	@if exist requirements-dev.txt (.venv\Scripts\activate && pip install -r requirements-dev.txt)
else
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt
	@if [ -f requirements-dev.txt ]; then . .venv/bin/activate && pip install -r requirements-dev.txt; fi
endif

reinstall:
	@echo "Deleting existing virtual environment..."
	rm -rf .venv
	@echo "Recreating virtual environment..."
	python -m venv .venv
	@echo "Installing dependencies..."
ifeq ($(OS),Windows_NT)
	.venv\Scripts\activate && pip install --upgrade pip && pip install -r requirements.txt
else
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt
endif
	@echo "Reinstallation complete."

.venv:
	@echo "Creating virtual environment in .venv..."
	python -m venv .venv
	@echo "Virtual environment created in .venv. Activate it using 'source .venv/bin/activate' (Linux/Mac) or '.venv\Scripts\activate' (Windows)."

docker-build:
	docker build -t antscrawlingjay/cpf-program .


docker-run:
	docker run -p 8501:8501 antscrawlingjay/cpf-program

clean:
	@echo "Cleaning up Python cache files and virtual environment..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .venv
	@echo "Cleanup complete."