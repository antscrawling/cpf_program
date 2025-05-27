.PHONY: help install install-dev docker-build docker-run clean

help:
	@echo "Available targets:"
	@echo "  install       Create .venv and install Python dependencies"
	@echo "  install-dev   Create .venv and install Python dependencies with dev requirements (if any)"
	@echo "  docker-build  Build the Docker image"
	@echo "  docker-run    Run the Docker container"
	@echo "  clean         Remove Python cache files and .venv"

install: .venv
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

install-dev: .venv
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt
	@if [ -f requirements-dev.txt ]; then . .venv/bin/activate && pip install -r requirements-dev.txt; fi

.venv:
	python3 -m venv .venv
	@echo "Virtual environment created in .venv"

docker-build:
	docker build -t cpf_app .

docker-run:
	docker run -p 8501:8501 cpf_app

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .venv