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
    @echo "Creating virtual environment in .venv..."
    python3 -m venv .venv
    @echo "Virtual environment created in .venv. Activate it using 'source .venv/bin/activate'."

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