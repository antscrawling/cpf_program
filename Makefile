.PHONY: help docker-build docker-push docker-run docker-compose-up docker-compose-down docker-logs docker-pull docker-stop docker-rm docker-clean

help:
	@echo "Available targets:"
	@echo "  docker-build      Build the Docker image"
	@echo "  docker-push       Push the Docker image to Docker Hub"
	@echo "  docker-pull       Pull the latest Docker image from Docker Hub"
	@echo "  docker-run        Run the Docker container"
	@echo "  docker-stop       Stop the running container"
	@echo "  docker-rm         Remove the container"
	@echo "  docker-logs       View container logs"
	@echo "  docker-compose-up Start the application using docker-compose"
	@echo "  docker-compose-down Stop and remove containers created by docker-compose"
	@echo "  docker-clean      Remove all containers and images related to this project"

docker-build:
	@echo "Building Docker image..."
	docker build -t antscrawlingjay/cpf-program:latest .
	@echo "Docker image built successfully!"

docker-push:
	@echo "Pushing Docker image to Docker Hub..."
	docker push antscrawlingjay/cpf-program:latest
	@echo "Docker image pushed successfully!"

docker-pull:
	@echo "Pulling latest Docker image..."
	docker pull antscrawlingjay/cpf-program:latest
	@echo "Docker image pulled successfully!"

docker-run:
	@echo "Starting Docker container..."
	docker run -d --name cpf-program -p 8501:8501 antscrawlingjay/cpf-program:latest
	@echo "Container started! Access the application at http://localhost:8501"

docker-stop:
	@echo "Stopping container..."
	docker stop cpf-program || true
	@echo "Container stopped!"

docker-rm:
	@echo "Removing container..."
	docker rm cpf-program || true
	@echo "Container removed!"

docker-logs:
	@echo "Showing container logs (Ctrl+C to exit)..."
	docker logs -f cpf-program

docker-compose-up:
	@echo "Starting application with docker-compose..."
	docker compose up -d
	@echo "Application started! Access it at http://localhost:8501"

docker-compose-down:
	@echo "Stopping application..."
	docker compose down
	@echo "Application stopped!"

docker-clean:
	@echo "Cleaning up Docker resources..."
	docker stop cpf-program || true
	docker rm cpf-program || true
	docker rmi antscrawlingjay/cpf-program:latest || true
	@echo "Cleanup complete!"

# Convenience targets
deploy: docker-build docker-push
	@echo "Deployment complete! Image pushed to Docker Hub."

start: docker-compose-up
	@echo "Application started! Access it at http://localhost:8501"

stop: docker-compose-down
	@echo "Application stopped!"

restart: stop start
	@echo "Application restarted!"