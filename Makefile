docker-build:
	docker build -t antscrawlingjay/cpf-program:latest .

docker-push:
	docker push antscrawlingjay/cpf-program:latest

docker-run:
	docker run -d --name cpf-program -p 8501:8501 antscrawlingjay/cpf-program:latest

docker-compose-up:
	docker-compose up -d

docker-compose-down:
	docker-compose down

docker-logs:
	docker logs -f cpf-program