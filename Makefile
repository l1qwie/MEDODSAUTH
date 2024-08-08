net:
	docker network create medods-auth

build:
	docker build . -t medods-auth-app

rm:
	docker compose stop \
	&& docker compose rm \
	&& sudo rm -rf pgdata/
up:
	docker compose -f docker-compose.yml up --force-recreate