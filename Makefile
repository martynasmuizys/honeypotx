docker: docker-clean docker-build

docker-clean:
	docker container rm hpx
	docker image rm hpx

docker-build:
	docker buildx build -t hpx .
	docker run --privileged -it --name hpx hpx:latest

install:
	cargo install --path .
