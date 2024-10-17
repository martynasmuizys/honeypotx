all: build run

all_docker: build run_docker

docker_clean:
	docker container rm hpx
	docker image rm hpx

docker_build:
	docker buildx build -t hpx .
	docker run --privileged -it --name hpx hpx:latest

build:
	clang -O2 -g -target bpf -c src/bpf/xdp.c -o src/bpf/xdp.o
	cargo build

run_docker:
	cargo run

run:
	cargo run
