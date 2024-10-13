all: build run

build:
	clang -O2 -g -target bpf -c src/bpf/xdp.c -o src/bpf/xdp.o
	cargo build
run:
	sudo cargo run
