dev: build
		./bpache

build: server.c
		clang -std=c99 -g -o bpache server.c
