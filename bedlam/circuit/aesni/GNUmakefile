
all: benchmarks

benchmarks: c/aesni
	go test -bench=.
	c/aesni

c/aesni: c/aesni.c
	gcc -Wall -maes -march=native -o $@ $+
