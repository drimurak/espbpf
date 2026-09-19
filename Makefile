# Host build: library, bpfrun, tests, example programs, fuzzers.
#   make            build everything and run the tests
#   make fuzz       build libFuzzer targets (clang)

CC      ?= cc
CLANG   ?= clang
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -Werror -D_DEFAULT_SOURCE -Icore/include -Isdk
SAN     := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
BPFFLAGS := -O2 -g -target bpf -ffreestanding -mcpu=v4 -Isdk -Wall -Werror -c

CORE := core/src/vm.c core/src/verifier.c core/src/elf.c core/src/disasm.c core/src/std.c
HDRS := $(wildcard core/include/*.h core/src/*.h sdk/*.h)

EXAMPLES := $(patsubst %.c,build/%.o,$(wildcard examples/*.c))
BAD      := $(patsubst %.c,build/%.o,$(wildcard tests/bad/*.c))

all: build/bpfrun build/test_vm $(EXAMPLES) $(BAD) test

build/bpfrun: host/bpfrun.c $(CORE) $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SAN) -o $@ host/bpfrun.c $(CORE)

build/test_vm: tests/test_vm.c $(CORE) $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SAN) -o $@ tests/test_vm.c $(CORE)

build/%.o: %.c sdk/espbpf_prog.h
	@mkdir -p $(dir $@)
	$(CLANG) $(BPFFLAGS) $< -o $@

test: build/bpfrun build/test_vm $(EXAMPLES) $(BAD)
	./build/test_vm
	./tests/run_examples.sh

fuzz: build/fuzz_elf build/fuzz_verify corpus

# Seeds for fuzz_verify: raw "sensor" sections of the examples, with lddw
# retargeted to the fuzzer's fake rodata (see tests/mkcorpus.py).
corpus: $(EXAMPLES)
	@mkdir -p build/corpus_v
	python3 tests/mkcorpus.py build/corpus_v $(EXAMPLES)

# Without libFuzzer we use tests/minifuzz.c as the driver (same entry point).
build/fuzz_%: tests/fuzz_%.c tests/minifuzz.c $(CORE) $(HDRS)
	@mkdir -p build
	$(CC) -O1 -g -Icore/include $(SAN) -o $@ $< tests/minifuzz.c $(CORE)

clean:
	rm -rf build

.PHONY: all test fuzz corpus clean
