CC ?= cc
PYTHON ?= python3
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror
LDLIBS = -lcrypto
SANITIZER_OPTIONS ?= detect_leaks=1
VALGRIND ?= valgrind
VALGRIND_FLAGS ?=

.PHONY: all check sanitize memcheck timing taint clean
all: build/libspiral_native.so build/libspiral_testing.so

build:
	mkdir -p build

build/libspiral_native.so: spiral_native.c spiral_native.h | build
	$(CC) $(CFLAGS) -fPIC -fvisibility=hidden -shared $< $(LDLIBS) -o $@

build/libspiral_testing.so: spiral_native.c spiral_native.h | build
	$(CC) $(CFLAGS) -fPIC -fvisibility=hidden -DSPIRAL_TESTING -shared $< $(LDLIBS) -o $@

build/check_sanitize: check_native.c spiral_native.c spiral_native.h | build
	$(CC) -O1 -g -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer $< -Wl,--wrap=RAND_priv_bytes -Wl,--wrap=EVP_MD_CTX_new $(LDLIBS) -o $@

build/check_memcheck: check_native.c spiral_native.c spiral_native.h | build
	$(CC) $(CFLAGS) $< -Wl,--wrap=RAND_priv_bytes -Wl,--wrap=EVP_MD_CTX_new $(LDLIBS) -o $@

build/timing: timing_native.c spiral_native.c spiral_native.h | build
	$(CC) $(CFLAGS) $< $(LDLIBS) -lm -o $@

check: all
	cd .. && $(PYTHON) -m unittest native_research.test_native -v

sanitize: build/check_sanitize
	ASAN_OPTIONS=$(SANITIZER_OPTIONS) ./build/check_sanitize

memcheck: build/check_memcheck
	$(VALGRIND) $(VALGRIND_FLAGS) --error-exitcode=99 --track-origins=yes --leak-check=full ./build/check_memcheck

timing: build/timing
	./build/timing 6000

build/taint: taint_native.c spiral_native.c spiral_native.h | build
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

taint: build/taint
	@set +e; $(VALGRIND) $(VALGRIND_FLAGS) --error-exitcode=99 --track-origins=yes ./build/taint positive; result=$$?; test $$result -eq 99
	$(VALGRIND) $(VALGRIND_FLAGS) --error-exitcode=99 --track-origins=yes --leak-check=full ./build/taint

clean:
	rm -rf build
