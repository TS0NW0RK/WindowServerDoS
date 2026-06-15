CC ?= clang
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = -framework IOKit -framework CoreFoundation

SRCS = src/main.c src/registry.c src/fuzzer.c src/utils.c
OBJS = $(SRCS:.c=.o)
TARGET = ca-iokit-fuzz
PROBE = ca-iokit-probe
REPLAY = ca-iokit-replay
FUZZ_OPS = src/fuzz_ops.o

.PHONY: all clean list test-dry probe replay

all: $(TARGET) $(PROBE) $(REPLAY)

$(TARGET): $(OBJS) $(FUZZ_OPS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(FUZZ_OPS) $(LDFLAGS)

$(PROBE): src/probe.o src/registry.o src/utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(REPLAY): src/replay.o src/fuzz_ops.o src/registry.o src/utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(FUZZ_OPS): src/fuzz_ops.c include/ca_fuzz.h include/ca_io.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/probe.o: src/probe.c include/ca_io.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/%.o: src/%.c include/ca_io.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

list: $(TARGET)
	./$(TARGET) --list | head -30

test-dry: $(TARGET)
	./$(TARGET) --dry-run -u IOSurface
