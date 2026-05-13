CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation -g -O0 \
         -I../src -I./mock_android -D_GNU_SOURCE
LDFLAGS = -lm -ldl -lpthread

SRC_DIR = ../src
SRC_FILES = sha1.c signal_handler.c dex_detector.c file_utils.c \
            registry_manager.c config_manager.c memory_scanner.c stealth.c
SRC_OBJS = $(SRC_FILES:.c=.o)

.PHONY: all clean run

all: run

$(SRC_OBJS): %.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

stub_main.o: stub_main.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_runner.o: test_runner.c test_framework.h
	$(CC) $(CFLAGS) -c -o $@ $<

test_runner: $(SRC_OBJS) stub_main.o test_runner.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: test_runner
	./test_runner

clean:
	rm -f *.o test_runner
