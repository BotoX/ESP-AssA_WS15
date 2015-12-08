OUT = assa

CC = gcc
CFLAGS = -m32 -std=gnu90 -g3 -O3 -Wall

SRC = assa.c

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $^

.PHONY: clean

clean:
	rm $(OUT)
