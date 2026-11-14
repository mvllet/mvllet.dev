CC = cc
CFLAGS = -O2 -Wall -Wextra -std=c11

TARGET = server

.PHONY: all clean run

all: $(TARGET)

$(TARGET): server.c
	$(CC) $(CFLAGS) -o $@ server.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
