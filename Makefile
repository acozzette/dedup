TARGET		:= dedup
OBJS		:= $(TARGET:=.o)

CC			:= gcc
CFLAGS		:= -g -pedantic -Wall -Wextra -std=c99 -I./BUSE
LDFLAGS		:= -lbuse -lcrypto -L./BUSE

.PHONY: all clean
all: $(TARGET)

$(TARGET): %: %.o
	$(CC) -o $@ $< $(LDFLAGS)

$(TARGET:=.o): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET) $(OBJS)
