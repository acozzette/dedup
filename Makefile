TARGET		:= dedup
OBJS		:= $(TARGET:=.o)

CC			:= gcc
CFLAGS		:= -g -pedantic -Wall -Wextra -std=c99 -I$(HOME)/src/BUSE
LDFLAGS		:= -lbuse -lcrypto -L$(HOME)/src/BUSE

.PHONY: all clean
all: $(TARGET)

$(TARGET): %: %.o
	$(CC) -o $@ $< $(LDFLAGS)

$(TARGET:=.o): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET) $(OBJS)
