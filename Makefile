TARGET		:= dedup
OBJS		:= $(TARGET:=.o)

CC			:= gcc
CFLAGS		:= -g -pedantic -Wall -Wextra -std=c99 -I$(HOME)/src/BUSE
LDFLAGS		:= -lbuse -lssl -L$(HOME)/src/BUSE

.PHONY: all clean
all: $(TARGET)

$(TARGET): %: %.o
	$(CC) $(LDFLAGS) -o $@ $<

$(TARGET:=.o): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET) $(OBJS)
