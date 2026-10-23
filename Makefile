CC      = gcc
CFLAGS  = -O2 -pthread -Wno-deprecated-declarations -Wno-unused-result
LDFLAGS = -lssl -lcrypto -largon2
TARGET  = jennifer
SRC     = jennifer.c
OBJ     = $(SRC:.c=.o)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	mkdir -p $(DESTDIR)/usr/local/bin
	cp $(TARGET) $(DESTDIR)/usr/local/bin/
	@if [ -f src/wordlists.txt ]; then \
		mkdir -p $(DESTDIR)/usr/local/share/jennifer/src; \
		cp src/wordlists.txt $(DESTDIR)/usr/local/share/jennifer/src; \
	fi
