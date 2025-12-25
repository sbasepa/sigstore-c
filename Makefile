CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -fPIC -I./include
LDFLAGS := -lcrypto -lssl -lcurl

SRC := src/sigstore.c
OBJ := $(SRC:.c=.o)

LIB_STATIC := libsigstore.a
LIB_SHARED := libsigstore.so

.PHONY: all clean install test

all: $(LIB_STATIC) $(LIB_SHARED)

$(LIB_STATIC): $(OBJ)
	ar rcs $@ $^

$(LIB_SHARED): $(OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build and run example
example: examples/sign_verify.c $(LIB_STATIC)
	$(CC) $(CFLAGS) -o examples/sign_verify examples/sign_verify.c -L. -lsigstore $(LDFLAGS)

test: example
	./examples/sign_verify

clean:
	rm -f $(OBJ) $(LIB_STATIC) $(LIB_SHARED) examples/sign_verify

install: $(LIB_STATIC) $(LIB_SHARED)
	install -d $(DESTDIR)/usr/local/lib
	install -d $(DESTDIR)/usr/local/include
	install -m 644 $(LIB_STATIC) $(DESTDIR)/usr/local/lib/
	install -m 755 $(LIB_SHARED) $(DESTDIR)/usr/local/lib/
	install -m 644 include/sigstore.h $(DESTDIR)/usr/local/include/
