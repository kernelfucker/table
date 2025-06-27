cc=clang
cflags=-Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
ldflags=-lpcap
src=src/table.c src/tui.c
target=table

all= $(target)

$(target): $(src)
	$(cc) $(cflags) -o $(target) $(src) $(ldflags)

install: $(target)
	install -m 755 $(target) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(target)

.PHONY: all install uniunstall
