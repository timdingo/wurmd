CC=gcc
prefix=/usr
CCC=/opt/crosstool-ng/x-tools/arm-unknown-linux-gnueabi/bin/arm-unknown-linux-gnueabi-gcc
SRC_FILES=`find -iname *.c | grep -v main.c`

all:
	make x86
	make x86-debug
x86:
	mkdir -p bin/x86-64
	$(CC) -Wall -Wextra -pedantic -lpcap $(SRC_FILES) src/main.c -o bin/x86-64/wurmd
	strip bin/x86-64/wurmd

x86-debug:
	mkdir -p bin/x86-64
	$(CC) -g -Wall -Wextra -pedantic -lpcap $(SRC_FILES) src/main.c -o bin/x86-64/wurmd-debug

arm:
	$(CCC) src/functions.c src/main.c -L/opt/crosstool-ng/x-tools/arm-unknown-linux-gnueabi/lib/ -I/opt/crosstool-ng/x-tools/arm-unknown-linux-gnueabi/include/ -Wall -Wextra -pedantic -static -lpcap -o bin/arm/wurmd

install:
	install -m 0755 bin/x86-64/wurmd $(prefix)/sbin/
	install -m 0755 debian/etc/wurmd.conf /etc/
	install -m 0755 debian/etc/default/wurmd /etc/default/
	install -m 0755 debian/etc/init.d/wurmd /etc/init.d/

uninstall:
	rm bin/x86-64/wurmd $(prefix)/sbin/
	rm debian/etc/wurmd.conf /etc/
	rm debian/etc/default/wurmd /etc/default/
	rm debian/etc/init.d/wurmd /etc/init.d/

clean:
	rm -r bin/

