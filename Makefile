CC=gcc
EABI=arm-linux-gnueabi
prefix=/usr
SRC_FILES=`find src -iname *.c | grep -v main.c`
PCAP_VERSION=1.9.0
PCAP_ARM=libpcap-$(PCAP_VERSION)

all:
	$(MAKE) x86
	$(MAKE) x86-debug
x86:
	mkdir -p bin/x86-64
	$(CC) -Wall -Wextra -pedantic -lpcap $(SRC_FILES) src/main.c -o bin/x86-64/wurmd
	strip bin/x86-64/wurmd

x86-debug:
	mkdir -p bin/x86-64
	$(CC) -g -Wall -Wextra -pedantic -fstack-protector-strong -lpcap $(SRC_FILES) src/main.c -o bin/x86-64/wurmd-debug

arm-pcap:
	wget http://www.tcpdump.org/release/libpcap-$(PCAP_VERSION).tar.gz
	tar -zxvf libpcap-$(PCAP_VERSION).tar.gz
	cd libpcap-$(PCAP_VERSION); \
	CC=arm-linux-gnueabi-gcc ac_cv_linux_vers=2 ./configure --host=arm-linux --with-pcap=linux; \
	make

arm-debug:
	mkdir -p bin/arm
	$(EABI)-$(CC) $(SRC_FILES) src/main.c -L$(PCAP_ARM)/ -I$(PCAP_ARM)/ -Wall -Wextra -pedantic -static -lpcap -o bin/arm/wurmd

arm:
	make arm-debug
	$(EABI)-strip bin/arm/wurmd

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
	rm -rf bin
	rm -rf libpcap-$(PCAP_VERSION)
	rm -rf libpcap-$(PCAP_VERSION).tar.gz
