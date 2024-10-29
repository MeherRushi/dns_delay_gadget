# Makefile
CLANG ?= clang
CFLAGS ?= -O2 -g -Wall

all: dns_delay.o dns_delay_user

dns_delay.o: dns_delay.c
	$(CLANG) -target bpf \
		-D __BPF_TRACING__ \
		$(CFLAGS) \
		-c dns_delay.c -o dns_delay.o

dns_delay_user: dns_delay_user.c
	$(CC) $(CFLAGS) dns_delay_user.c -o dns_delay_user -lbpf

clean:
	rm -f dns_delay.o dns_delay_user