CC = $(CROSS_COMPILE)gcc
CFLAGS=-O0 -Werror -g2 -I. -I../../../arch/powerpc/include/

opal-prd: opal-prd.o thunk.o
	$(CC) $(CFLAGS) -o $@ $^

all: opal-prd

clean:
	rm -f *.[odsa] opal-prd

distclean: clean
	rm -f *~
