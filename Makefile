.PHONY: clean

phttpd: phttpd.c
	gcc -Wall -o phttpd phttpd.c

clean:
	rm -f phttpd *.o
