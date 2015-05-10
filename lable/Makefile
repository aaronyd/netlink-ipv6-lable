CC=gcc

label:addr-sele.o ip-addr.o
	${CC} -o label addr-sele.o ip-addr.o
	rm *.o

addr-sele.o: addr-sele.c ip-addr.h
	${CC} -c addr-sele.c

ip-addr.o: ip-addr.c ip-addr.h
	${CC} -c ip-addr.c

clean:
	rm -f label *.o
