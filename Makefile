a.out : main.o
	gcc -o a.out main.o

a.o :
	gcc -c main.c

clean :
	rm a.out *.o
