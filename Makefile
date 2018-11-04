all: captail btail

captail: captail.c
	gcc -o captail captail.c

btail: btail.c
	gcc -o btail btail.c


clean:
	@rm -f captail btail tcap tnotif
