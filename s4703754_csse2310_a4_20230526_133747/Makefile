CC=gcc 
CFLAGS=-Wall -pedantic -std=gnu99 -Werror
CLINKS=-I/local/courses/csse2310/include -L/local/courses/csse2310/lib -lcsse2310a3 -lcsse2310a4 -pthread -lcrypt 

all: crackclient crackserver
#Will need to add commands.c and commands.h to this later on
crackclient: crackclient.c 
	$(CC) $(CFLAGS) $(CLINKS) $^ -o $@
	# $@ = name of target, $< = name of first prereq
	# line above same as
	# gcc -Wall -pedantic -std=gnu99 -o $@ $< 
 
crackserver: crackserver.c
	$(CC) $(CFLAGS) $(CLINKS) $^ -g -o $@

clean: 
	rm crackclient crackserver
