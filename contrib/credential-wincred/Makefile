all: git-credential-wincred.exe

CC = gcc
RM = rm -f
CFLAGS = -O2 -Wall

git-credential-wincred.exe : git-credential-wincred.c
	$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@
