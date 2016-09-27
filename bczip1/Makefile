# Using the default compiler in Ubuntu 14.04:
# gcc (Ubuntu 4.8.4-2ubuntu1~14.04) 4.8.4
CC := gcc-4.8

# -g: include debugging information
# -m32: compile a 32-bit binary, even on a 64-bit machine
# -Wall: enable most warning messages
# -fno-stack-protector: disable a security mechanism
# -z execstack: allow code execution on the stack
# -z norelro: disable a security mechanism
BCZ_CFLAGS := -g -Wall -m32 -fno-stack-protector -z execstack -z norelro

all: bczip bcunzip-as-root

bczip: bczip.c
	$(CC) $(BCZ_CFLAGS) $< -o $@

CFLAGS := -g -w

bcunzip-as-root: bcunzip-as-root.c
	$(CC) $(CFLAGS) $< -o $@

ifeq ($(shell which rootshell),/bin/rootshell)

EXE:=bczip
EXEPATH:=/usr/bin/$(EXE)

install:
	@# The bczip executable itself is not setuid or setgid
	sudo -v && sudo cp $(EXE) $(EXEPATH)
	sudo -v && sudo chown root:root $(EXEPATH)
	sudo -v && sudo chmod a+rx $(EXEPATH)
	@# The bcuzip-as-root executable is setuid root
	sudo -v && sudo cp bcunzip-as-root /usr/bin/bcunzip-as-root
	sudo -v && sudo chown root:root /usr/bin/bcunzip-as-root
	sudo -v && sudo chmod a+rx /usr/bin/bcunzip-as-root
	sudo -v && sudo chmod u+s /usr/bin/bcunzip-as-root

else
install:
	@echo "Don't install this on a real machine!"
endif
