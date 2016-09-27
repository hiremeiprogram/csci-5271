-- README1.TXT --

Course: CSCI 5271 - Introduction to Computer Security
Assignment: HW1 Part 1
Date: 09/22/2016

-- EXPLOIT 1 DESCRIPTION --
The source code in bczip.c defines different compressed block types: BLOCK_RAW, BLOCK_B32, etc. However, the block type BLOCK_SHELL does not appear to serve any purpose other than if this type of block is found in the compressed file during decompression it calls the c function system().

The problem with this is that the call to system() can invoke a shell as described by the man pages. It grabs the contents in the decompressed file, and passes it to the system call.

Therefore we managed to write our exploit1.sh file to modify a block in the compressed file to a block of type BLOCK_SHELL (42 = * in ASCII), to trigger the function output_block_shell() during decompression.

Our exploit1.sh performs the following:
1) Create a raw text file with the string "/bin/rootshell"
2) Run bczip compression of text file created in step 1 to create *.bcz archive
3) Use sed command to find and replace a normal block with BLOCK_SHELL ('*' in ASCII) in *.bcz archive created in step 2
4) Run bczip decompression on *.bcz archive created in step 2 that was modified in step 3
5) bczip application encounters BLOCK_SHELL and calls function output_block_shell which triggers system() call
6) Content of raw text file created in step 1 is passed to system call, and shell runs command ("/bin/rootshell")
7) Rootshell is invoked, and we now have root access
