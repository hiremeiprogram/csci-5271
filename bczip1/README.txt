===================

~* READ ME FIRST *~

===================

a. Instructions on how to access your VM are in `vm-instructions.html`

	* Remember: you need to e-mail Nishad (triv0025@umn.edu) the names and UMN usernames of all your group members first.
	  He will then e-mail you your credentials, so you can log in.



b. Instructions on the actual assignment are in `HA1-instructions.pdf`



c. How to install the BCZIP program:

	i. Log into your VM and copy bczip to /src/
		If you don't know how to copy files remotely, do the following command:

		$ scp <username>@<host>:<path-to-bczip.c> /src/.  (e.g.  scp triv0025@kh4250-01.cselabs.edu:~/bczip1/bczip.c /src/.)

	ii. Copy the Makefile to /src/ as well 

	iii. Now build and install the program

		$ cd /src
		$ sudo make all
		$ sudo make install
	 	$ bczip -v

	 iii. If everything worked it should say you're on BCZIP version 2



If you encounter any problems with accessing your VM, installing the BCZIP program, and need help, contact Nishad 
and he will get back to you as soon as he can!

Good luck!

- Nishad
