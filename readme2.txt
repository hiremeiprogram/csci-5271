-- README2.TXT --


Course: CSCI 5271 - Introduction to Computer Security

Assignment: HW1 Part 1

Date: 09/23/2016

-- EXPLOIT 2 DESCRIPTION --

The source code for bczip includes a mode where files written to the /tmp/ directory during decompression are given full executable privileges. By enabling this mode, and compressing and decompressing a file containing a binary copy of /bin/rootshell, we are able to construct a file that can run a binary copy of /bin/rootshell. Running this file gives us root privileges.

step by step, this is what happens in exploit2.sh:

1. Sets BCZIP_MODE environment variable to -1. This enables bczip to write files in /tmp/ with execute permissions set to everyone. (-1 was chosen because it is less than or equal to 0777 (if (m <= 0777)) setting pi.mode to -1. Later when pi.mode & 07777 is called it retains the value of 07777, giving full executable permissions.)
2. copies the contents of /bin/rootshell into a file called test2.sh
3. compresses and decompresses this file.
4. finds the copy of the file that was left in the /tmp/ directory with full execute permissions
5. executes this file to gain root.


