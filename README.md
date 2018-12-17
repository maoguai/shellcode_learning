# shellcode_learning
这个日志记录了学习shellcode过程和在学习过程中遇到的问题。<br><br>
主要参考了蒸米的一步一步学ROP，修改了作者的部分错误和一些其他博客。<br><br>

## 配置环境
操作系统：ubuntu16.04 LTS 64位系统（建议不使用ubuntu18,可能使用了更加复杂的地址保护机制，容易导致实验失败）<br>
编译工具：
1. python2 <br>
2. pwntools(py的库函数，安装方法见https://www.cnblogs.com/pcat/p/5451780.html ）<br>
3. objdump <br>
4. ROPgadget<br>

## linux_84

$ gcc -fno-stack-protector -z execstack  -m32 -o level1 level1.c<br>
因为ubuntu16.04是64位系统在编译 -m32 时会报错，因为需要安装安装库文件sudo apt-get install gcc-4.8-multilib g++-4.8-multilib
$ sudo -s
$ echo 0 > /proc/sys/kernel/randomize_va_space
$ exit
$ python pattern.py create 150得到
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9
$ gdb ./level1
（gdb)run 得到
Program received signal SIGSEGV, Segmentation fault.
0x37654136 in ?? ()
（gdb）quit
$ python pattern.py offset 0x37654136 得到
hex pattern decoded as: 6Ae7
140
$ ulimit -c unlimited
$ sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
$ ./level1 得到
ABCDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
段错误 (核心已转储)
$ gdb level1 /tmp/core.1545029320
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x41414141 in ?? ()
(gdb) x/10s $esp -144
0xffffd000:	"ABCD", 'A' <repeats 140 times>, "\nS\373\367\260\320\377\377"
0xffffd099:	""
$ python exp1.py
