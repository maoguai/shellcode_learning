# shellcode_learning
这个日志记录了学习shellcode过程和在学习过程中遇到的问题。<br><br>
主要参考了蒸米的一步一步学ROP，修改了作者的部分错误和一些其他博客。<br><br>

## 配置环境
操作系统：ubuntu16.04 LTS （建议不使用ubuntu18,可能使用了更加复杂的地址保护机制，容易导致实验失败<br>
编译工具：
1. python2 <br>
2. pwntools(py的库函数，安装方法见https://www.cnblogs.com/pcat/p/5451780.html ）<br>
3. objdump <br>
4. ROPgadget<br>

## linux_84
