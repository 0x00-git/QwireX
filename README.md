# QwireX

# ! IMPORTANT EDUCATIONAL DISCLAIMER !

This software is developed **exclusively for educational purposes** to understand:
- Linux kernel module architecture
- System security mechanisms
- Rootkit detection techniques

**The author does NOT condone, support, or encourage:**
- Unauthorized system access
- Malicious use of this software
- Violation of computer fraud laws

**By using this software, you agree:**
+ To use it only in your own systems or with explicit written permission
+ That the author bears no responsibility for misuse
+ That you understand the legal implications in your jurisdiction

## info: ##
The QwireX rootkit allows remote access to a Linux terminal; this rootkit is currently under development and does not guarantee operation without kernel panics. 

**Security by design:** By design, the module is intentionally restricted to local network operation only. Remote access over the internet is not supported — this is a deliberate security measure to prevent unauthorized external access and emphasize the educational nature of the project.

+ The module was tested on kernel 6.17.0-19-generic (Ubuntu)

## installation: ##
```sh
cd QwireX
mkdir binaries
make
insmod QwireX/binaries/qwirex.ko
```

## use: ##
After installing qwirex, send a UDP packet using any method to the IP address of the PC running the module (within the local network) on port 80, and don’t forget to check the payload—there should be a command there.
## example: ##
```sh
echo -n "reboot" | nc -u 127.0.0.1 80
```