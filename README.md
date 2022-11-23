# Table of Contents
 - [Summary](#Synopsis)
 - [Analysis](#Analysis)

## Summary

ANGRYORCHARD is an proof of concept exploiting the NtUserHardErrorControl call to achieve arbitrary R/W on Microsoft Windows 7 to 11. The bug itself works on all versions of Windows 7 to 11, and on newer editions of Windows is no longer easily reachable without third-party issues due to the servicing of the KnownDLLs bug described by [James Forshaw](https://twitter.com/tiraniddo?ref_src=twsrc%5Egoogle%7Ctwcamp%5Eserp%7Ctwgr%5Eauthor) and PoC developed by [itm4n](https://twitter.com/itm4n) in July of 2022. The bug itself lies within CSRSS, so any means of getting access to CSRSS will allow the attacker to exploit the affected issue.

The proof of concept is designed as an ReflectiveDLL, and must be injected into a privileged SYSTEM process to function properly. Upon execution, the bug will either depending on version inject the exploit directly into CSRSS, or elevate to PPL to inject the exploit code if it can. Once the code is injected, the exploit will call [NtUserHardErrorControl to decrement KTHREAD.PreviousMode to 0](Exploit.c) of the intial exploit stage thread.

## Analysis

The bug itself lies within the win32k system call NtUserHardErrorControl, in the way it handles arbitrary handles being passed to it. It was observed that when calling NtUserHardErrorControl with a control code set to `HardErrorDetachNoQueue`, the functions `NtUserHardErrorControl`, `xxxHardErrorControl`, and `xxxRestoreCsrssThreadDesktop` would perform no validation on the handle before calling `CloseProtectedHandle` ( later ObfDereferenceObject )

![](https://i.imgur.com/G837Pqw.png)

*Demonstrating control flow of HardErrorDetachNoQueue to xxxRestoreCsrssThreadDesktop*

![](https://i.imgur.com/WnReUoT.png)

*Demonstrating what lead to the actual 'bug' when within CSRSS*

Fortunately, for me anyhow, achieving elevation is relatively trivial. I observed that when when performing the transition from usermode to kernel mode, a thread's PreviousMode is considered to be the valid indicator of whether the caller originates from Kernel Mode. So by passing the address of the KTHREAD object's PreviousMode field, and accounting for the offset to the respective member in the OBJECT_HEADER that would be decremented, I was able to successfully force PreviousMode of my current thread ( originally set to `UserMode` ) to be decremented to `KernelMode`.

With this new privilege, I am able to use the available system calls with the same ease as a kernel
caller, without all the validation checks that would have previously stopped me from interacting with kernel memory such as virtual, or even physical memory from the `\Device\PhysicalMemory` object. With this, we can even inject an unsigned rootkit, regardless of HVCI / VBS being configured ;).
