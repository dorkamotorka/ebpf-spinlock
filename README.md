# eBPF Spinlock

A common technique in the kernel for synchronization is a spinlock. eBPF also provides spinlock capabilities for map values. 
The main advantage of spinlocks over atomic instructions is that it guarantees multiple fields are updated together, while atomic operations only work on a single variable of 1, 2, 4, or 8 bytes.

This example includes two LSM-BPF programs (type of the program was arbitrarily chosen) that both update the same eBPF Map (also the same element). 

The idea is to simulate how two different programs can safely update elements in the eBPF Map using spin locks.

## How to run
```
go generate
go build
sudo ./lock
```

Test using:
```
sudo -u restricted-user -- ls & sudo -u restricted-user -- su another-user
```
In Linux, '&' runs multiple commands simultaneously. Using this built-in bash ampersand or operator causes the shell to run the next command without waiting for the currently running one, and the commands are run in parallel.

You can check the eBPF logs, that eBPF map elements are indeed updated, using:
```
sudo bpftool prog trace
```
