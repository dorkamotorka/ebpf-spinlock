# eBPF Spinlock

```
go generate
go build
sudo ./lock
```

Test using:
```
sudo -u restricted-user -- ls & sudo -u restricted-user -- su another-user
```
In Linux, you can run multiple commands simultaneously using the '&' sign after one command. Using this built-in bash ampersand or operator causes the shell to run the next command without waiting for the currently running one, and the commands are run in parallel.
