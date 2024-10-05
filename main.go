package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type shared_data lock lock.c

import (
    "log"
    "time"
    "flag"
    "net"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Allow the current process to lock memory for eBPF resources.
    if err := rlimit.RemoveMemlock(); err != nil {
	log.Fatal(err)
    }

    var ifname string
    flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF program will be attached")
    flag.Parse()

    // Load pre-compiled programs and maps into the kernel.
    var lockObjs lockObjects
    lockObjs = lockObjects{}
    if err := loadLockObjects(&lockObjs, nil); err != nil {
	log.Fatal(err)
    }

    iface, err := net.InterfaceByName(ifname)
    if err != nil {
	log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    var key uint32 = 0
    config := lockSharedData{
	Counter: uint32(0),
	LastUpdated: uint64(0),
    }
    err = lockObjs.lockMaps.SharedMap.Update(&key, &config, ebpf.UpdateLock) // // UpdateLock flag updates elements under bpf_spin_lock.
    if err != nil {
	log.Fatalf("Failed to update the map: %v", err)
    }

    // Attach XDP program to the network interface.
    xdplink, err := link.AttachXDP(link.XDPOptions{ 
	Program:   lockObjs.XdpProgram,
	Interface: iface.Index,
    })
    if err != nil {
	log.Fatal("Attaching XDP:", err)
    }
    defer xdplink.Close()


    time.Sleep(time.Second * 10)
}
