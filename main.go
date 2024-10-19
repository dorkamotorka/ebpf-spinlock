package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type shared_data lock lock.c

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
    // Allow the current process to lock memory for eBPF resources.
    if err := rlimit.RemoveMemlock(); err != nil {
	    log.Fatal(err)
    }

    // Load pre-compiled programs and maps into the kernel.
    var lockObjs lockObjects
    lockObjs = lockObjects{}
    if err := loadLockObjects(&lockObjs, nil); err != nil {
	    log.Fatal(err)
    }

    var key uint32 = 0
    config := lockSharedData{
	    RejectCount: uint32(0),
	    LastUpdated: uint64(0),
    }
    err := lockObjs.lockMaps.SharedMap.Update(&key, &config, ebpf.UpdateLock) // UpdateLock flag updates elements under bpf_spin_lock.
    if err != nil {
	    log.Fatalf("Failed to update the map: %v", err)
    }

    // Attach LSM programs.
    lsmLink, err := link.AttachLSM(link.LSMOptions{
	    Program:   lockObjs.PolicePerm,
    })
    if err != nil {
	    log.Fatal("Attaching LSM bprm_creds_from_file:", err)
    }
    defer lsmLink.Close()

    lsmLink2, err := link.AttachLSM(link.LSMOptions{
	    Program:   lockObjs.PolicePermChange,
    })
    if err != nil {
	    log.Fatal("Attaching LSM task_fix_setuid:", err)
    }
    defer lsmLink2.Close()

    time.Sleep(time.Second * 60)
}
