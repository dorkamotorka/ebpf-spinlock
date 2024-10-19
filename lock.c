//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define PATHLEN 256

struct shared_data {
  struct bpf_spin_lock lock; // spinlock to protect the data
  __u32 reject_count;        // Counter for rejected actions
  __u64 last_updated;        // timestamp of last update
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct shared_data);
  __uint(max_entries, 1);
} shared_map SEC(".maps");

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(police_perm, struct linux_binprm *bprm) {
  char bl[] = "/usr/bin/ls";
  char buf[PATHLEN];

  __u32 key = 0;
  struct shared_data *data;

  // Get the shared data from the map
  data = bpf_map_lookup_elem(&shared_map, &key);
  if (!data) {
    return 0;
  }

  __u64 time = bpf_ktime_get_ns(); // Get the current time
  __u32 uid =
      bpf_get_current_uid_gid() & 0xFFFFFFFF; // Extract the lower 32 bits (UID)
  int len = bpf_probe_read_str(buf, sizeof(buf), bprm->filename);

  if (uid == 1001 && len > 11) {
    if (buf[0] == bl[0] && buf[1] == bl[1] && buf[2] == bl[2] &&
        buf[3] == bl[3] && buf[4] == bl[4] && buf[5] == bl[5] &&
        buf[6] == bl[6] && buf[7] == bl[7] && buf[8] == bl[8] &&
        buf[9] == bl[9] && buf[10] == bl[10] && buf[11] == bl[11]) {
      bpf_printk("Reject execution of ls command for user with ID 1001");

      // Acquire the spinlock
      bpf_spin_lock(&data->lock);

      // Safely update both fields
      data->reject_count += 1;
      data->last_updated = time;

      // Release the spinlock
      bpf_spin_unlock(&data->lock);
      bpf_printk("Reject count increased from bprm_creds_from_file: %d",
                 data->reject_count);
      return -EPERM;
    }
  }

  return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(police_perm_change, struct cred *new, const struct cred *old,
             int flags) {
  __u64 time = bpf_ktime_get_ns(); // Get the current time
  __u32 pid = bpf_get_current_pid_tgid();
  __u32 old_uid = old->uid.val;
  __u32 new_uid = new->uid.val;
  __u32 key = 0;
  struct shared_data *data;

  // Get the shared data from the map
  data = bpf_map_lookup_elem(&shared_map, &key);
  if (!data) {
    return 0;
  }

  if ((old_uid != 0) && (old_uid == 1001) && (old_uid != new_uid)) {

    bpf_printk("Reject user with 1001 from changing their uid through setuid() "
               "command");
    // Acquire the spinlock
    bpf_spin_lock(&data->lock);

    // Safely update both fields
    data->reject_count += 1;
    data->last_updated = time;

    // Release the spinlock
    bpf_spin_unlock(&data->lock);
    bpf_printk("Reject count increased from task_fix_setuid: %d",
               data->reject_count);
    return -EPERM;
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
