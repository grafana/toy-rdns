
#include <vmlinux.h>
#include <bpf_tracing.h>
#include "bpf_helpers.h"
#include "bpf_builtins.h"

#define HOSTNAME_MAX_LEN 64

typedef struct dns_entry {
    u8 name[HOSTNAME_MAX_LEN];
    u8 ip[16];
} __attribute__((packed)) dns_entry_t;
// Force emitting struct dns_entry_t into the ELF for automatic creation of Golang struct
const dns_entry_t *unused_dns_entry_t __attribute__((unused));

// The ringbuffer is used to forward messages directly to the user space (Go program)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} resolved SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, char[64]);
    __uint(max_entries, 128);
} ongoing_calls SEC(".maps");

SEC("uprobe/libc.so.6:getaddrinfo")
int BPF_UPROBE(uprobe_getaddrinfo, const char *name,
               const char *service,
               const void *hints, //const struct addrinfo *hints,
               void **pai) {  //struct addrinfo **pai

    u64 id = bpf_get_current_pid_tgid();

    dns_entry_t entry;
    bpf_probe_read_str(entry.name, HOSTNAME_MAX_LEN, name);

    bpf_map_update_elem(&ongoing_calls, &id, entry.name, BPF_ANY);

    return 0;
}


SEC("uretprobe/libc.so.6:getaddrinfo")
int BPF_URETPROBE(uretprobe_getaddrinfo, int ret) {  //struct addrinfo **pai
    u64 id = bpf_get_current_pid_tgid();
    dns_entry_t *entry = bpf_map_lookup_elem(&ongoing_calls, &id);
    if (entry == NULL) {
        return 0;
    }

    dns_entry_t *info = bpf_ringbuf_reserve(&resolved, sizeof(dns_entry_t), 0);
    if (!info) {
        return 0;
    }
    bpf_probe_read_str(info->name, HOSTNAME_MAX_LEN, entry->name);
    bpf_ringbuf_submit(info, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
