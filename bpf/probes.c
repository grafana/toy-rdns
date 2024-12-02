#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_tracing.h>
#include <string.h>

// The ringbuffer is used to forward messages directly to the user space (Go program)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} requests SEC(".maps");

// We start by looking when the SSL handshake is established. In between
// the start and the end of the SSL handshake, we'll see at least one tcp_sendmsg
// between the parties. Sandwitching this tcp_sendmsg allows us to grab the sock *
// and match it with our SSL *. The sock * will give us the connection info that is
// used by the generic HTTP filter.
SEC("uprobe/libc.so.6:getaddrinfo")
int BPF_UPROBE(getaddrinfo,
               const char *name,
               const char *service,
               const struct void *hints,
               struct void **pai) {
               //const struct addrinfo *hints,
               //struct addrinfo **pai) {
    u64 len = strlen(name) + strlen(service) + 1;

    char *info = bpf_ringbuf_reserve(&requests, len, 0);

    memcpy(info, name, strlen(name));
    name[strlen(name)] = ':';
    memcpy(info + strlen(name), service, strlen(service));
    return 0;
}

/*
SEC("uretprobe/libssl.so:SSL_do_handshake")
int BPF_URETPROBE(uretprobe_ssl_do_handshake, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_do_handshake=%d", id);

    bpf_map_delete_elem(&active_ssl_handshakes, &id);

    return 0;
}
*/

char _license[] SEC("license") = "GPL";
