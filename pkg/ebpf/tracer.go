package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type dns_entry_t -target amd64,arm64 Bpf ../../bpf/rdns.c -- -I../../bpf/include

var log = slog.With(
	slog.String("component", "ebpf.Tracer"),
)

type tracer struct {
	bpfObjects BpfObjects
	uprobe     link.Link
	uretprobe  link.Link
}

func (t *tracer) register() error {
	// Allow the current process to lock memory for eBPF resources.
	log.Debug("Registering eBPF tracer")
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("removing mem lock", "error", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	log.Debug("loading BPF objects")
	if err := LoadBpfObjects(&t.bpfObjects, nil); err != nil {
		verr := &ebpf.VerifierError{}
		if !errors.As(err, &verr) {
			return fmt.Errorf("loading BPF objects: %w", err)
		}
		return fmt.Errorf("loading BPF objects: %w, %s", err, strings.Join(verr.Log, "\n"))
	}

	log.Debug("registering uprobes")
	// TODO: replace
	exec, err := link.OpenExecutable("/usr/lib/aarch64-linux-gnu/libc.so.6")
	if err != nil {
		return fmt.Errorf("opening executable: %w", err)
	}
	t.uprobe, err = exec.Uprobe("getaddrinfo", t.bpfObjects.UprobeGetaddrinfo, nil)
	if err != nil {
		return fmt.Errorf("registering uprobe: %w", err)
	}
	t.uretprobe, err = exec.Uretprobe("getaddrinfo", t.bpfObjects.UretprobeGetaddrinfo, nil)

	return nil
}

func (t *tracer) Close() error {
	var errs []string
	if t.uprobe != nil {
		if err := t.uprobe.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := t.bpfObjects.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("closing BPF resources: '%s'", strings.Join(errs, "', '"))
	}
	return nil
}

func Trace() (func(out chan<- BpfDnsEntryT), error) {
	t := tracer{}
	if err := t.register(); err != nil {
		return nil, fmt.Errorf("registering eBPF tracer: %w", err)
	}
	slog.Debug("creating ringbuf reader")
	rd, err := ringbuf.NewReader(t.bpfObjects.Resolved)
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	return func(out chan<- BpfDnsEntryT) {
		defer t.Close()
		// TODO: set proper context-based cancellation
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Debug("Received signal, exiting..")
					return
				}
				log.Error("reading from ringbuf", err)
				continue
			}
			input := bytes.NewBuffer(record.RawSample)
			dnsEntry := BpfDnsEntryT{}
			if err := binary.Read(input, binary.LittleEndian, &dnsEntry); err != nil {
				log.Error("reading ringbuf event", "error", err)
				continue
			}
			out <- dnsEntry
		}
	}, nil
}
