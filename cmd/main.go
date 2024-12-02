package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mariomac/pipes/pkg/node"

	tracer "github.com/mariomac/toy-rdns/pkg/ebpf"
)

func main() {
	ho := slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &ho)))
	traceFunc, err := tracer.Trace()
	if err != nil {
		panic(err)
	}
	traceNode := node.AsStart(traceFunc)
	printerNode := node.AsTerminal(func(entries <-chan tracer.BpfDnsEntryT) {
		for entry := range entries {
			fmt.Printf("intercepted %v\n", string(entry.Name[:]))
		}
	})
	traceNode.SendsTo(printerNode)
	slog.Info("Starting main node")
	traceNode.Start()
	wait := make(chan struct{})
	<-wait
}
