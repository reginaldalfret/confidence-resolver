package compiled_module

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	wasmtime "github.com/nicklasl/wasmtime-go/v50"
	"google.golang.org/protobuf/proto"

	"github.com/spotify/confidence-resolver/openfeature-provider/go/confidence/internal/proto/flagswasm"
)

// LogSink receives the concatenated bytes of one WriteFlagLogsRequest
// produced by the module. It is called from inside a WASM call, so it must
// not block, must not re-enter the module, and must not panic; failures are
// the sink's business and must never surface into a resolve. The token to
// attach at delivery time is captured by the caller of NewHost (it is not
// part of the module).
type LogSink func(body []byte)

// Host is one live compiled client module: a wasmtime engine, the module, the
// shared memory the module's flag data lives in, and a single instance entered
// exclusively through a mutex.
//
// The single-instance/single-memory design follows the module contract: the
// flag data is initialized into the shared memory once (by the first
// instantiation's start function) and instances are thin execution contexts.
// All entry into WASM is serialized by one mutex, so the module's internal
// de-duplication and flush locks never contend and memory.atomic.wait never
// blocks a host goroutine.
type Host struct {
	engine   *wasmtime.Engine
	module   *wasmtime.Module
	memory   *wasmtime.SharedMemory
	store    *wasmtime.Store
	instance *wasmtime.Instance
	mod      *Module

	mu sync.Mutex // entry mutex: one WASM call at a time

	alloc  *wasmtime.Func
	frees  *wasmtime.Func
	ackLog *wasmtime.Func

	resolveProcessStart   *wasmtime.Func
	resolveProcessResume  *wasmtime.Func
	resolveProcessDiscard *wasmtime.Func
	applyFlags            *wasmtime.Func
	flushLogs             *wasmtime.Func
	evaluate              *wasmtime.Func
	metricsSnapshot       *wasmtime.Func
	allocatedBytes        *wasmtime.Func
	observeLatency        *wasmtime.Func

	logSink LogSink

	hasMetricsSnapshot bool
	hasAllocatedBytes  bool
	hasObserveLatency  bool
}

// HostConfig carries the host-provided callbacks.
type HostConfig struct {
	// LogSink receives log batches (see LogSink). Required.
	LogSink LogSink
	// Now returns wall-clock milliseconds since the epoch. Optional.
	Now func() int64
	// Seed returns a random value used once per instance. Optional.
	Seed func() int64
	// ApplySeen and SchemaSeen implement the exposure/schema de-duplication
	// imports: they return true when the fingerprint was already reported.
	// Nil disables de-duplication for that namespace (always false).
	ApplySeen  func(fingerprint int64) bool
	SchemaSeen func(fingerprint int64) bool
	// Logger for callback failures. Optional.
	Logger *slog.Logger
}

func (c HostConfig) now() int64 {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UnixMilli()
}

func (c HostConfig) seed() int64 {
	if c.Seed != nil {
		return c.Seed()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UnixNano()
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}

func (c HostConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// NewHost compiles and instantiates a validated module. The returned host is
// ready to resolve; Close tears the instance down.
func NewHost(mod *Module, cfg HostConfig) (*Host, error) {
	if cfg.LogSink == nil {
		return nil, errNilLogSink
	}

	wasmCfg := wasmtime.NewConfig()
	wasmCfg.SetWasmThreads(true)
	wasmCfg.SetSharedMemory(true)
	engine := wasmtime.NewEngineWithConfig(wasmCfg)

	compiled, err := wasmtime.NewModule(engine, mod.Bytes)
	if err != nil {
		engine.Close()
		return nil, err
	}

	limits := mod.info.HostMemoryLimits
	memType, err := wasmtime.NewMemoryType(limits.Initial, limits.HasMax, limits.Maximum, true)
	if err != nil {
		engine.Close()
		return nil, err
	}
	memory, err := wasmtime.NewSharedMemory(engine, memType)
	if err != nil {
		engine.Close()
		return nil, err
	}

	store := wasmtime.NewStore(engine)
	h := &Host{
		engine:             engine,
		module:             compiled,
		memory:             memory,
		store:              store,
		mod:                mod,
		logSink:            cfg.LogSink,
		hasMetricsSnapshot: mod.HasExport("metrics_snapshot"),
		hasAllocatedBytes:  mod.HasExport("allocated_bytes"),
		hasObserveLatency:  mod.HasExport("observe_client_resolve_latency"),
	}

	imports, err := h.buildImports(cfg)
	if err != nil {
		store.Close()
		memory.Close()
		engine.Close()
		return nil, err
	}

	instance, err := wasmtime.NewInstance(store, compiled, imports)
	if err != nil {
		store.Close()
		memory.Close()
		engine.Close()
		return nil, err
	}
	h.instance = instance

	h.alloc = instance.GetFunc(store, "alloc")
	h.frees = instance.GetFunc(store, "free")
	h.ackLog = instance.GetFunc(store, "ack_logs")
	h.resolveProcessStart = instance.GetFunc(store, "resolve_process_start")
	h.resolveProcessResume = instance.GetFunc(store, "resolve_process_resume")
	h.resolveProcessDiscard = instance.GetFunc(store, "resolve_process_discard")
	h.applyFlags = instance.GetFunc(store, "apply_flags")
	h.flushLogs = instance.GetFunc(store, "flush_logs")
	h.evaluate = instance.GetFunc(store, "evaluate")
	h.metricsSnapshot = instance.GetFunc(store, "metrics_snapshot")
	h.allocatedBytes = instance.GetFunc(store, "allocated_bytes")
	h.observeLatency = instance.GetFunc(store, "observe_client_resolve_latency")
	if h.alloc == nil || h.frees == nil || h.ackLog == nil ||
		h.resolveProcessStart == nil || h.resolveProcessResume == nil ||
		h.resolveProcessDiscard == nil || h.applyFlags == nil ||
		h.flushLogs == nil || h.evaluate == nil {
		h.Close()
		return nil, errMissingExport
	}
	return h, nil
}

// buildImports binds exactly the import set the module declares.
func (h *Host) buildImports(cfg HostConfig) ([]wasmtime.AsExtern, error) {
	logger := cfg.logger()
	var imports []wasmtime.AsExtern
	for _, imp := range h.mod.info.Imports {
		key := imp.Module + "." + imp.Name
		switch key {
		case memoryImportModule + "." + memoryImportField:
			imports = append(imports, h.memory)
		case "env.current_time":
			imports = append(imports, wasmtime.WrapFunc(h.store, func() int64 {
				return cfg.now()
			}))
		case "env.random_seed":
			imports = append(imports, wasmtime.WrapFunc(h.store, func() int64 {
				return cfg.seed()
			}))
		case "env.write_logs":
			imports = append(imports, wasmtime.WrapFunc(h.store, func(caller *wasmtime.Caller, payload int64) {
				h.deliverLogs(caller, payload, logger)
			}))
		case "apply_filter.seen":
			seen := cfg.ApplySeen
			imports = append(imports, wasmtime.WrapFunc(h.store, func(fingerprint int64) int32 {
				return boolToI32(seen != nil && seen(fingerprint))
			}))
		case "schema_filter.seen":
			seen := cfg.SchemaSeen
			imports = append(imports, wasmtime.WrapFunc(h.store, func(fingerprint int64) int32 {
				return boolToI32(seen != nil && seen(fingerprint))
			}))
		default:
			return nil, errUnexpectedImport(key)
		}
	}
	return imports, nil
}

// deliverLogs implements the env.write_logs callback: copy the parts out of
// WASM memory while the callback runs, hand the body to the sink, and ack
// exactly once in a finally. It must never throw (a panic would trap the
// in-flight WASM call) and must never re-enter the module other than through
// ack_logs, which is safe from any thread.
func (h *Host) deliverLogs(caller *wasmtime.Caller, payload int64, logger *slog.Logger) {
	acked := false
	defer func() {
		if !acked {
			h.ack(caller, payload)
		}
		if r := recover(); r != nil {
			logger.Error("write_logs callback panicked", "panic", r)
		}
	}()

	ptr, length := unpackSlice(payload)
	if length == 0 {
		return
	}
	data := h.memory.UnsafeData()
	if int(ptr)+int(length) > len(data) {
		logger.Error("write_logs payload out of memory bounds")
		return
	}

	envelope := &flagswasm.WriteLogsPayload{}
	if err := proto.Unmarshal(data[ptr:ptr+length], envelope); err != nil {
		logger.Error("cannot parse write_logs payload", "error", err)
		return
	}

	var body []byte
	for _, part := range envelope.GetParts() {
		pptr, plen := unpackSlice(int64(part))
		if int(pptr)+int(plen) > len(data) {
			logger.Error("write_logs part out of memory bounds")
			return
		}
		body = append(body, data[pptr:pptr+plen]...)
	}
	if len(body) == 0 {
		return
	}
	h.logSink(body)
}

// ack acknowledges a delivered payload. It is called from inside the
// write_logs callback (already inside a WASM call) and therefore takes no
// host lock; the contract allows ack_logs from any thread.
func (h *Host) ack(caller *wasmtime.Caller, payload int64) {
	defer func() {
		// ack_logs must never throw; a failure here is logged and dropped.
		if r := recover(); r != nil {
			slog.Default().Error("ack_logs panicked", "panic", r)
		}
	}()
	ackFn := h.ackLog
	if caller != nil {
		if extern := caller.GetExport("ack_logs"); extern != nil {
			if fn := extern.Func(); fn != nil {
				ackFn = fn
			}
		}
	}
	if ackFn == nil {
		return
	}
	if _, err := ackFn.Call(h.store, payload); err != nil {
		slog.Default().Error("ack_logs failed", "error", err)
	}
}

// Close tears the instance down while the shared memory is still alive, then
// releases the store, memory and engine. It must not be called concurrently
// with in-flight calls (the provider drains first).
func (h *Host) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.instance != nil {
		if fn := h.instance.GetFunc(h.store, "destroy_instance"); fn != nil {
			if _, err := fn.Call(h.store); err != nil {
				slog.Default().Error("destroy_instance failed", "error", err)
			}
		}
		h.instance = nil
	}
	h.store.Close()
	h.memory.Close()
	h.engine.Close()
}

func boolToI32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}
