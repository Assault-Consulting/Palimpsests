"""Engine capabilities and memory configuration — behavior via data.

The orchestration layer must never branch on an engine's concrete type
(``isinstance``). Instead every adapter declares what it can do through
``EngineCapabilities``, and callers read those flags. Adding a new
control level is then a matter of setting flags in one place, not
threading type checks through the call sites.

``EngineMemoryConfig`` is the parallel idea for memory-reduction knobs:
levels 1-2 do not implement these mechanisms, they *expose* the engine
launch parameters that drive them (KV-cache quantization, flash
attention, GPU offload, ...). An adapter that cannot honor a field
ignores it; an adapter that can, validates it.
"""
from __future__ import annotations

from dataclasses import dataclass


class CapabilityUnsupported(Exception):
    """Raised when a caller asks an engine for something it cannot do.

    The "loud refusal" principle applied to capabilities: a level-1
    engine asked to open a stateful session raises this rather than
    silently degrading to something that merely looks similar. The
    message should name the capability and the engine so the failure is
    self-explanatory.
    """


@dataclass(frozen=True)
class EngineCapabilities:
    """What an engine adapter can do. Read by the orchestrator, never
    inferred from the adapter's type.

    ``control_level`` is the coarse tier (1 thin wrapper, 2 embedded, 3
    own service). The booleans are the fine-grained truth the
    orchestrator actually branches on — two level-3 engines might differ
    in which optimizations they've implemented, so the level alone is
    never the gate.
    """

    control_level: int
    streaming: bool = False
    stateful_sessions: bool = False  # holds KV between calls        (L3)
    shared_prefix: bool = False  # shared prefix KV across sessions   (L3)
    server_side_tools: bool = False  # tool-loop without re-prefill   (L3)
    continuous_batching: bool = False  # N sessions in one forward    (L3)
    kv_persistence: bool = False  # KV to/from disk                   (L3)


@dataclass(frozen=True)
class EngineMemoryConfig:
    """Memory-reduction knobs exposed (not implemented) by an adapter.

    These map to engine launch parameters. Levels 1-2 surface the subset
    their backend supports; unsupported fields are ignored by the
    adapter. The one hard rule enforced here is the flash-attention
    prerequisite for KV-cache quantization — without it, quantized KV is
    dequantized every step and becomes slower than no quantization at
    all, so we reject the combination early with a clear error rather
    than let it silently regress performance.
    """

    kv_cache_quant: str | None = None  # None | "q8_0" | "q4_0" | "turbo3"
    flash_attention: bool = False  # PREREQUISITE for kv_cache_quant
    gpu_layers: int | None = None  # -ngl; None = CPU-only
    use_mmap: bool = True
    context_size: int | None = None  # -c; main driver of KV size
    draft_model: str | None = None  # speculative decoding

    def __post_init__(self) -> None:
        if self.kv_cache_quant is not None and not self.flash_attention:
            raise ValueError(
                "kv_cache_quant requires flash_attention=True; without it "
                "the KV cache is dequantized every step and runs slower "
                "than unquantized"
            )
