# THE KERNEL-WRITE PRIMITIVE (AppleAVE2 913.43, iOS 27.0 RC 24A435): everything the campaign has proven

> **NOTICE — AI-GENERATED SECURITY RESEARCH** Authorized research on
> the owner's device, coordinated-disclosure aim, crash-oracle discipline. Every claim cites a
> checkable artifact (function + offset + disasm, or a device receipt in a runlog/.ips).
> Labels: **PROVEN** = disassembled both sides + device receipt; **RECEIPT** = on-device evidence;
> **REFUTED** = killed by evidence; **SHAPE** = static reading, not yet device-proven.

## 1. THE WRITE (PROVEN both sides + device receipts)

`AVE_PSGen::Init` (kext sub_87de0b4) executes **THREE linear write loops** in the armed block,
same value `w24`, same count = prop−1 (u32 slots, do-while — ≥1 write at count 0):

| # | base | count source | disasm |
|---|---|---|---|
| 1 | `pClient+0x4678` | `*(pClient+0x3760)` = VPS+8 = `vps_max_sub_layers_minus1` = prop−1 RAW (no clamp) | 0x87de2ec–0x87de30c |
| 2 | `pClient+0x6424` (SPS[0]+0x1fc) | SPS[0]+8 = session+0x3720 — the SAME prop−1 | 0x87de324–0x87de350 |
| 3 | `pClient+0x8098` (SPS[1]+0x1fc, hardcoded 2 layers) | SPS[1]+8 = kext-composed f(prop) = prop+1 (CORRECTION 4) | same, layer-1 iter |

- Loop 1's base lies INSIDE the copied sHEVC_VPS (VPS spans +0x3758..+0x6228): the first
  ~0x1BB0 bytes overwrite the VPS's own per-sub-layer arrays (legit count ≤6), then the
  per-layer SPS/PPS/slice structs, then past the allocation into the pool array and beyond.
- **The 27.2 fix is GATE-ONLY** (the loops are UNCHANGED in 913.64.1, only re-laid): the fixed
  Verify inserts CheckMCTFInfo/CheckLRMEInfo/CheckVPSExtBounds + the `vps_max_sub_layers_minus1
  < 7` family BEFORE the memcpy's — the gates the write bypasses pre-fix.

## 2. THE INPUTS (all device-receipted)

- **Count**: the `NumberOfTemporalLayers` property (public FIG key, on the VT pass-list),
  accepted **unbounded on 27.0** — RECEIPT: `pstat=0` at values 22, 23, 24, 308, 310, 1769, 1792
  (the 10-27 extcal+nosve sweeps). Plugin stores raw at session+0x7c0 → VPS+8 = prop−1.
  On 27.2 the same key returns the NEW `NumberOfTemporalLayers <= 7` setter bound (-2004) = the A/B.
- **Arming = the fire key ALONE** — RECEIPT (10-27 nosve sweep): the fill arms with NO
  EncoderUsage/RCMode pre-props (`err=0`, the session takes the config). EncoderUsage=1 breaks
  the encode hard (-17691) and is unnecessary; `RCMode` is not even on the VT pass-list
  (KL08P dump, 168 keys — returned -12900 in EVERY run, including the v190 panics).
- **Value `w24`** = `min(CalcRefNum(...), max(HEVC_CalcMaxDpbSize(w,h,tier,level),1)-1)`
  ∈ **{1, 9}** (0..15 REFUTED structurally: no plugin writer of session+0xB40/+0xB44 exists —
  binary-wide census, analysis/ave2_plugin_value_knobs.md). All device receipts show w24=1.

## 3. THE VICTIM MAP (PROVEN)

- **pClient**: `AVE_Client_Create` (sub_8739440 @0x8739af0) → `_kalloc_type_impl` view
  `"site._S_AVE_Client"`, size **0x147c8**, flags carry KT_LARGE → **permanent kalloc_large:
  a page-run of 0x18000 = 6×16KiB pages** (usable 0x147c8, slack 0x3838). NOT a zone element.
- **The pool array**: `pcaSurfacePool[0..2]` at **pClient+0x147b0 / +0x147b8 / +0x147c0**
  (the teardown deref victims, decoded from frame 2 `AVE_Client_UninitSurfacePool` @0x8735f14).
- **The fatal consumer chain** (attacker-SCHEDULED — fires at session teardown, no race):
  `AVE_Client_Destroy` → `UninitSurfacePool` → `AVE_SurfacePool::Uninit` (sub_87e5b4c, the
  "AVE_SurfacePool::Uninit Enter" log) → `InitList(pool+0x58)` (sub_86cfce0, `stp x0,x0,[x0]`).

## 4. THE DEVICE RECEIPTS (the write's proof ladder)

1. **R1 — deterministic crash**: 9+ identical panics across 8 boots / 2 kernel slides: the
   full-forge band — `x19/x21 = 0x0000000100000001` (the (w24,w24) = (1,1) pair), `FAR =
   0x100000059`, teardown frames byte-identical (`+0x123AF8/…` all resolve to the chain above).
2. **R2 — THE SURGICAL WRITE (10-27 bisect run)**: ladder {16463, 16464, 16465, 16466, 16468, 16592}:
   - **16463 = CLEAN** (one slot before pool[0] — the control held)
   - **16464 = the single-slot PARTIAL write: panic with `x19 = 1`, `FAR = 0x59`** — ONE w24=1
     write into pool[0]'s LOW half; high half stayed 0 (armed sessions fail the encode → no
     pool allocated → NULL flipped to 1 → deref'd at the COMPUTABLE address 1+0x58).
     **The end-slot math is surgical to ±1 slot ON DEVICE.**
   - 16465+ = the full-forge band (the R1 signature).
   - The real-pointer variant (`FAR = 0xfffffff0_00000059` — partial overwrite of a LIVE pool
     pointer) is SHAPE-predicted, pending a session that encodes.
3. **Extcal sweeps (10-27)**: all 7 gate-band cells (counts 21→1791) NON-CRASH — the first
   fully-clean armed sweep; the fill writing deep into the VPS/ext control fields in-bounds
   (slot 21 max_layer_id, 22 num_layer_sets, 284 num_hrd, **307 the vps_extension gate**,
   1768 add-OLS) with w24≤9 inside 64+ arrays. The fill's collateral is survivable to at least
   slot 1791 in-object.

## 5. CAPABILITIES AND LIMITS (honest)

**Can do (proven):**
- Length: arbitrary u32 count, device-exercised 21..16591+.
- Start: three fixed bases (loop selection: +0x4678 / +0x6424 / +0x8098 — loop 3 binds first,
  bound f(prop)=prop+1).
- End-slot: exact — stop ON a chosen u32 slot (±1 device-proven), or 1 slot past for a full u64 forge.
- Value: 1 or 9 per u32 slot.
- Trigger: deterministic, attacker-scheduled (teardown), repeatable per session.
- Everything between base and end gets w24 (linear stomp — count it as collateral, or use it:
  a contiguous 1-fill of a span IS a usable shape, e.g. zeroing/`1`-ing count fields, matrices).

**Cannot do (proven limits):**
- No pointer forging for code pointers (PAC; small values can't sign) — and `0xfffffff0_N`
  partial results point at unmapped kernel-image space unless the high half survives from a
  REAL pointer (the 16464-on-a-live-pool cell is exactly that experiment).
- No 0..15 value richness (REFUTED structurally).
- Cannot skip collateral between base and the end slot.
- The readback conflict: arming sets VPS+8 = prop−1 (out of 0..6), which kills the encoder →
  no output bitstream from an armed session (RECEIPT: `bytes=0 fp=-` on every armed cell).

## 6. THE LADDER (device-validated geometry, loop-1 binding)

| cell (prop) | landing | receipt |
|---|---|---|
| ≤ 16462 | in-struct (VPS/SPS/PPS span + slack) | clean (extcal: even 1791 slots clean) |
| **16463** | one slot BEFORE pool[0] | **CLEAN (device)** |
| **16464** | pool[0] LOW half only | **partial write — FAR=0x59 (device)** |
| 16465 | pool[0] full u64 | full forge — FAR=0x100000059 (device, R1 band) |
| 16466..16468 | pool[1]/pool[2] | the walk band (ladder staged) |
| ≥ ~16592 | deep pool-forge band | the v190 signature (×9 receipts) |
| ≥ ~20067 (loop-1) / 16347 (loop-3) | past the 0x18000 page-run | adjacent-object territory (spray's arena) |

## 7. WEAPONIZATION PATHS (ranked, from the spec + tonight's receipts)

1. **Single-slot count/size flips in adjacent objects** (the R4 rung): the fix's own consumer
   list is the menu — MCTF/LRME/DMV counts, slice-map iNum, HRD counts. A `0→N` flip in a victim
   count field turns a consumer into a second, value-richer OOB. Needs the spray (below) or the
   adjacent-object calibration walk.
2. **Partial data-pointer overwrite** (16464-class on a LIVE pointer): keep the high half →
   retarget a data pointer inside kernel image / kext mappings; PAC doesn't cover data pointers.
   Requires a session whose pools were allocated (an encoding session — blocked by the VPS+8
   conflict) OR a spray-placed victim with known pointer fields.
3. **Spray mode** (v191, staged, unrun): N filler pClients (same kalloc_large class,
   back-to-back allocations), free the middle, fire into the hole — known-layout victims
   (another session's pClient) at computable offsets.
4. **The contiguous-fill-as-a-shape**: spans of 1s across victim structures (count fields,
  flag bytes, whole config structs) — the collateral becomes the payload when the target
  region is what you want `1`-ed.

## 8. THE A/B (the fixed build)

- App side: `NumberOfTemporalLayers > 7` → **-2004** (the 913.64.1 setter bound).
- Kext side: Verify's new gates (`HEVC VPS count is out of range` log, the `<7/<=64` family)
  reject the blob before the memcpy's → the loops never arm.
- The loops themselves: UNCHANGED (gate-only fix) — the primitive class persists behind the gates.

## 9. ATTRIBUTION

The AVEVideoEncoder advisory family (27.2 GM, support.apple.com/149230): our bug is one of the
four OOB-write CVEs — shape-ranked **CVE-2026-112705** (Calif.io credit; "unexpected system
termination" = the crash-only receipt class) with the Hcamael trio (112470/112469/112468) as
fallback; the R4/MCTF/LRME channel and the DPB walk (Apple's own `N<=16` plugin gate + the
"VCP has mismatch DPB number of frames" fixed-build log) are additional members of the same
gate wave. Exact per-CVE assignment pending Calif's disclosure or credit-level detail.
