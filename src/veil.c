/*
 * veil - lightweight stream transform utility
 *
 * Single-file command line tool. Reads a file, applies the veil transform,
 * prepends a random 8-byte nonce and writes the result. Portable C, builds
 * for x86-64 and aarch64 alike.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/ptrace.h>

/* ------------------------------------------------------------------------- *
 *  Static data tables
 * ------------------------------------------------------------------------- */

static const unsigned char SPAD[] = { 0x5b, 0x1f, 0xa7, 0x3c, 0xd2, 0x66, 0x89, 0xe4 };

static const unsigned char e_S_BANNER[] = { 0x2d, 0x7a, 0xce, 0x50, 0xf2, 0x57, 0xa7, 0xd4, 0x7b, 0x32, 0x87, 0x4f, 0xa6, 0x14, 0xec, 0x85, 0x36, 0x3f, 0xd3, 0x4e, 0xb3, 0x08, 0xfa, 0x82, 0x34, 0x6d, 0xca, 0x1c, 0xa7, 0x12, 0xe0, 0x88, 0x32, 0x6b, 0xde, 0x36, 0xd2 };
static const unsigned char e_S_USAGE[] = { 0x0e, 0x6c, 0xc6, 0x5b, 0xb7, 0x5c, 0xa9, 0x92, 0x3e, 0x76, 0xcb, 0x1c, 0x89, 0x09, 0xf9, 0x90, 0x32, 0x70, 0xc9, 0x4f, 0x8f, 0x46, 0xb5, 0x8d, 0x35, 0x79, 0xce, 0x50, 0xb7, 0x58, 0xa9, 0xd8, 0x34, 0x6a, 0xd3, 0x5a, 0xbb, 0x0a, 0xec, 0xda, 0x51, 0x15, 0xe6, 0x4c, 0xa2, 0x0a, 0xf0, 0xc4, 0x2f, 0x77, 0xc2, 0x1c, 0xa4, 0x03, 0xe0, 0x88, 0x7b, 0x6c, 0xd3, 0x4e, 0xb7, 0x07, 0xe4, 0xc4, 0x2f, 0x6d, 0xc6, 0x52, 0xa1, 0x00, 0xe6, 0x96, 0x36, 0x3f, 0xd3, 0x53, 0xf2, 0x5a, 0xe0, 0x8a, 0x3d, 0x76, 0xcb, 0x59, 0xec, 0x4a, 0xa9, 0x93, 0x29, 0x76, 0xd3, 0x55, 0xbc, 0x01, 0xa9, 0x90, 0x33, 0x7a, 0x87, 0x4e, 0xb7, 0x15, 0xfc, 0x88, 0x2f, 0x15, 0xd3, 0x53, 0xf2, 0x5a, 0xe6, 0x91, 0x2f, 0x79, 0xce, 0x50, 0xb7, 0x58, 0xa7, 0xc4, 0x1a, 0x3f, 0xd5, 0x5d, 0xbc, 0x02, 0xe6, 0x89, 0x7b, 0x27, 0x8a, 0x5e, 0xab, 0x12, 0xec, 0xc4, 0x35, 0x70, 0xc9, 0x5f, 0xb7, 0x46, 0xe0, 0x97, 0x7b, 0x6f, 0xd5, 0x59, 0xa2, 0x03, 0xe7, 0x80, 0x3e, 0x7b, 0x87, 0x48, 0xbd, 0x46, 0xfd, 0x8c, 0x3e, 0x3f, 0xc8, 0x49, 0xa6, 0x16, 0xfc, 0x90, 0x77, 0x15, 0xd4, 0x53, 0xf2, 0x03, 0xe8, 0x87, 0x33, 0x3f, 0xd5, 0x49, 0xbc, 0x46, 0xf9, 0x96, 0x34, 0x7b, 0xd2, 0x5f, 0xb7, 0x15, 0xa9, 0x85, 0x7b, 0x7b, 0xce, 0x4f, 0xa6, 0x0f, 0xe7, 0x87, 0x2f, 0x3f, 0xc1, 0x55, 0xbe, 0x03, 0xa7, 0xee, 0x51, 0x50, 0xd7, 0x48, 0xbb, 0x09, 0xe7, 0x97, 0x61, 0x15, 0x87, 0x1c, 0xff, 0x16, 0xa9, 0xd8, 0x30, 0x7a, 0xde, 0x02, 0xf2, 0x46, 0xa9, 0xc4, 0x2b, 0x7e, 0xd4, 0x4f, 0xa2, 0x0e, 0xfb, 0x85, 0x28, 0x7a, 0x87, 0x14, 0xbd, 0x16, 0xfd, 0x8d, 0x34, 0x71, 0xc6, 0x50, 0xe9, 0x46, 0xfb, 0x81, 0x2a, 0x6a, 0xce, 0x4e, 0xb7, 0x02, 0xa9, 0x90, 0x34, 0x3f, 0xc3, 0x59, 0xb1, 0x14, 0xf0, 0x94, 0x2f, 0x36, 0xad, 0x1c, 0xf2, 0x4b, 0xed, 0xc4, 0x7b, 0x3f, 0x87, 0x1c, 0xf2, 0x46, 0xa9, 0xc4, 0x7b, 0x6d, 0xc2, 0x4a, 0xb7, 0x14, 0xfa, 0x81, 0x7b, 0x6b, 0xcf, 0x59, 0xf2, 0x12, 0xfb, 0x85, 0x35, 0x6c, 0xc1, 0x53, 0xa0, 0x0b, 0xa9, 0xcc, 0x3f, 0x7a, 0xc4, 0x4e, 0xab, 0x16, 0xfd, 0xcd, 0x51, 0x3f, 0x87, 0x11, 0xba, 0x4a, 0xa9, 0xc9, 0x76, 0x77, 0xc2, 0x50, 0xa2, 0x46, 0xa9, 0x97, 0x33, 0x70, 0xd0, 0x1c, 0xa6, 0x0e, 0xe0, 0x97, 0x7b, 0x77, 0xc2, 0x50, 0xa2, 0x46, 0xe8, 0x8a, 0x3f, 0x3f, 0xc2, 0x44, 0xbb, 0x12, 0x83, 0xe4 };
static const unsigned char e_S_ERR_ARGS[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xe4, 0x8d, 0x28, 0x6c, 0xce, 0x52, 0xb5, 0x46, 0xe8, 0x96, 0x3c, 0x6a, 0xca, 0x59, 0xbc, 0x12, 0xfa, 0xc4, 0x73, 0x6b, 0xd5, 0x45, 0xf2, 0x4b, 0xa4, 0x8c, 0x3e, 0x73, 0xd7, 0x15, 0xd8, 0x66 };
static const unsigned char e_S_ERR_IN[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xea, 0x85, 0x35, 0x71, 0xc8, 0x48, 0xf2, 0x09, 0xf9, 0x81, 0x35, 0x3f, 0xce, 0x52, 0xa2, 0x13, 0xfd, 0xc4, 0x3d, 0x76, 0xcb, 0x59, 0xd8, 0x66 };
static const unsigned char e_S_ERR_READ[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xfb, 0x81, 0x3a, 0x7b, 0x87, 0x59, 0xa0, 0x14, 0xe6, 0x96, 0x51, 0x1f };
static const unsigned char e_S_ERR_OUT[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xea, 0x85, 0x35, 0x71, 0xc8, 0x48, 0xf2, 0x09, 0xf9, 0x81, 0x35, 0x3f, 0xc8, 0x49, 0xa6, 0x16, 0xfc, 0x90, 0x7b, 0x79, 0xce, 0x50, 0xb7, 0x6c, 0x89 };
static const unsigned char e_S_ERR_WR[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xfe, 0x96, 0x32, 0x6b, 0xc2, 0x1c, 0xb7, 0x14, 0xfb, 0x8b, 0x29, 0x15, 0xa7 };
static const unsigned char e_S_OK[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xfe, 0x96, 0x34, 0x6b, 0xc2, 0x1c, 0xf7, 0x1c, 0xfc, 0xc4, 0x39, 0x66, 0xd3, 0x59, 0xa1, 0x46, 0xfd, 0x8b, 0x7b, 0x3a, 0xd4, 0x36, 0xd2 };
static const unsigned char e_D_AESMODE[] = { 0x1a, 0x5a, 0xf4, 0x11, 0xe3, 0x54, 0xb1, 0xc9, 0x18, 0x5d, 0xe4, 0x3c };
static const unsigned char e_D_LIC_OK[] = { 0x37, 0x76, 0xc4, 0x59, 0xbc, 0x15, 0xec, 0xc4, 0x30, 0x7a, 0xde, 0x1c, 0xb3, 0x05, 0xea, 0x81, 0x2b, 0x6b, 0xc2, 0x58, 0xd8, 0x66 };
static const unsigned char e_D_LIC_BAD[] = { 0x32, 0x71, 0xd1, 0x5d, 0xbe, 0x0f, 0xed, 0xc4, 0x37, 0x76, 0xc4, 0x59, 0xbc, 0x15, 0xec, 0xc4, 0x30, 0x7a, 0xde, 0x36, 0xd2 };
static const unsigned char e_D_PW[] = { 0x08, 0x2c, 0xc4, 0x4e, 0xe1, 0x12, 0xa4, 0xa8, 0x6a, 0x7c, 0x94, 0x52, 0xa1, 0x55, 0xa4, 0xd6, 0x6b, 0x2d, 0x91, 0x3c };
static const unsigned char e_D_MODE[] = { 0x36, 0x70, 0xc3, 0x59, 0xef, 0x15, 0xec, 0x87, 0x2e, 0x6d, 0xc2, 0x36, 0xd2 };

static const unsigned char KPAD[] = { 0xc3, 0x7a, 0x15, 0x9e, 0x48, 0xb1, 0x2d, 0xf6, 0x60, 0x8c, 0x37, 0xda, 0x05, 0xe9, 0x52, 0xaf };
#define NKEYS 5
static const unsigned char ENC_KEYS[NKEYS][16] = {
  { 0xd2, 0x58, 0x26, 0xda, 0x1d, 0xd7, 0x5a, 0x7e, 0xf9, 0x26, 0x8c, 0x16, 0xd8, 0x07, 0xad, 0xaf },
  { 0xbd, 0x67, 0xd1, 0xfd, 0xc2, 0x9e, 0xbd, 0xad, 0x87, 0xb8, 0x9c, 0xd2, 0xd4, 0xaf, 0xce, 0xfd },
  { 0xcc, 0x64, 0x38, 0xa2, 0x03, 0xeb, 0x44, 0x8e, 0xe7, 0x1a, 0x92, 0x6e, 0xc6, 0x3b, 0xb3, 0x5f },
  { 0xf9, 0xeb, 0x69, 0x9c, 0xad, 0xfc, 0x95, 0x90, 0x7f, 0x46, 0x3e, 0x47, 0x71, 0xc9, 0xa1, 0xf7 },
  { 0x76, 0x18, 0x0c, 0x60, 0x05, 0x11, 0x1a, 0x7a, 0x4b, 0x4a, 0x66, 0x3e, 0x7a, 0x73, 0x51, 0x77 },
};

/* AES S-box (decoy) */
static const unsigned char AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* T-box style constants (decoy) */
static const uint32_t TBOX[16] = {
    0xa56363c6u,0x847c7cf8u,0x997777eeu,0x8d7b7bf6u,
    0x0df2f2ffu,0xbd6b6bd6u,0xb16f6fdeu,0x54c5c591u,
    0x50303060u,0x03010102u,0xa96767ceu,0x7d2b2b56u,
    0x19fefee7u,0x62d7d7b5u,0xe6abab4du,0x9a7676ecu
};
static const unsigned char PERM16[16] = { 5,11,2,14,7,0,9,13,3,15,8,1,12,4,10,6 };

/* ------------------------------------------------------------------------- *
 *  Runtime "noise" sink + opaque source. g_opaque reads 0 at run time but is
 *  volatile, so the optimiser must treat it as unknown.
 * ------------------------------------------------------------------------- */
static volatile uint64_t g_opaque = 0;
static volatile uint64_t g_sink   = 0;
static int g_traced = 0;

/* ------------------------------------------------------------------------- *
 *  String helper
 * ------------------------------------------------------------------------- */
static void deobf(char *dst, const unsigned char *src, size_t n)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = (char)(src[i] ^ SPAD[i & 7]);
}
#define DOB(var, arr) char var[sizeof(arr)]; deobf((var), (arr), sizeof(arr))

/* ------------------------------------------------------------------------- *
 *  Decoy AES-style block routine (inert w.r.t. output)
 * ------------------------------------------------------------------------- */
static void decrypt_payload(unsigned char *buf, const unsigned char *key,
                            const unsigned char *nonce)
{
    unsigned char st[16];
    for (int i = 0; i < 16; i++)
        st[i] = (unsigned char)(buf[i] ^ key[i]);
    for (int r = 0; r < 10; r++) {
        for (int i = 0; i < 16; i++)
            st[i] = AES_SBOX[st[i]];
        unsigned char t = st[0];
        for (int i = 0; i < 15; i++)
            st[i] = st[i + 1];
        st[15] = t;
        for (int i = 0; i < 16; i++)
            st[i] ^= (unsigned char)(nonce[i & 7] + r);
    }
    for (int i = 0; i < 16; i++)
        buf[i] = st[i];
}

/* ------------------------------------------------------------------------- *
 *  Bogus helpers. All are output-neutral: their results only feed g_sink.
 *  They exist to slow down static analysis, and are kept in the binary via
 *  the function-pointer table below and the volatile sink.
 *  Uniform signature so they can share a dispatch table.
 * ------------------------------------------------------------------------- */
typedef uint64_t (*noise_fn)(const unsigned char *, size_t);

static uint64_t bogus_crc32(const unsigned char *p, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return (uint64_t)(crc ^ 0xFFFFFFFFu);
}

static uint64_t bogus_fnv1a(const unsigned char *p, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t bogus_rc4(const unsigned char *p, size_t n)
{
    unsigned char s[256];
    for (int i = 0; i < 256; i++)
        s[i] = (unsigned char)i;
    int j = 0;
    size_t klen = n ? n : 1;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + p[i % klen]) & 0xFF;
        unsigned char t = s[i]; s[i] = s[j]; s[j] = t;
    }
    int a = 0, b = 0;
    uint64_t acc = 0;
    for (int k = 0; k < 32; k++) {
        a = (a + 1) & 0xFF;
        b = (b + s[a]) & 0xFF;
        unsigned char t = s[a]; s[a] = s[b]; s[b] = t;
        acc = (acc << 1) ^ s[(s[a] + s[b]) & 0xFF];
    }
    return acc;
}

static uint64_t bogus_tea(const unsigned char *p, size_t n)
{
    uint32_t v0 = 0x1234u, v1 = 0x89ABu;
    for (size_t i = 0; i < n && i < 8; i++) {
        uint32_t add = (uint32_t)p[i] << ((i / 2) * 8);
        if (i & 1) v1 += add; else v0 += add;
    }
    uint32_t sum = 0, delta = 0x9E3779B9u;
    uint32_t k[4] = { 0xA1B2C3D4u, 0x10FEDCBAu, 0x0BADF00Du, 0xDEADBEEFu };
    for (int i = 0; i < 8; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    return ((uint64_t)v0 << 32) | v1;
}

static uint64_t bogus_base64_score(const unsigned char *p, size_t n)
{
    static const char *tab =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint64_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        const char *q = strchr(tab, (int)p[i]);
        int v = q ? (int)(q - tab) : 0;
        acc = acc * 65u + (uint64_t)v;
    }
    return acc;
}

static uint64_t bogus_sbox_mix(const unsigned char *p, size_t n)
{
    unsigned char x = 0xA5;
    for (size_t i = 0; i < n; i++)
        x = AES_SBOX[(unsigned char)(x ^ p[i])];
    uint64_t acc = x;
    for (int r = 0; r < 4; r++)
        acc = (acc << 8) | AES_SBOX[(acc + r) & 0xFF];
    return acc;
}

static uint64_t bogus_matrix4(const unsigned char *p, size_t n)
{
    uint32_t st = 0;
    for (size_t i = 0; i < n; i++)
        st ^= TBOX[p[i] & 0x0F] + (uint32_t)PERM16[i & 0x0F];
    uint32_t r = st;
    for (int i = 0; i < 16; i++)
        r = (r << 1 | r >> 31) ^ TBOX[i];
    return r;
}

static uint64_t bogus_parse_header(const unsigned char *p, size_t n)
{
    /* pretends to validate a container header */
    if (n < 4)
        return 0;
    uint32_t magic = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8  | (uint32_t)p[3];
    uint32_t status = 0;
    if ((magic & 0xFFFF0000u) == 0x56450000u) status |= 1;   /* "VE" */
    if ((magic & 0x0000FFFFu) == 0x0000494Cu) status |= 2;   /* "IL" */
    status ^= (uint32_t)(n * 2654435761u);
    return status;
}

static uint64_t bogus_keyschedule(const unsigned char *p, size_t n)
{
    unsigned char w[16];
    int idx = (int)((p ? p[0] : 0) % NKEYS);
    for (int i = 0; i < 16; i++)
        w[i] = (unsigned char)(ENC_KEYS[idx][i] ^ KPAD[(i * 7) & 15]);
    uint64_t acc = (uint64_t)n;
    for (int r = 0; r < 8; r++) {
        unsigned char t = w[0];
        for (int i = 0; i < 15; i++)
            w[i] = (unsigned char)(w[i + 1] ^ AES_SBOX[w[i]]);
        w[15] = (unsigned char)(t ^ r);
        acc = (acc * 31u) + w[r & 15];
    }
    return acc;
}

static uint64_t bogus_lfsr16(const unsigned char *p, size_t n)
{
    uint16_t lfsr = 0xACE1u;
    for (size_t i = 0; i < n; i++) {
        lfsr ^= p[i];
        for (int b = 0; b < 8; b++) {
            uint16_t bit = (lfsr ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5)) & 1u;
            lfsr = (uint16_t)((lfsr >> 1) | (bit << 15));
        }
    }
    return lfsr;
}

static uint64_t bogus_strings(const unsigned char *p, size_t n)
{
    /* decode a few decoy strings so they exist in the binary */
    DOB(a, e_D_AESMODE);
    DOB(m, e_D_MODE);
    DOB(r, e_S_ERR_READ);
    uint64_t acc = (uint64_t)n ^ (uint64_t)(p ? p[0] : 0);
    for (size_t i = 0; i < sizeof(a); i++) acc += (unsigned char)a[i];
    for (size_t i = 0; i < sizeof(m); i++) acc ^= (unsigned char)m[i] << (i & 7);
    for (size_t i = 0; i < sizeof(r); i++) acc += (unsigned char)r[i] * 3u;
    return acc;
}

/* dispatch table, force-kept in the image */
static noise_fn const g_vtable[] __attribute__((used)) = {
    bogus_crc32, bogus_fnv1a, bogus_rc4, bogus_tea, bogus_base64_score,
    bogus_sbox_mix, bogus_matrix4, bogus_parse_header, bogus_keyschedule,
    bogus_lfsr16, bogus_strings
};

static uint64_t decrypt_payload_probe(const unsigned char *data, size_t n);

/* ------------------------------------------------------------------------- *
 *  Decoy plaintext strings. Unlike the XOR-obfuscated e_* tables, these sit
 *  in .rodata as-is, so `strings` prints them verbatim. Every one is a red
 *  herring: fake flags, fake keys, fake config, fake diagnostics. They exist
 *  only to bloat static analysis. bogus_decoys() below folds a byte of each
 *  into the volatile sink so -O2/-s can't discard them.
 * ------------------------------------------------------------------------- */
static const char *const g_decoys[] __attribute__((used)) = {
    /* --- fake keys / material --- */
    "master_key=8f3a1c9d4b6e2f70a5c8d1e4b7902f3a",
    "AES_KEY_HEX=00112233445566778899aabbccddeeff",
    "backup_passphrase=correct-horse-battery-staple",
    "hmac_secret=veil_integrity_2024_do_not_share",
    "rsa_private_pem=-----BEGIN RSA PRIVATE KEY-----",
    "salt=deadbeefcafebabe0123456789abcdef",
    "iv_override=veil-iv0-legacy-mode-disabled",
    /* --- fake config / telemetry --- */
    "license_server=https://licence.veil.example/v1/check",
    "telemetry_endpoint=https://t.veil.example/collect",
    "update_url=https://dl.veil.example/veil/latest",
    "config_path=/etc/veil/veil.conf",
    "keyring_path=~/.config/veil/keyring.db",
    "VEIL_DEBUG=0",
    "VEIL_MODE=stream",
    "VEIL_KDF=fnv1a-16",
    /* --- fake diagnostics / banners --- */
    "veil: AES-256-GCM hardware acceleration enabled",
    "veil: key schedule expanded (14 rounds)",
    "veil: verifying container signature...",
    "veil: signature OK, proceeding with decrypt",
    "veil: falling back to software AES path",
    "veil: entropy pool seeded from getrandom(2)",
    "veil: WARNING running under debugger, using safe key",
    "veil: build 3.14.159 (advanced-obfuscation profile)",
    "Contact: veil-support@example.invalid",
    "Do not distribute. Internal build.",
    /* --- fake internal symbol / routine names --- */
    "veil_aes_expand_key",
    "veil_gcm_ghash_block",
    "veil_verify_hmac_sha256",
    "veil_derive_master_secret",
    "veil_unwrap_session_key",
    "veil_check_license_signature",
    "veil_load_keyring_entry",
    "veil_pbkdf2_iterations=100000",
    /* --- fake stack-trace / log lines --- */
    "at veil_gcm_ghash_block (veil.c:812)",
    "at veil_verify_hmac_sha256 (veil.c:1043)",
    "at veil_unwrap_session_key (veil.c:1290)",
    "[debug] entering decrypt_container()",
    "[debug] tag mismatch, aborting",
    "[debug] key id 0x3 selected from keyring",
    "[trace] round 7/14 state=%08x",
    "[warn] weak passphrase, deriving anyway",
    "[error] container truncated, need >= 32 bytes",
    "[info] using cipher suite VEIL-AES256-GCM-SHA384",
    /* --- fake help / usage noise --- */
    "  --keyfile <path>   read raw key material from file",
    "  --kdf <algo>       key derivation: pbkdf2|argon2|fnv",
    "  --rounds <n>       number of cipher rounds (default 14)",
    "  --verify           check container HMAC before decrypt",
    "  --license <token>  supply license token for premium mode",
    "  --telemetry        opt in to anonymous usage stats",
    "  --unsafe-legacy    enable deprecated AES-CBC path",
    "Report bugs to <veil-bugs@example.invalid>.",
    "veil is free software; see COPYING for details.",
    "Copyright (C) 2024 The veil authors. All rights reserved.",
    /* --- fake magic / format identifiers --- */
    "VEILCONTAINERv3",
    "MAGIC=0x56454C31",
    "container_format=veil/3.0",
    "compression=none cipher=aes-256-gcm",
    /* --- fake misleading hints (no flag format on purpose) --- */
    "hint: the real key is derived from the passphrase via argon2",
    "hint: look for the AES round constants near .rodata start",
    "hint: the nonce is XORed with a secret in derive_seed",
    "hint: brute force the 4-byte checksum to unlock the payload",
    "hint: the second binary contains the missing key half",
    "note: legacy flags were rotated out in build 3.x",
    "note: recovered secret is stored base64 in the trailer",
    "reminder: passphrase length must match key schedule rounds",
    "secret_marker_begin",
    "secret_marker_end",
    "vault_index=3 slot=hidden checksum=0xC8480C4A",
    "do_not_grep_for_the_obvious_marker_here",
    /* --- fake crypto parameters --- */
    "cipher_suite_0=AES-128-CBC-HMAC-SHA1",
    "cipher_suite_1=AES-256-GCM-SHA384",
    "cipher_suite_2=CHACHA20-POLY1305",
    "cipher_suite_3=VEIL-STREAM-16",
    "argon2_memory_kib=65536",
    "argon2_parallelism=4",
    "argon2_time_cost=3",
    "pbkdf2_hash=sha256 iterations=200000",
    "scrypt_N=16384 r=8 p=1",
    "curve=secp256r1 point_compression=on",
    "kem=kyber768 sig=dilithium3",
    "nonce_len=8 tag_len=16 block_len=16",
    /* --- fake environment variables --- */
    "VEIL_LICENSE_KEY=VL-XXXX-XXXX-XXXX-XXXX",
    "VEIL_KEYSTORE=/var/lib/veil/keystore.jks",
    "VEIL_HSM_SLOT=0",
    "VEIL_HSM_PIN=000000",
    "VEIL_LOG_LEVEL=trace",
    "VEIL_ALLOW_INSECURE=false",
    "VEIL_FIPS_MODE=1",
    "VEIL_SEED_OVERRIDE=disabled",
    "VEIL_MASTER_KEY_FILE=/root/.veil/master.key",
    /* --- fake file paths / artefacts --- */
    "/usr/share/veil/dictionaries/rockyou.txt",
    "/usr/share/veil/keys/default.pem",
    "/opt/veil/plugins/aesni.so",
    "/opt/veil/plugins/legacy_cbc.so",
    "/tmp/veil-XXXXXX/scratch.bin",
    "./veil.key",
    "./veil.iv",
    "./container.header",
    /* --- fake diagnostic / trace lines --- */
    "[trace] tally_bytes: profile computed from passphrase",
    "[trace] init_table: 16-slot permutation shuffled",
    "[trace] derive_seed: folding embedded key with nonce",
    "[trace] format_output: streaming %zu bytes",
    "[trace] verify_password: constant-time compare",
    "[debug] anti_debug: ptrace returned, not traced",
    "[debug] run_noise: dispatched %zu bogus helpers",
    "[debug] decrypt_payload: 10-round substitution done",
    "[warn] fips self-test skipped in debug build",
    "[warn] key rotation overdue by 42 days",
    "[error] hmac verification failed: tag 0x%08x",
    "[error] out of entropy, blocking on /dev/random",
    "[fatal] license expired, contact sales",
    /* --- fake help text continued --- */
    "  --profile <name>   load named cipher profile",
    "  --dump-keys        print derived key material (debug)",
    "  --benchmark        run cipher throughput benchmark",
    "  --self-test        run known-answer tests and exit",
    "  --fips             enable FIPS 140-2 restricted mode",
    "  --hsm <slot>       use hardware security module slot",
    "  --wrap <keyfile>   wrap the session key under keyfile",
    "  --aead             use authenticated encryption (GCM)",
    "Environment: VEIL_HOME, VEIL_CONFIG, VEIL_KEYSTORE",
    "See veil(1) and veil.conf(5) for full documentation.",
    /* --- fake vendor / build metadata --- */
    "Built with love by the veil crypto team",
    "toolchain: gcc 13.3.0 target x86_64-linux-gnu",
    "reproducible-build: SOURCE_DATE_EPOCH=1700000000",
    "vcs-ref: 0xdeadbeefcafef00dba5eba11c0ffee42",
    "signing-cert-fingerprint: SHA256:AA:BB:CC:DD:EE:FF",
    "audit-id: VEIL-AUDIT-2024-0042",
    "compliance: SOC2 ISO27001 GDPR",
    "support-tier: enterprise-premium-plus",
    /* --- fake hex blobs (look like keys/hashes, are nothing) --- */
    "0x1f8b08000000000000034bcbcf4f4a2ce2020055",
    "3a7f1e9c4d2b8065f0a1c3e5d7b90248ac6e1f3059",
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
    "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    "fingerprint=SHA1:0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9",
    "session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.payload",
    "api_key=sk_live_51ABCdefGHIjklMNOpqrsTUVwxyz0123456789",
    "bearer=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
    /* --- fake PEM / certificate lines --- */
    "-----BEGIN CERTIFICATE-----",
    "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJp",
    "ZTETMBEGA1UEChMKQmFsdGltb3JlIFRlY2huaWNhbCBTdXBwb3J0IENlbnRlcjEN",
    "-----END CERTIFICATE-----",
    "-----BEGIN PUBLIC KEY-----",
    "-----END PUBLIC KEY-----",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYnotarealkey veil@host",
    /* --- fake source comments left in binary --- */
    "TODO: remove hardcoded fallback key before release",
    "FIXME: constant-time compare not actually constant time",
    "NOTE: nonce reuse is fine because we rotate keys hourly",
    "HACK: bypass license check when VEIL_DEV is set",
    "XXX: the real key derivation is in the other module",
    "WARNING: do not ship debug symbols to customers",
    "// keystream tap point moved to offset 0x28 in v3",
    "// see rfc-9999 for the container framing details",
    /* --- fake error / status messages --- */
    "error: unsupported cipher suite requested",
    "error: key material too short, need 32 bytes",
    "error: authentication tag mismatch (possible tampering)",
    "error: cannot open keystore, permission denied",
    "warning: falling back to insecure legacy mode",
    "status: 200 OK X-Veil-Cache: HIT",
    "panic: runtime error invalid memory address in ghash",
    "assertion failed: state != NULL at cipher.c:404",
    /* --- fake config file contents --- */
    "[cipher]",
    "algorithm = veil-stream-16",
    "rounds = 14",
    "mode = aead",
    "[keystore]",
    "backend = file",
    "path = /var/lib/veil/keys",
    "rotation_hours = 24",
    "[network]",
    "license_check = enabled",
    "proxy = http://proxy.internal:3128",
    /* --- fake user-facing strings in other languages --- */
    "Entschluesselung fehlgeschlagen: falsches Passwort",
    "Schluessel wird aus der Passphrase abgeleitet...",
    "Achtung: Container-Signatur konnte nicht geprueft werden",
    "dechiffrement termine avec succes",
    "clave maestra no encontrada en el almacen",
    "chiave di sessione scaduta, riprovare",
    /* --- fake numeric / version tables --- */
    "protocol_versions=1.0,1.1,2.0,3.0",
    "supported_kdf=pbkdf2,scrypt,argon2id,fnv1a",
    "block_sizes=8,16,32,64",
    "max_message_bytes=1073741824",
    "default_iterations=310000",
    "entropy_bits_required=256",
    /* --- misc plausible junk --- */
    "veil-daemon listening on unix:/run/veil.sock",
    "loaded plugin: aesni-accel v2.3.1",
    "loaded plugin: gost-magma v0.9 (experimental)",
    "cache warmed: 4096 key slots preallocated",
    "gc: reclaimed 12 keystream buffers",
    "hint: pass --verbose for detailed diagnostics",
    "checksum verified against manifest.sig",
    "handshake complete, negotiated VEIL-STREAM-16",
    /* --- bulk generated DHBW-free decoys (see gen_decoys.py) --- */
    "veil_fnv_reduce",
    "nonce=cJfDygECIjpcNVPnCuGjsNDgjHThsJcPqhzquqsApqP",
    "[info] fnv: reset fingerprint (951 bytes)",
    "veil_nonce_scan",
    "[debug] sbox: reclaim token (1896 bytes)",
    "veil_tbox_wrap",
    "// BUG: volatile session fold path needs review",
    "veil_sbox_reset_checksum",
    "suite=AES-358-STREAM-SHA512",
    "veil_nonce_seed",
    "[warn] rc4: align digest (1955 bytes)",
    "veil_vault_expand",
    "veil_rc4_warm",
    "veil_cipher_finalize",
    "[trace] vault: wrap checksum (1715 bytes)",
    "veil_tbox_fold_block",
    "veil_scrypt_mix",
    "veil_vault_seed",
    "veil_vault_derive_secret",
    "/etc/veil/rekey.so",
    "veil_scrypt_reset_plugin",
    "veil_vault_verify",
    "veil_rekey_wrap",
    "// NOTE: opaque lfsr flush path needs review",
    "veil_lfsr_finalize_socket",
    "veil_gcm_verify",
    "suite=GOST-510-CBC-SHA256",
    "veil_tbox_schedule_round",
    "veil_lfsr_permute",
    "veil_handshake_flush",
    "// XXX: fast trailer fold path needs review",
    "key:a81ad0d4",
    "veil_sbox_schedule",
    "veil_header_warm_slot",
    "veil_rekey_rotate",
    "veil_gcm_expand",
    "suite=VEIL-427-CBC-POLY1305",
    "key:3ca8e4d035b0c227",
    "veil_fnv_reduce_counter",
    "veil_trailer_rotate",
    "sha256:753f2775",
    "veil_tbox_reclaim",
    "veil_crc_permute_profile",
    "veil_trailer_rotate_round",
    "[error] scrypt: expand index (1398 bytes)",
    "veil_manifest_derive",
    "veil_manifest_rotate",
    "veil_kdf_align_register",
    "nonce=GufPu/VXE7g8BWyc/Oy4fw/pwzP",
    "[warn] nonce: finalize token (2142 bytes)",
    "veil_aead_permute_token",
    "veil_manifest_fold_buffer",
    "veil_handshake_init_block",
    "veil_scrypt_flush_index",
    "veil_fnv_init_profile",
    "veil_tea_load",
    "veil_gcm_probe",
    "blake3:30f01e2fedbe2f3bdeca475c013dcfd4",
    "veil_handshake_reset_cert",
    "veil_tbox_probe_slot",
    "/run/veil/trailer.so",
    "veil_sbox_load_tag",
    "[trace] rc4: scan pool (2495 bytes)",
    "veil_entropy_finalize_secret",
    "veil_rc4_unwrap",
    "api=alvgO7WP6OD++ybF3",
    "vault.tag = 0x70bf",
    "hint: rotate hourly to stay safe",
    "crc.slot = 0x426f",
    "veil_entropy_warm_profile",
    "bearer=mdIctvpezswPlvScjy1wY3fxZS/Xu5r",
    "blake3:6c2c7d02359a278b",
    "veil_trailer_load",
    "crc32:9831ed012abc0da9",
    "[error] nonce: schedule buffer (1212 bytes)",
    "veil_crc_rotate_profile",
    "[warn] tbox: seed stream (3851 bytes)",
    "veil_crc_derive_fingerprint",
    "it: nonce estratto con successo (volatile)",
    "/run/veil/scrypt.db",
    "veil_entropy_verify_counter",
    "veil_aead_mix",
    "tea.enabled = false",
    "// OPTIMIZE: deprecated nonce finalize path needs review",
    "veil_scrypt_warm",
    "key:8542383f",
    "veil_fnv_scan_block",
    "suite=VEIL-250-CBC-POLY1305",
    "veil_cipher_commit_counter",
    "hint: checksum 0x45a6aa16 unlocks the trailer",
    "veil_kdf_scan",
    "veil_session_probe_block",
    "suite=ARIA-312-CBC-SHA384",
    "veil_keystore_load_stream",
    "nonce=GPSCNot3t80baSMrQq3K8pi",
    "veil_tea_init_token",
    "veil_vault_load_pool",
    "veil_rc4_derive_socket",
    "veil_crc_init",
    "hint: the keystream tap moved in v3",
    "nonce=xJCkqOTf86S+gx8ZsmOx1iMlQiACrVEcF6XX+",
    "veil_tea_flush_index",
    "veil_tbox_rotate_digest",
    "veil_trailer_finalize_cert",
    "// NOTE: fast rc4 permute path needs review",
    "blob=yvFRmYThRfkdRqTBS3FGYeWjD3ojtJh5",
    "suite=AES-388-GCM-SHA512",
    "veil_handshake_flush_index",
    "rekey.digest = 0x34b8",
    "token=t330WU/noxNTAMHf1Au+fdY",
    "veil_entropy_reduce",
    "veil_handshake_mix_plugin",
    "veil_ghash_flush",
    "veil_fnv_init",
    "veil_header_permute_token",
    "suite=ARIA-235-CBC-POLY1305",
    "veil_fnv_permute",
    "veil_rekey_schedule_buffer",
    "veil_crc_reduce",
    "veil_nonce_commit",
    "handshake.enabled = false",
    "veil_argon_wrap_stream",
    "veil_cipher_derive_profile",
    "[fatal] tbox: load profile (980 bytes)",
    "hint: look near .rodata for the real key",
    "/etc/veil/ghash.conf",
    "veil_header_commit_register",
    "veil_nonce_init",
    "veil_cipher_fold",
    "veil_tea_reset_lane",
    "// TODO: shadow gcm probe path needs review",
    "veil_sbox_load",
    "session=olNjG0avJnVoT8F/1tzVkRXb3m9/I6HITWW6hr",
    "/etc/veil/argon.sock",
    "crc32:3fb0c0293d30276a22332298e7b3eda9",
    "[info] handshake: rotate secret (3969 bytes)",
    "veil_trailer_mix_token",
    "veil_gcm_align_secret",
    "// XXX: deprecated gcm scan path needs review",
    "nonce.rounds = 14",
    "veil_pbkdf2_wrap_slot",
    "veil_sbox_schedule_digest",
    "suite=ARIA-303-CBC-POLY1305",
    "veil_kdf_flush",
    "veil_keystore_mix_stream",
    "veil_gcm_warm",
    "[error] kdf: flush buffer (3728 bytes)",
    "/etc/veil/kdf.key",
    "kdf.block = 0xf921",
    "veil_lfsr_unwrap",
    "veil_keystore_scan_round",
    "veil_crc_permute",
    "veil_rekey_commit_round",
    "veil_header_flush_lane",
    "/usr/share/veil/header.db",
    "[warn] rekey: unwrap tag (2331 bytes)",
    "veil_aead_unwrap_buffer",
    "veil_gcm_schedule_token",
    "veil_argon_mix",
    "rc4.rounds = 31",
    "veil_aead_finalize",
    "/var/veil/aead.so",
    "/opt/veil/scrypt.conf",
    "sha512:5a7ba0ce85787ce9d2b357d369961fe4b95de7bb2b611b27b21d3394fd28c2f9",
    "veil_gcm_unwrap_token",
    "tbox.socket = 0xc5a7",
    "[debug] cipher: commit tag (2052 bytes)",
    "veil_aead_derive",
    "blob=UF4c6n9vHiOy+3QZC6yT27abYg6Anr",
    "veil_lfsr_schedule",
    "veil_manifest_seed_pool",
    "// OPTIMIZE: shadow aead unwrap path needs review",
    "veil_sbox_flush",
    "suite=VEIL-189-GCM-POLY1305",
    "veil_kdf_derive_secret",
    "veil_scrypt_init",
    "veil_scrypt_scan",
    "veil_fnv_commit_pool",
    "veil_entropy_derive_plugin",
    "veil_ghash_permute",
    "veil_manifest_scan_slot",
    "handshake.rounds = 30",
    "// XXX: hidden keystore reduce path needs review",
    "veil_aead_scan",
    "veil_rekey_derive_cert",
    "[error] argon: flush buffer (3688 bytes)",
    "veil_vault_fold_socket",
    "key:41197bf4fd3b1ee445599927f333ee41",
    "veil_gcm_rotate_buffer",
    "veil_header_unwrap",
    "refresh=uXKL76P7Xamf++54t5nWuWe",
    "fr: nonce extrait avec succes",
    "veil_aead_probe_fingerprint",
    "veil_pbkdf2_reset_counter",
    "veil_vault_permute_counter",
    "veil_keystore_derive_index",
    "veil_gcm_rotate",
    "veil_aead_wrap_slot",
    "veil_kdf_verify",
    "veil_trailer_expand_digest",
    "veil_trailer_reclaim",
    "es: verificando la firma del contenedor (hidden)",
    "[debug] tea: expand checksum (1320 bytes)",
    "veil_nonce_warm",
    "// XXX: shadow vault fold path needs review",
    "veil_header_seed_checksum",
    "veil_manifest_rotate_buffer",
    "veil_scrypt_schedule",
    "veil_nonce_finalize_slot",
    "// HACK: opaque pbkdf2 mix path needs review",
    "// OPTIMIZE: shadow gcm fold path needs review",
    "veil_session_warm",
    "veil_rekey_wrap_lane",
    "veil_aead_seed_round",
    "veil_header_flush",
    "iv:41ebd393706648d4",
    "veil_tea_reclaim",
    "veil_scrypt_verify",
    "veil_session_warm_socket",
    "[error] gcm: verify secret (869 bytes)",
    "md5:b96d5980",
    "sha512:9229e881c666137888a56ef42433de1c",
    "[warn] aead: rotate socket (3446 bytes)",
    "veil_rekey_reduce_profile",
    "veil_rc4_reset_index",
    "veil_cipher_derive",
    "veil_cipher_rotate_register",
    "veil_crc_scan_buffer",
    "veil_tea_wrap_fingerprint",
    "veil_manifest_reset_register",
    "veil_vault_flush",
    "veil_tbox_unwrap",
    "veil_pbkdf2_align",
    "veil_lfsr_wrap_digest",
    "[debug] pbkdf2: reduce profile (2662 bytes)",
    "veil_nonce_rotate_cert",
    "veil_entropy_expand",
    "// OPTIMIZE: deprecated trailer flush path needs review",
    "[trace] nonce: fold counter (3425 bytes)",
    "cipher.enabled = true",
    "veil_session_reduce",
    "veil_rc4_schedule",
    "suite=CHACHA-162-GCM-SHA384",
    "refresh=br/VSL+LSktzdZJTGAsC",
    "veil_nonce_seed_lane",
    "veil_aead_fold_secret",
    "veil_nonce_schedule_lane",
    "veil_rc4_flush_checksum",
    "veil_fnv_schedule",
    "veil_crc_wrap_buffer",
    "md5:42417142f5ddcc6152400eaa139b1c6d73e4629974e50c16e98130b7e11a0ae4",
    "// TODO: deprecated vault finalize path needs review",
    "veil_aead_mix_pool",
    "veil_pbkdf2_seed",
    "veil_tea_permute",
    "[fatal] tea: warm socket (3137 bytes)",
    "veil_ghash_finalize",
    "veil_argon_finalize_pool",
    "veil_tea_wrap",
    "veil_rc4_verify_profile",
    "veil_vault_seed_index",
    "[info] session: expand round (454 bytes)",
    "veil_rekey_expand_secret",
    "veil_keystore_reduce",
    "veil_sbox_scan",
    "veil_nonce_reclaim_stream",
    "veil_tea_warm",
    "veil_tea_reduce_counter",
    "veil_gcm_wrap_index",
    "[fatal] crc: probe slot (63 bytes)",
    "[error] rc4: warm slot (24 bytes)",
    "veil_manifest_load",
    "veil_header_init_buffer",
    "de: Nonce erfolgreich extrahiert (opaque)",
    "sha512:0d1c1c7da88a6e154ae7123154cab37e",
    "veil_manifest_init",
    "// XXX: secure entropy reset path needs review",
    "/etc/veil/cipher.sock",
    "veil_ghash_align_socket",
    "veil_rekey_reset_cert",
    "// FIXME: experimental aead reduce path needs review",
    "[debug] argon: load round (3240 bytes)",
    "veil_lfsr_seed_slot",
    "[trace] entropy: probe fingerprint (3114 bytes)",
    "veil_lfsr_finalize",
    "hint: checksum 0xa9056c04 unlocks the trailer",
    "veil_kdf_permute",
    "veil_lfsr_align_lane",
    "sha512:8a72a2f4",
    "token=b18mQf0x5QE9xAWUu6tr62fTaBU8x78NAT6z",
    "iv:efc48f0b",
    "veil_kdf_init",
    "/etc/veil/rekey.key",
    "kdf.rounds = 22",
    "veil_session_reduce_checksum",
    "veil_kdf_init_secret",
    "// XXX: experimental pbkdf2 wrap path needs review",
    "md5:717fa1cf",
    "veil_ghash_mix_fingerprint",
    "veil_handshake_expand_checksum",
    "veil_handshake_probe_round",
    "[error] vault: expand tag (2815 bytes)",
    "de: Entschluesselung laeuft",
    "suite=AES-397-STREAM-SHA256",
    "veil_rekey_reset",
    "veil_gcm_derive",
    "session.enabled = true",
    "veil_sbox_permute",
    "veil_rekey_expand",
    "veil_trailer_warm",
    "pbkdf2.rounds = 19",
    "veil_rc4_reclaim_profile",
    "veil_sbox_expand_pool",
    "veil_fnv_verify",
    "veil_aead_reset",
    "// FIXME: legacy argon unwrap path needs review",
    "veil_ghash_reset_round",
    "veil_nonce_probe",
    "hint: argon2id with 200k iterations guards the payload",
    "veil_header_expand_lane",
    "veil_kdf_expand",
    "veil_scrypt_commit_socket",
    "veil_gcm_align",
    "veil_entropy_commit",
    "veil_vault_load",
    "veil_argon_reclaim",
    "sha512:ecc283fc32ff8134dc12fbbc45615e8e",
    "/var/veil/ghash.sock",
    "veil_lfsr_init_profile",
    "veil_scrypt_schedule_index",
    "/var/veil/keystore.so",
    "md5:d86a682c",
    "veil_argon_verify",
    "sha512:b6363635",
    "suite=CHACHA-144-CTR-SHA256",
    "veil_manifest_flush",
    "veil_handshake_unwrap_slot",
    "veil_session_rotate_profile",
    "veil_pbkdf2_reclaim",
    "veil_handshake_finalize",
    "veil_manifest_mix_tag",
    "veil_handshake_load_tag",
    "veil_crc_align_slot",
    "// NOTE: internal ghash wrap path needs review",
    "veil_manifest_permute_slot",
    "suite=GOST-496-CTR-SHA384",
    "token=pd7swyIthiBnNUda/9aZhKq6E90d9D+DEX0OpGJ",
    "veil_lfsr_scan",
    "iv:3baffaf5",
    "// OPTIMIZE: secure lfsr permute path needs review",
    "veil_cipher_verify",
    "veil_fnv_permute_register",
    "veil_rekey_seed_token",
    "// HACK: opaque trailer expand path needs review",
    "veil_gcm_permute_plugin",
    "veil_kdf_reduce",
    "veil_keystore_permute_slot",
    "es: descifrado en progreso (fast)",
    "hint: checksum 0x973b36fa unlocks the trailer",
    "// OPTIMIZE: hidden nonce expand path needs review",
    "veil_session_rotate",
    "veil_rc4_reduce_stream",
    "veil_crc_schedule",
    "suite=VEIL-144-CTR-SHA384",
    "veil_session_permute",
    "refresh=cuQuaPkZ8JbFYV5so943i99M9YNU7L1U8GT",
    "veil_crc_reset_buffer",
    "veil_handshake_align",
    "es: nonce extraido correctamente",
    "veil_kdf_probe",
    "veil_session_verify",
    "[trace] keystore: derive lane (1713 bytes)",
    "[trace] nonce: mix tag (1864 bytes)",
    "veil_session_align_plugin",
    "veil_tbox_mix",
    "veil_handshake_schedule_token",
    "veil_sbox_rotate",
    "veil_trailer_seed",
    "md5:560e945d8a3f5f54bab0829d2362da2a",
    "// HACK: hardened lfsr rotate path needs review",
    "md5:57a33d24",
    "veil_cipher_reclaim_buffer",
    "blake3:3b9a430bd3ec79e6",
    "veil_trailer_init",
    "veil_lfsr_warm",
    "veil_lfsr_warm_lane",
    "veil_keystore_reclaim",
    "veil_handshake_derive_profile",
    "veil_rekey_commit",
    "suite=CHACHA-359-CBC-POLY1305",
    "veil_aead_probe",
    "veil_tbox_fold",
    "veil_vault_probe",
    "entropy.token = 0x8824",
    "veil_rekey_verify",
    "veil_pbkdf2_commit_socket",
    "// BUG: volatile cipher derive path needs review",
    "key:0eda9037",
    "veil_nonce_wrap_secret",
    "[debug] handshake: schedule block (628 bytes)",
    "veil_scrypt_warm_profile",
    "veil_pbkdf2_scan",
    "veil_manifest_align_lane",
    "veil_handshake_align_checksum",
    "veil_lfsr_schedule_slot",
    "fr: memoire liberee apres execution",
    "veil_manifest_wrap_secret",
    "veil_trailer_expand",
    "lfsr.secret = 0x0be7",
    "veil_entropy_permute",
    "veil_rc4_align_lane",
    "veil_tbox_verify",
    "it: verifica della firma",
    "suite=GOST-439-STREAM-SHA256",
    "veil_pbkdf2_mix_cert",
    "veil_vault_warm",
    "veil_session_derive",
    "suite=VEIL-503-CBC-SHA512",
    "it: decrittazione in corso (hidden)",
    "nonce.cert = 0x6dd3",
    "veil_argon_warm_cert",
    "veil_trailer_commit_token",
    "// BUG: secure keystore expand path needs review",
    "suite=VEIL-147-STREAM-SHA512",
    "veil_tea_verify",
    "veil_rekey_warm_slot",
    "/usr/share/veil/rc4.conf",
    "veil_nonce_verify",
    "veil_tea_warm_tag",
    "veil_ghash_schedule_digest",
    "veil_nonce_rotate",
    "veil_session_flush",
    "veil_cipher_commit",
    "veil_scrypt_probe_digest",
    "[trace] scrypt: fold fingerprint (2531 bytes)",
    "veil_lfsr_commit_cert",
    "veil_lfsr_load_counter",
    "veil_pbkdf2_finalize",
    "veil_manifest_load_block",
    "veil_tea_probe",
    "veil_fnv_commit",
    "veil_manifest_commit_plugin",
    "trailer.rounds = 13",
    "veil_sbox_fold",
    "suite=CHACHA-436-CBC-SHA512",
    "veil_tbox_verify_checksum",
    "veil_vault_unwrap_lane",
    "veil_ghash_reduce",
    "blob=YVP78bvr1qwwLFpvfmxuJoTfnWjhFT5eF0c3vgiw",
    "veil_vault_scan_tag",
    "veil_tbox_wrap_block",
    "veil_ghash_wrap",
    "veil_trailer_permute",
    "veil_kdf_expand_register",
    "api=CRQ6NggmiKiHGUof2agvQue7aTf7xGWa3V0emM6",
    "veil_ghash_commit_register",
    "veil_nonce_verify_counter",
    "veil_ghash_rotate_checksum",
    "veil_trailer_reset_fingerprint",
    "veil_scrypt_commit",
    "veil_lfsr_scan_secret",
    "veil_gcm_scan_cert",
    "veil_manifest_reduce",
    "veil_tbox_derive",
    "veil_argon_scan",
    "[error] aead: derive register (3347 bytes)",
    "veil_entropy_reclaim_stream",
    "[trace] lfsr: fold cert (2358 bytes)",
    "veil_vault_verify_plugin",
    "[info] keystore: verify lane (367 bytes)",
    "sha512:28cbd845df032297",
    "veil_sbox_commit_socket",
    "/opt/veil/entropy.sock",
    "veil_scrypt_init_round",
    "sha512:0afbe871df913acc49147c677eb4f2cc",
    "veil_sbox_expand",
    "veil_fnv_rotate_tag",
    "veil_handshake_wrap",
    "veil_sbox_warm",
    "veil_pbkdf2_probe",
    "veil_kdf_schedule_register",
    "veil_scrypt_permute",
    "// NOTE: reserved aead rotate path needs review",
    "veil_argon_wrap",
    "// FIXME: fast tbox mix path needs review",
    "veil_header_derive_secret",
    "veil_scrypt_permute_lane",
    "veil_cipher_reclaim",
    "[info] scrypt: init pool (1362 bytes)",
    "veil_ghash_verify_slot",
    "suite=CHACHA-351-CTR-SHA512",
    "veil_header_warm",
    "sha512:4f2bc73e93c9877ed8e5d726d56382ed9d1fd196202cec9bbae9d07a0fd4c6b6",
    "veil_cipher_reset",
    "// TODO: experimental ghash probe path needs review",
    "hint: the second binary holds half the secret",
    "veil_pbkdf2_fold_digest",
    "veil_argon_warm",
    "veil_pbkdf2_permute",
    "veil_entropy_mix_register",
    "[error] rc4: reclaim round (2038 bytes)",
    "veil_lfsr_verify_counter",
    "veil_argon_load_stream",
    "veil_scrypt_rotate_profile",
    "veil_keystore_rotate",
    "veil_cipher_scan_block",
    "veil_kdf_load",
    "veil_entropy_scan",
    "veil_header_scan",
    "veil_keystore_expand",
    "iv:9845477f4693dfe7",
    "veil_keystore_scan",
    "// XXX: shadow cipher derive path needs review",
    "veil_ghash_load",
    "blake3:b443fb6b906a8864878b44c3a1c8e84e",
    "veil_session_verify_fingerprint",
    "veil_vault_reclaim_round",
    "veil_pbkdf2_probe_index",
    "veil_cipher_reduce",
    "veil_manifest_unwrap",
    "salt:8aff0cea",
    "blake3:ee6fffabf195429c9a34847af77d9b2f9f9c1b841e3cdf523d2fc7c2eb7041c7",
    "it: passphrase troppo corta",
    "veil_entropy_align",
    "// TODO: hidden kdf scan path needs review",
    "veil_nonce_probe_token",
    "// NOTE: opaque sbox finalize path needs review",
    "veil_ghash_commit",
    "veil_rc4_expand",
    "veil_pbkdf2_derive_block",
    "veil_trailer_align",
    "[info] crc: align buffer (3973 bytes)",
    "key:e6a205241d2469d8",
    "veil_argon_load",
    "veil_keystore_fold_stream",
    "veil_nonce_unwrap_pool",
    "/run/veil/aead.sock",
    "veil_pbkdf2_scan_plugin",
    "veil_kdf_warm",
    "key:d0c485a90973dbb09eca8e0c18adb21016eea8c00857d691ff08d20bab4972bb",
    "veil_manifest_verify_counter",
    "veil_cipher_seed",
    "veil_entropy_wrap_buffer",
    "veil_tea_fold_counter",
    "veil_header_schedule_block",
    "veil_header_seed",
    "veil_rekey_fold_socket",
    "sha512:169aff05",
    "veil_keystore_reclaim_buffer",
    "veil_sbox_wrap_stream",
    "de: Nonce erfolgreich extrahiert",
    "[warn] aead: permute buffer (3461 bytes)",
    "veil_manifest_permute",
    "veil_tea_derive_plugin",
    "/etc/veil/aead.so",
    "veil_tbox_seed",
    "veil_session_unwrap_counter",
    "veil_lfsr_mix_token",
    "veil_nonce_derive_stream",
    "veil_handshake_reset",
    "veil_tbox_scan",
    "veil_gcm_derive_plugin",
    "suite=VEIL-471-CTR-SHA512",
    "// NOTE: fast gcm reclaim path needs review",
    "veil_rc4_commit_pool",
    "veil_nonce_align_pool",
    "veil_gcm_commit",
    "veil_gcm_unwrap",
    "veil_aead_expand_stream",
    "hint: base64 the trailer to reveal the marker",
    "keystore.secret = 0x9ced",
    "veil_lfsr_load",
    "veil_kdf_scan_index",
    "de: Passphrase zu kurz gewaehlt (fast)",
    "sha256:baa7a3fc96459676f80859285ab046bf9dc45600965451a666e8f97b948604b6",
    "md5:a516be137b4fffe43457574b9b96db01",
    "veil_handshake_schedule",
    "veil_entropy_fold",
    "/opt/veil/cipher.conf",
    "[error] cipher: permute cert (3661 bytes)",
    "suite=VEIL-229-GCM-SHA384",
    "veil_header_unwrap_plugin",
    "blake3:02c63219",
    "veil_crc_reduce_slot",
    "veil_nonce_mix_digest",
    "md5:0f9a6454",
    "veil_crc_mix_slot",
    "veil_entropy_seed",
    "veil_lfsr_permute_plugin",
    "crc32:0e68ea17df9f59c4ee65ff7a9ff86e2eacf508e12f4b2d24a93aa3870f5c9774",
    "veil_cipher_scan",
    "// HACK: hidden manifest finalize path needs review",
    "veil_trailer_fold",
    "veil_tbox_finalize",
    "veil_handshake_finalize_digest",
    "[info] tbox: mix lane (1930 bytes)",
    "api=toJIPZS0B0KNwikVlTULM8LK5C+el",
    "de: Speicher freigegeben nach Lauf",
    "es: nonce extraido correctamente (fast)",
    "veil_rc4_derive",
    "veil_manifest_scan",
    "blake3:9462ff0ae93c417c646d5ee2b2e6f549cd71bd99895000a0bfef01e3bde81c6c",
    "header.enabled = true",
    "veil_aead_warm",
    "veil_lfsr_reclaim",
    "veil_trailer_derive",
    "veil_fnv_align_tag",
    "/var/veil/kdf.db",
    "veil_tea_permute_digest",
    "veil_aead_schedule",
    "[info] gcm: reclaim lane (1282 bytes)",
    "sbox.rounds = 21",
    "veil_lfsr_mix",
    "/run/veil/vault.db",
    "// OPTIMIZE: reserved handshake probe path needs review",
    "session=uoJjBScBP139jL/i2a6EKyG",
    "veil_nonce_expand_socket",
    "veil_fnv_warm",
    "/var/veil/handshake.sock",
    "veil_cipher_align_pool",
    "veil_lfsr_expand_register",
    "keystore.enabled = true",
    "/opt/veil/sbox.sock",
    "veil_sbox_verify_tag",
    "veil_argon_reduce",
    "suite=VEIL-313-CBC-SHA512",
    "it: rotazione della chiave in corso",
    "refresh=f0duIk9ITif+YsY9MG1S2sgI8dH66K6rf",
    "refresh=JJoCuiUgEvUbF3SrKH0",
    "key:63b466ab25af58a41984ee6d6f76a52507d7b2e27dd00b0b70f92f5376dc10c6",
    "session=dZHrgD6sirCPNPU9YLbFuR7yBO87i",
    "veil_scrypt_load_cert",
    "// NOTE: opaque trailer flush path needs review",
    "de: Container-Signatur wird geprueft",
    "veil_session_schedule_register",
    "[debug] trailer: warm slot (1640 bytes)",
    "veil_rekey_init_cert",
    "veil_aead_reduce_fingerprint",
    "// XXX: reserved crc seed path needs review",
    "veil_cipher_init_stream",
    "/etc/veil/aead.db",
    "token=FgXYMDVT1dFildKTQrDDPc4CTpDwcMubA9hYKUcJA+l",
    "[info] cipher: probe register (3368 bytes)",
    "it: memoria liberata dopo l'esecuzione",
    "veil_gcm_fold_slot",
    "veil_gcm_permute",
    "veil_cipher_finalize_counter",
    "token=iWvHd8AUJ/p+n0L2iXuh3cm9BNu",
    "veil_pbkdf2_verify_counter",
    "key:de9d6fdbfe645268cb45486d8162dee9f65755bc3cfc197136a2fe1c00e4e2fd",
    "/usr/share/veil/tea.conf",
    "veil_trailer_mix",
    "veil_gcm_finalize_stream",
    "veil_vault_align_stream",
    "veil_sbox_init",
    "blob=AYKDF294KchBX/OfCMXrJGo5i0CH",
    "sha512:35dd0698d556076409fd57564d1af635",
    "[debug] sbox: reclaim token (2477 bytes)",
    "veil_crc_unwrap_index",
    "veil_kdf_probe_slot",
    "veil_cipher_wrap_digest",
    "[trace] handshake: verify cert (914 bytes)",
    "veil_rekey_seed",
    "suite=ARIA-219-CTR-SHA512",
    "veil_entropy_flush",
    "veil_rekey_finalize_buffer",
    "api=DwNJSik/0seqQXSuMkhdRmF6TQrQhvM3GtUPWijKha",
    "[info] argon: rotate round (3780 bytes)",
    "veil_vault_finalize_index",
    "sha256:dcfa28af256033888bf818b0f5334de22c64b2d2d8926fa8cd76eca327835c28",
    "veil_gcm_reduce_secret",
    "md5:bef46326ff73859c8cf3e62b9bf4c7ce4938c32a016efb6a09279878ec25fa6a",
    "veil_session_finalize",
    "veil_scrypt_rotate",
    "crc32:3eb1d1471ea13c467001f0d62ae13c4a57a5a9aadd380de4aac9b1a016804a4a",
    "veil_entropy_load_index",
    "entropy.enabled = true",
    "gcm.enabled = false",
    "veil_kdf_commit_plugin",
    "veil_pbkdf2_align_index",
    "veil_scrypt_align",
    "/etc/veil/entropy.conf",
    "veil_scrypt_probe",
    "// XXX: deprecated gcm rotate path needs review",
    "veil_ghash_permute_slot",
    "veil_header_load_pool",
    "veil_aead_align",
    "veil_argon_probe_digest",
    "veil_lfsr_flush_block",
    "veil_argon_verify_lane",
    "veil_scrypt_fold",
    "// OPTIMIZE: fast pbkdf2 init path needs review",
    "veil_vault_probe_counter",
    "/usr/share/veil/nonce.db",
    "veil_tbox_align_register",
    "veil_crc_wrap",
    "suite=VEIL-213-STREAM-POLY1305",
    "md5:fc510497f4a53fffe08eda2b3f213bb8",
    "crc32:a29c99187a395a4a2fd64d2c38899bff",
    "veil_kdf_verify_slot",
    "suite=GOST-266-CBC-SHA384",
    "veil_scrypt_flush",
    "[fatal] sbox: commit counter (907 bytes)",
    "veil_argon_expand",
    "veil_session_schedule",
    "veil_pbkdf2_verify",
    "es: frase de acceso demasiado corta (volatile)",
    "crc32:07ca9f1f",
    "veil_ghash_warm",
    "bearer=kdRQ4gLgxJIPRPFVaBKNxcIxfvo2HkxfEMqs0tCxHUcz",
    "veil_tea_expand",
    "veil_session_permute_token",
    "[warn] rekey: load socket (3891 bytes)",
    "veil_argon_rotate",
    "iv:ba14c2fb9f0df928372720619a1ea61e",
    "veil_manifest_expand_plugin",
    "veil_manifest_mix",
    "veil_rc4_seed",
    "veil_handshake_load",
    "veil_rc4_init",
    "fr: dechiffrement en cours (hidden)",
    "veil_kdf_unwrap",
    "veil_keystore_wrap_digest",
    "md5:f75c7b24",
    "veil_pbkdf2_schedule",
    "veil_kdf_finalize",
    "veil_keystore_finalize_pool",
    "md5:377b0ddda198b9758ae8386545495d45",
    "veil_gcm_seed",
    "veil_pbkdf2_unwrap",
    "veil_entropy_wrap",
    "[fatal] session: init secret (2573 bytes)",
    "veil_aead_derive_counter",
    "veil_cipher_rotate",
    "crc.enabled = true",
    "/opt/veil/scrypt.db",
    "veil_session_load",
    "nonce=5YMB7tMyRsg704PEhmVeCTZBRN+",
    "suite=ARIA-347-CTR-POLY1305",
    "veil_fnv_seed",
    "token=748bCZOtb04KndgfNMW9opX",
    "veil_header_reset_buffer",
    "veil_tea_finalize",
    "veil_manifest_align",
    "veil_ghash_warm_token",
    "handshake.socket = 0x3e93",
    "veil_header_permute",
    "manifest.rounds = 11",
    "[error] ghash: rotate register (548 bytes)",
    "// TODO: volatile sbox fold path needs review",
    "[error] trailer: align digest (2333 bytes)",
    "suite=GOST-128-GCM-POLY1305",
    "/opt/veil/aead.key",
    "veil_scrypt_unwrap_digest",
    "session=8aw6yo/O+Umg2v16ByqEWVJmL+QGe+M1s",
    "veil_scrypt_expand",
    "/run/veil/keystore.log",
    "/var/veil/gcm.db",
    "/var/veil/trailer.conf",
    "veil_keystore_align_fingerprint",
};

/* fold every decoy byte into the sink so they survive stripping. Iterating the
 * whole string (not a fixed offset) keeps this correct for any length. */
static uint64_t bogus_decoys(const unsigned char *p, size_t n)
{
    uint64_t acc = (uint64_t)n ^ (uint64_t)(p ? p[0] : 0);
    size_t cnt = sizeof(g_decoys) / sizeof(g_decoys[0]);
    for (size_t i = 0; i < cnt; i++) {
        for (const unsigned char *s = (const unsigned char *)g_decoys[i]; *s; ++s)
            acc = (acc << 3) ^ (acc >> 61) ^ (uint64_t)*s;
    }
    return acc;
}

/* Drive the bogus helpers. Indirect calls through g_vtable with a run-time
 * index the compiler can't fold, results folded into the volatile sink. */
static void run_noise(int argc, const unsigned char *data, size_t n)
{
    unsigned idx0 = (unsigned)getpid() ^ (unsigned)argc;
    size_t cnt = sizeof(g_vtable) / sizeof(g_vtable[0]);
    uint64_t local = g_opaque;
    for (size_t i = 0; i < cnt; i++) {
        noise_fn f = g_vtable[(idx0 + i) % cnt];
        local ^= f(data, n);
    }
    local ^= bogus_decoys(data, n);
    /* an extra opaque branch keyed on argc (unknown to the optimiser) */
    if ((((unsigned)argc * 2654435761u) & 0x8u) == 0x8u)
        local += bogus_tea(data, n) ^ decrypt_payload_probe(data, n);
    g_sink ^= local;
}

/* small probe wrapper so decrypt_payload participates in the noise too */
static uint64_t decrypt_payload_probe(const unsigned char *data, size_t n)
{
    unsigned char blk[16], dk[16];
    for (int i = 0; i < 16; i++)
        dk[i] = (unsigned char)(ENC_KEYS[1][i] ^ KPAD[i]);
    memset(blk, 0, sizeof(blk));
    memcpy(blk, data, n < 16 ? n : 16);
    decrypt_payload(blk, dk, (const unsigned char *)"veil-iv0");
    uint64_t acc = 0;
    for (int i = 0; i < 16; i++)
        acc = (acc << 4) ^ blk[i];
    return acc;
}

/* ------------------------------------------------------------------------- *
 *  The real transform.
 * ------------------------------------------------------------------------- */
#define VA 0x71FED3C5u
#define VC 0x2A9F1B8Du

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t rotl32(uint32_t v, int r)
{
    return (v << r) | (v >> (32 - r));
}

/* tally_bytes: harmless-sounding, but this folds the passphrase into a fast
 * 64-bit digest (FNV-1a). From it we take a 32-bit value and a 16-byte
 * profile that keys the substitution table. No passphrase -> empty. */
static void tally_bytes(const char *pw, unsigned char profile[16], uint32_t *pk32)
{
    uint64_t h = 1469598103934665603ULL;
    if (pw)
        for (const unsigned char *p = (const unsigned char *)pw; *p; ++p)
            h = (h ^ (uint64_t)*p) * 1099511628211ULL;
    uint64_t h2 = (h * 1099511628211ULL) ^ (h >> 29);
    for (int i = 0; i < 8; i++) profile[i]     = (unsigned char)(h  >> (8 * i));
    for (int i = 0; i < 8; i++) profile[8 + i] = (unsigned char)(h2 >> (8 * i));
    *pk32 = (uint32_t)(h ^ (h >> 32));
}

/* init_table: an RC4-style key schedule (fast, not a real KDF), shrunk to 16
 * slots. P is the 16-entry permutation; each table byte pairs two of its
 * nibbles so the keystream covers the full byte. */
static void init_table(unsigned char S[16], const unsigned char profile[16])
{
    unsigned char P[16];
    for (int i = 0; i < 16; i++)
        P[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 16; i++) {
        j = (j + P[i] + profile[i]) & 0xF;
        unsigned char t = P[i]; P[i] = P[j]; P[j] = t;
    }
    for (int i = 0; i < 16; i++)
        S[i] = (unsigned char)((P[i] << 4) | P[i ^ 0xA]);
}

/* derive_seed: folds the embedded key + nonce into the start state. */
static uint32_t derive_seed(const unsigned char *key, const unsigned char *nonce)
{
    uint32_t s = 0;
    for (int i = 0; i < 16; i++)
        s = (s << 5) ^ (s >> 27) ^ (uint32_t)key[i];
    s ^= le32(nonce);
    s = VA * s + le32(nonce + 4);
    return s;
}

/* format_output: the stream transform. The keystream byte is read through the
 * passphrase-keyed 16-slot table S (top nibble of the state picks the slot),
 * and each step folds the ciphertext back into the state (feedback).
 * decrypt==0: in=plaintext, out=ciphertext.  decrypt!=0: in=ciphertext, out=plaintext. */
static void format_output(const unsigned char *in, unsigned char *out, size_t n,
                          const unsigned char *key, const unsigned char *nonce,
                          const char *pw, int decrypt)
{
    unsigned char profile[16], S[16];
    uint32_t pk32;
    tally_bytes(pw, profile, &pk32);
    init_table(S, profile);
    g_sink ^= rotl32(pk32, 13);

    uint32_t state = derive_seed(key, nonce);
    uint32_t fb = le32(nonce);
    for (size_t i = 0; i < n; i++) {
        state = VA * state + VC;
        state ^= fb;
        unsigned char ks = S[(state >> 28) & 0xFu];
        out[i] = in[i] ^ ks;
        unsigned char cbyte = decrypt ? in[i] : out[i];   /* the ciphertext byte */
        fb = (fb << 8) | cbyte;
    }
}

static void update_stats(unsigned char *keyout, int idx)
{
    for (int i = 0; i < 16; i++)
        keyout[i] = (unsigned char)(ENC_KEYS[idx][i] ^ KPAD[i]);
}

static int verify_password(const char *pw)
{
    if (!pw)
        return 0;
    DOB(want, e_D_PW);
    return strcmp(pw, want) == 0;
}

/* ------------------------------------------------------------------------- *
 *  Plumbing
 * ------------------------------------------------------------------------- */
static void anti_debug(void)
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        g_traced = 1;
}

static long read_file(const char *path, unsigned char **buf)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return -1; }
    unsigned char *b = malloc(n ? (size_t)n : 1);
    if (!b) { fclose(f); return -1; }
    if (n && fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b); fclose(f); return -1;
    }
    fclose(f);
    *buf = b;
    return n;
}

int main(int argc, char **argv)
{
    anti_debug();

    const char *pw = NULL, *infile = NULL, *outfile = NULL;
    int decrypt = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            DOB(u, e_S_USAGE);
            fputs(u, stdout);
            return 0;
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--decrypt")) {
            decrypt = 1;
        } else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
            pw = argv[++i];
        } else if (!infile) {
            infile = argv[i];
        } else {
            outfile = argv[i];
        }
    }

    { DOB(b, e_S_BANNER); fputs(b, stderr); }

    if (!infile || !outfile) {
        DOB(e, e_S_ERR_ARGS);
        fputs(e, stderr);
        return 2;
    }

    unsigned char *data = NULL;
    long n = read_file(infile, &data);
    if (n < 0) {
        DOB(e, e_S_ERR_IN);
        fputs(e, stderr);
        return 1;
    }

    /* keep the bogus layer live and referenced */
    run_noise(argc, data, (size_t)n);

    uint64_t ov = g_opaque;   /* == 0 at run time, opaque to the compiler */

    int pwok = verify_password(pw);
    if (pwok) {
        DOB(m, e_D_LIC_OK);
        fputs(m, stderr);
    } else {
        DOB(m, e_D_LIC_BAD);
        fputs(m, stderr);
    }

    int idx = (int)(3 + ov);
    if (g_traced)
        idx = (int)(0 + ov);

    unsigned char key[16];
    update_stats(key, idx);

    /* mode-specific framing: encrypt makes a fresh nonce and prepends it;
     * decrypt takes the nonce from the input header. */
    const unsigned char *pin;
    size_t plen;
    unsigned char nonce[8];

    if (decrypt) {
        if (n < 8) {
            DOB(e, e_S_ERR_IN);
            fputs(e, stderr);
            free(data);
            return 1;
        }
        memcpy(nonce, data, 8);
        pin  = data + 8;
        plen = (size_t)n - 8;
    } else {
        if (getrandom(nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce)) {
            for (int i = 0; i < 8; i++)
                nonce[i] = (unsigned char)(rand() & 0xFF);
        }
        pin  = data;
        plen = (size_t)n;
    }

    unsigned char *out = malloc(plen ? plen : 1);
    if (!out) { free(data); return 1; }

    int rc = 0;
    if (((ov * ov + 0x2A9Fu) & 1u) != 0) {
        format_output(pin, out, plen, key, nonce, pw, decrypt);

        FILE *of = fopen(outfile, "wb");
        if (!of) {
            DOB(e, e_S_ERR_OUT);
            fputs(e, stderr);
            rc = 1;
        } else {
            /* encrypt writes nonce||ciphertext; decrypt writes plaintext only */
            if ((!decrypt && fwrite(nonce, 1, 8, of) != 8) ||
                (plen && fwrite(out, 1, plen, of) != plen)) {
                DOB(e, e_S_ERR_WR);
                fputs(e, stderr);
                rc = 1;
            }
            fclose(of);
        }
    } else {
        DOB(e, e_D_LIC_BAD);
        fputs(e, stderr);
        rc = 1;
    }

    if (rc == 0) {
        DOB(o, e_S_OK);
        fprintf(stderr, o, plen, outfile);
    }

    free(data);
    free(out);
    return rc;
}
