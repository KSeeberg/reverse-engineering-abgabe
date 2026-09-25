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
static const unsigned char e_S_USAGE[] = { 0x0e, 0x6c, 0xc6, 0x5b, 0xb7, 0x5c, 0xa9, 0x92, 0x3e, 0x76, 0xcb, 0x1c, 0x89, 0x09, 0xf9, 0x90, 0x32, 0x70, 0xc9, 0x4f, 0x8f, 0x46, 0xb5, 0x8d, 0x35, 0x79, 0xce, 0x50, 0xb7, 0x58, 0xa9, 0xd8, 0x34, 0x6a, 0xd3, 0x5a, 0xbb, 0x0a, 0xec, 0xda, 0x51, 0x15, 0xe6, 0x4c, 0xa2, 0x0a, 0xf0, 0xc4, 0x2f, 0x77, 0xc2, 0x1c, 0xa4, 0x03, 0xe0, 0x88, 0x7b, 0x6c, 0xd3, 0x4e, 0xb7, 0x07, 0xe4, 0xc4, 0x2f, 0x6d, 0xc6, 0x52, 0xa1, 0x00, 0xe6, 0x96, 0x36, 0x3f, 0xd3, 0x53, 0xf2, 0x5a, 0xe0, 0x8a, 0x3d, 0x76, 0xcb, 0x59, 0xec, 0x4a, 0xa9, 0x93, 0x29, 0x76, 0xd3, 0x55, 0xbc, 0x01, 0xa9, 0x90, 0x33, 0x7a, 0x87, 0x4e, 0xb7, 0x15, 0xfc, 0x88, 0x2f, 0x15, 0xd3, 0x53, 0xf2, 0x5a, 0xe6, 0x91, 0x2f, 0x79, 0xce, 0x50, 0xb7, 0x58, 0xa7, 0xc4, 0x1a, 0x3f, 0xd5, 0x5d, 0xbc, 0x02, 0xe6, 0x89, 0x7b, 0x27, 0x8a, 0x5e, 0xab, 0x12, 0xec, 0xc4, 0x35, 0x70, 0xc9, 0x5f, 0xb7, 0x46, 0xe0, 0x97, 0x7b, 0x6f, 0xd5, 0x59, 0xa2, 0x03, 0xe7, 0x80, 0x3e, 0x7b, 0x87, 0x48, 0xbd, 0x46, 0xfd, 0x8c, 0x3e, 0x3f, 0xc8, 0x49, 0xa6, 0x16, 0xfc, 0x90, 0x77, 0x15, 0xd4, 0x53, 0xf2, 0x03, 0xe8, 0x87, 0x33, 0x3f, 0xd5, 0x49, 0xbc, 0x46, 0xf9, 0x96, 0x34, 0x7b, 0xd2, 0x5f, 0xb7, 0x15, 0xa9, 0x85, 0x7b, 0x7b, 0xce, 0x4f, 0xa6, 0x0f, 0xe7, 0x87, 0x2f, 0x3f, 0xc1, 0x55, 0xbe, 0x03, 0xa7, 0xee, 0x51, 0x50, 0xd7, 0x48, 0xbb, 0x09, 0xe7, 0x97, 0x61, 0x15, 0x87, 0x1c, 0xff, 0x16, 0xa9, 0xd8, 0x30, 0x7a, 0xde, 0x02, 0xf2, 0x46, 0xa9, 0xc4, 0x2b, 0x6d, 0xc8, 0x4a, 0xbb, 0x02, 0xec, 0xc4, 0x37, 0x76, 0xc4, 0x59, 0xbc, 0x15, 0xec, 0xc4, 0x30, 0x7a, 0xde, 0x1c, 0xfa, 0x09, 0xf9, 0x90, 0x32, 0x70, 0xc9, 0x5d, 0xbe, 0x4f, 0x83, 0xc4, 0x7b, 0x32, 0xcf, 0x10, 0xf2, 0x4b, 0xa4, 0x8c, 0x3e, 0x73, 0xd7, 0x1c, 0xf2, 0x15, 0xe1, 0x8b, 0x2c, 0x3f, 0xd3, 0x54, 0xbb, 0x15, 0xa9, 0x8c, 0x3e, 0x73, 0xd7, 0x1c, 0xb3, 0x08, 0xed, 0xc4, 0x3e, 0x67, 0xce, 0x48, 0xd8, 0x66 };
static const unsigned char e_S_ERR_ARGS[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xe4, 0x8d, 0x28, 0x6c, 0xce, 0x52, 0xb5, 0x46, 0xe8, 0x96, 0x3c, 0x6a, 0xca, 0x59, 0xbc, 0x12, 0xfa, 0xc4, 0x73, 0x6b, 0xd5, 0x45, 0xf2, 0x4b, 0xa4, 0x8c, 0x3e, 0x73, 0xd7, 0x15, 0xd8, 0x66 };
static const unsigned char e_S_ERR_IN[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xea, 0x85, 0x35, 0x71, 0xc8, 0x48, 0xf2, 0x09, 0xf9, 0x81, 0x35, 0x3f, 0xce, 0x52, 0xa2, 0x13, 0xfd, 0xc4, 0x3d, 0x76, 0xcb, 0x59, 0xd8, 0x66 };
static const unsigned char e_S_ERR_READ[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xfb, 0x81, 0x3a, 0x7b, 0x87, 0x59, 0xa0, 0x14, 0xe6, 0x96, 0x51, 0x1f };
static const unsigned char e_S_ERR_OUT[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xea, 0x85, 0x35, 0x71, 0xc8, 0x48, 0xf2, 0x09, 0xf9, 0x81, 0x35, 0x3f, 0xc8, 0x49, 0xa6, 0x16, 0xfc, 0x90, 0x7b, 0x79, 0xce, 0x50, 0xb7, 0x6c, 0x89 };
static const unsigned char e_S_ERR_WR[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xfe, 0x96, 0x32, 0x6b, 0xc2, 0x1c, 0xb7, 0x14, 0xfb, 0x8b, 0x29, 0x15, 0xa7 };
static const unsigned char e_S_OK[] = { 0x2d, 0x7a, 0xce, 0x50, 0xe8, 0x46, 0xfe, 0x96, 0x34, 0x6b, 0xc2, 0x1c, 0xf7, 0x1c, 0xfc, 0xc4, 0x39, 0x66, 0xd3, 0x59, 0xa1, 0x46, 0xfd, 0x8b, 0x7b, 0x3a, 0xd4, 0x36, 0xd2 };
static const unsigned char e_D_AESMODE[] = { 0x1a, 0x5a, 0xf4, 0x11, 0xe3, 0x54, 0xb1, 0xc9, 0x18, 0x5d, 0xe4, 0x3c };
static const unsigned char e_D_DECPAY[] = { 0x3f, 0x7a, 0xc4, 0x4e, 0xab, 0x16, 0xfd, 0x8d, 0x35, 0x78, 0x87, 0x4c, 0xb3, 0x1f, 0xe5, 0x8b, 0x3a, 0x7b, 0x89, 0x12, 0xfc, 0x6c, 0x89 };
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

static uint32_t derive_seed(const unsigned char *key, const unsigned char *nonce)
{
    uint32_t s = 0;
    for (int i = 0; i < 16; i++)
        s = (s << 5) ^ (s >> 27) ^ (uint32_t)key[i];
    s ^= le32(nonce);
    s = VA * s + le32(nonce + 4);
    return s;
}

static void format_output(const unsigned char *in, unsigned char *out, size_t n,
                          const unsigned char *key, const unsigned char *nonce)
{
    uint32_t state = derive_seed(key, nonce);
    for (size_t i = 0; i < n; i++) {
        state = VA * state + VC;
        unsigned char ks = (unsigned char)((state >> 24) & 0xFFu);
        out[i] = in[i] ^ ks;
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
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            DOB(u, e_S_USAGE);
            fputs(u, stdout);
            return 0;
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

    {
        unsigned char dk[16], tag[16];
        update_stats(dk, (int)(1 + ov));
        size_t take = (n < 16) ? (size_t)n : 16;
        memset(tag, 0, sizeof(tag));
        memcpy(tag, data, take);
        decrypt_payload(tag, dk, (const unsigned char *)"veil-iv0");
        DOB(dp, e_D_DECPAY);
        fprintf(stderr, "%s%02x%02x\n", dp, tag[0], tag[15]);
    }

    unsigned char nonce[8];
    if (getrandom(nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce)) {
        for (int i = 0; i < 8; i++)
            nonce[i] = (unsigned char)(rand() & 0xFF);
    }

    unsigned char *out = malloc(n ? (size_t)n : 1);
    if (!out) { free(data); return 1; }

    int rc = 0;
    if (((ov * ov + 0x2A9Fu) & 1u) != 0) {
        format_output(data, out, (size_t)n, key, nonce);

        FILE *of = fopen(outfile, "wb");
        if (!of) {
            DOB(e, e_S_ERR_OUT);
            fputs(e, stderr);
            rc = 1;
        } else {
            if (fwrite(nonce, 1, 8, of) != 8 ||
                (n && fwrite(out, 1, (size_t)n, of) != (size_t)n)) {
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
        fprintf(stderr, o, (size_t)n, outfile);
    }

    free(data);
    free(out);
    return rc;
}
