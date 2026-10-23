/*
 * thc-jennifer
 * kdbx v3/v4 password recovery (AES-KDF / Argon2d / Argon2id)
 *
 * author : Vineeth Kumar (foxcornlab)
 * build  : gcc -O2 -pthread jennifer.c -lssl -lcrypto -largon2 -o jennifer
 * deps   : libssl-dev libargon2-dev
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <argon2.h>

#define VERSION          "2.1"
#define MAX_PWD_LEN      256
#define DEFAULT_WORDLIST "src/wordlists.txt"
#define INSTALLED_WORDLIST "/usr/local/share/jennifer/src/wordlists.txt"
#define STREAM_BUF       (128 * 1024)
#define DEFAULT_THREADS  4

#define KDBX_SIG1        0x9AA2D903u
#define KDBX_SIG2_3      0xB54BFB65u
#define KDBX_SIG2_4      0xB54BFB67u

static const uint8_t UUID_ARGON2D[4]  = {0xEF, 0x63, 0x6D, 0xDF};
static const uint8_t UUID_ARGON2ID[4] = {0x9E, 0x29, 0x8B, 0x19};

typedef enum { KDF_AES, KDF_ARGON2D, KDF_ARGON2ID } kdf_type;

typedef struct {
    int      version;
    kdf_type kdf;

    uint8_t  master_seed[32];
    uint8_t  enc_iv[16];

    uint8_t  transform_seed[32];
    uint64_t transform_rounds;

    uint8_t  argon2_salt[64];
    uint32_t argon2_salt_len;
    uint32_t argon2_m;
    uint32_t argon2_t;
    uint32_t argon2_p;

    uint8_t  stream_start[32];

    uint8_t *raw_header;
    size_t   raw_header_len;

    uint8_t  payload_start[32];
} kdbx_header;

typedef struct {
    kdbx_header     *hdr;
    bool             verbose;
    bool             debug;

    pthread_mutex_t  q_lock;
    pthread_cond_t   q_has_work;
    pthread_cond_t   q_has_space;
    char           (*q_buf)[MAX_PWD_LEN];
    int              q_head, q_tail, q_cap;
    bool             q_done;

    char            *found;
    pthread_mutex_t  found_lock;

    volatile uint64_t attempts;
    volatile uint64_t total;
    time_t            start;
    int               throttle_us;
} crack_state;

volatile sig_atomic_t g_running = 1;
static void on_sigint(int s) { (void)s; g_running = 0; }

static void print_progress(crack_state *st, const char *cur)
{
    uint64_t done  = st->attempts;
    uint64_t total = st->total;
    int elapsed    = (int)difftime(time(NULL), st->start);
    if (elapsed < 1) elapsed = 1;

    int ppm      = (int)((done * 60) / elapsed);
    uint64_t rem = total > done ? total - done : 0;
    int eta      = ppm > 0 ? (int)((rem * 60) / ppm) : 0;

    char eta_s[64];
    if      (eta >= 86400) snprintf(eta_s, sizeof eta_s, "%dd%dh%dm",
                           eta/86400, (eta%86400)/3600, (eta%3600)/60);
    else if (eta >= 3600)  snprintf(eta_s, sizeof eta_s, "%dh%dm%ds",
                           eta/3600, (eta%3600)/60, eta%60);
    else if (eta >= 60)    snprintf(eta_s, sizeof eta_s, "%dm%ds", eta/60, eta%60);
    else                   snprintf(eta_s, sizeof eta_s, "%ds", eta);

    if (total)
        fprintf(stderr, "\r\033[K[~] %llu/%llu (%.1f%%) | %d/min | ETA %s%s%s",
                (unsigned long long)done, (unsigned long long)total,
                100.0 * done / total, ppm, eta_s,
                (cur && st->verbose) ? " | " : "",
                (cur && st->verbose) ? cur   : "");
    else
        fprintf(stderr, "\r\033[K[~] %llu tried | %d/min%s%s",
                (unsigned long long)done, ppm,
                (cur && st->verbose) ? " | " : "",
                (cur && st->verbose) ? cur   : "");
    fflush(stderr);
}

static void sha256_buf(const uint8_t *buf, size_t len, uint8_t *out)
{
    SHA256(buf, len, out);
}

static void sha256_2(const uint8_t *a, size_t la,
                     const uint8_t *b, size_t lb, uint8_t *out)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, a, la);
    SHA256_Update(&ctx, b, lb);
    SHA256_Final(out, &ctx);
}

static void sha512_buf(const uint8_t *buf, size_t len, uint8_t *out)
{
    SHA512(buf, len, out);
}

/*
 * AES-256-ECB key transform: N rounds on the 32-byte composite key
 * (both 16-byte halves in one 32-byte EVP call per round), then SHA256.
 */
static void aes_kdf(const uint8_t *composite, const uint8_t *seed,
                    uint64_t rounds, uint8_t *out)
{
    uint8_t block[32];
    memcpy(block, composite, 32);

    if (rounds > 0) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, seed, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outl;
        for (uint64_t i = 0; i < rounds; i++)
            EVP_EncryptUpdate(ctx, block, &outl, block, 32);
        EVP_CIPHER_CTX_free(ctx);
    }

    sha256_buf(block, 32, out);
}

static void composite_key(const char *pw, uint8_t *out)
{
    uint8_t h[32];
    sha256_buf((const uint8_t *)pw, strlen(pw), h);
    sha256_buf(h, 32, out);
}

static bool verify_v3(const kdbx_header *hdr, const uint8_t *composite)
{
    uint8_t xform[32];
    aes_kdf(composite, hdr->transform_seed, hdr->transform_rounds, xform);

    uint8_t mkey[32];
    sha256_2(hdr->master_seed, 32, xform, 32, mkey);

    uint8_t dec[32];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, mkey, hdr->enc_iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int l1 = 0, l2 = 0;
    EVP_DecryptUpdate(ctx, dec, &l1, hdr->payload_start, 32);
    EVP_DecryptFinal_ex(ctx, dec + l1, &l2);
    EVP_CIPHER_CTX_free(ctx);

    return (memcmp(dec, hdr->stream_start, 32) == 0);
}

/*
 * v4 oracle:
 *   xform    = KDF(composite)
 *   pre_key  = SHA512(master_seed || xform || 0x01)
 *   hmac_key = SHA512(0xFFFFFFFFFFFFFFFF_le || pre_key)
 *   expected = HMAC-SHA256(hmac_key[0..31], raw_header)
 */
static bool verify_v4(const kdbx_header *hdr, const uint8_t *composite)
{
    uint8_t xform[32];
    if (hdr->kdf == KDF_AES) {
        aes_kdf(composite, hdr->transform_seed, hdr->transform_rounds, xform);
    } else {
        argon2_type t = (hdr->kdf == KDF_ARGON2D) ? Argon2_d : Argon2_id;
        if (argon2_hash(hdr->argon2_t, hdr->argon2_m, hdr->argon2_p,
                        composite, 32,
                        hdr->argon2_salt, hdr->argon2_salt_len,
                        xform, 32,
                        NULL, 0, t, ARGON2_VERSION_13) != ARGON2_OK)
            return false;
    }

    uint8_t pre[65];
    memcpy(pre,      hdr->master_seed, 32);
    memcpy(pre + 32, xform,            32);
    pre[64] = 0x01;
    uint8_t pre_key[64];
    sha512_buf(pre, 65, pre_key);

    uint8_t idx[8];
    memset(idx, 0xFF, 8);

    uint8_t hkin[72];
    memcpy(hkin,     idx,     8);
    memcpy(hkin + 8, pre_key, 64);
    uint8_t hmac_key_full[64];
    sha512_buf(hkin, 72, hmac_key_full);

    uint8_t computed[32];
    unsigned int clen = 32;
    HMAC(EVP_sha256(), hmac_key_full, 64,
         hdr->raw_header, hdr->raw_header_len,
         computed, &clen);

    return (memcmp(computed, hdr->payload_start, 32) == 0);
}

static bool attempt_password(const kdbx_header *hdr, const char *pw)
{
    uint8_t comp[32];
    composite_key(pw, comp);
    return (hdr->version == 3) ? verify_v3(hdr, comp) : verify_v4(hdr, comp);
}

/*
 * Parse a KDBX4 VariantDictionary from a heap buffer.
 * Pure pointer arithmetic — no fseek, no fread, no cursor state to manage.
 *
 * Entry format:
 *   [1 byte type]   0x00 = terminator
 *   [4-byte LE klen]
 *   [klen bytes key (UTF-8)]
 *   [4-byte LE vlen]
 *   [vlen bytes value]
 */
static void parse_vdict(const uint8_t *data, size_t datalen, kdbx_header *hdr)
{
    if (datalen < 3) return;

    const uint8_t *p   = data + 2;       /* skip 2-byte VariantDictionary version */
    const uint8_t *end = data + datalen;

    uint8_t  s_buf[64] = {0};
    uint32_t s_len = 0;

    while (p < end) {
        uint8_t vtype = *p++;
        if (vtype == 0x00) break;

        if (p + 4 > end) break;
        uint32_t klen;
        memcpy(&klen, p, 4); p += 4;

        if (p + klen > end) break;
        char key[64] = {0};
        uint32_t kread = klen < (uint32_t)(sizeof key - 1) ? klen : (uint32_t)(sizeof key - 1);
        memcpy(key, p, kread);
        p += klen;

        if (p + 4 > end) break;
        uint32_t vlen;
        memcpy(&vlen, p, 4); p += 4;

        if (p + vlen > end) break;
        const uint8_t *vptr = p;
        p += vlen;

        if (strcmp(key, "$UUID") == 0 && vlen >= 4) {
            if      (memcmp(vptr, UUID_ARGON2D,  4) == 0) hdr->kdf = KDF_ARGON2D;
            else if (memcmp(vptr, UUID_ARGON2ID, 4) == 0) hdr->kdf = KDF_ARGON2ID;
            else                                           hdr->kdf = KDF_AES;
        } else if (strcmp(key, "S") == 0) {
            s_len = vlen < (uint32_t)sizeof s_buf ? vlen : (uint32_t)sizeof s_buf;
            memcpy(s_buf, vptr, s_len);
        } else if (strcmp(key, "R") == 0 && vlen == 8) {
            memcpy(&hdr->transform_rounds, vptr, 8);
        } else if (strcmp(key, "I") == 0 && vlen == 8) {
            uint64_t v; memcpy(&v, vptr, 8);
            hdr->argon2_t = (uint32_t)v;
        } else if (strcmp(key, "M") == 0 && vlen == 8) {
            uint64_t v; memcpy(&v, vptr, 8);
            hdr->argon2_m = (uint32_t)(v / 1024);
        } else if (strcmp(key, "P") == 0 && vlen == 4) {
            memcpy(&hdr->argon2_p, vptr, 4);
        }
    }

    /* KDF UUID might appear after "S" in the dict, so assign S here */
    if (s_len > 0) {
        if (hdr->kdf == KDF_AES) {
            uint32_t n = s_len < 32 ? s_len : 32;
            memcpy(hdr->transform_seed, s_buf, n);
        } else {
            uint32_t n = s_len < 64 ? s_len : 64;
            memcpy(hdr->argon2_salt, s_buf, n);
            hdr->argon2_salt_len = n;
        }
    }
}

static bool parse_header(const char *path, kdbx_header *hdr, bool debug)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return false; }

    memset(hdr, 0, sizeof *hdr);

    uint32_t sig1, sig2, ver;
    if (fread(&sig1, 4, 1, f) != 1) goto bad;
    if (fread(&sig2, 4, 1, f) != 1) goto bad;
    if (fread(&ver,  4, 1, f) != 1) goto bad;

    if (sig1 != KDBX_SIG1) goto bad;
    if (sig2 != KDBX_SIG2_3 && sig2 != KDBX_SIG2_4) goto bad;

    uint16_t major = (ver >> 16) & 0xFFFF;
    hdr->version = (major >= 4) ? 4 : 3;

    hdr->kdf = KDF_AES;

    /* KDBX3: TLV with 1-byte id, 2-byte length */
    if (hdr->version == 3) {
        while (1) {
            uint8_t  fid;
            uint16_t fsz;
            if (fread(&fid, 1, 1, f) != 1) break;
            if (fread(&fsz, 2, 1, f) != 1) break;
            long fpos = ftell(f);
            if (fid == 0) { fseek(f, fpos + fsz, SEEK_SET); break; }
            switch (fid) {
                case 4: fread(hdr->master_seed,       1, fsz < 32 ? fsz : 32, f); break;
                case 5: fread(hdr->transform_seed,    1, fsz < 32 ? fsz : 32, f); break;
                case 6: fread(&hdr->transform_rounds, 1, fsz <  8 ? fsz :  8, f); break;
                case 7: fread(hdr->enc_iv,            1, fsz < 16 ? fsz : 16, f); break;
                case 9: fread(hdr->stream_start,      1, fsz < 32 ? fsz : 32, f); break;
            }
            fseek(f, fpos + fsz, SEEK_SET);
        }
        fread(hdr->payload_start, 1, 32, f);
        if (debug)
            fprintf(stderr, "[d] v3  rounds=%llu  ms[0]=%02x  ts[0]=%02x  iv[0]=%02x\n",
                    (unsigned long long)hdr->transform_rounds,
                    hdr->master_seed[0], hdr->transform_seed[0], hdr->enc_iv[0]);
        fclose(f);
        return true;
    }

    /*
     * KDBX4: TLV with 1-byte id, 4-byte length.
     * Each field's content is read into a malloc'd buffer so parse_vdict
     * can walk the VariantDictionary with pointer arithmetic only.
     */
    while (1) {
        uint8_t  fid;
        uint32_t fsz;
        if (fread(&fid, 1, 1, f) != 1) break;
        if (fread(&fsz, 4, 1, f) != 1) break;

        if (fid == 0) { fseek(f, fsz, SEEK_CUR); break; }

        uint8_t *fbuf = NULL;
        if (fsz > 0) {
            fbuf = malloc(fsz);
            if (!fbuf) { fclose(f); return false; }
            if (fread(fbuf, 1, fsz, f) != fsz) { free(fbuf); goto bad; }
        }

        switch (fid) {
            case 4:
                if (fbuf && fsz >= 32) memcpy(hdr->master_seed, fbuf, 32);
                else if (fbuf)         memcpy(hdr->master_seed, fbuf, fsz);
                break;
            case 7:
                if (fbuf && fsz >= 16) memcpy(hdr->enc_iv, fbuf, 16);
                else if (fbuf)         memcpy(hdr->enc_iv, fbuf, fsz);
                break;
            case 11:
                if (fbuf) parse_vdict(fbuf, fsz, hdr);
                break;
        }

        free(fbuf);
        /* cursor is already at fstart+fsz because we fread(fsz) */
    }

    if (debug)
        fprintf(stderr, "[d] v4  kdf=%d  rounds=%llu  ms[0]=%02x  "
                "ts[0]=%02x  salt_len=%u  iv[0]=%02x\n",
                hdr->kdf, (unsigned long long)hdr->transform_rounds,
                hdr->master_seed[0], hdr->transform_seed[0],
                hdr->argon2_salt_len, hdr->enc_iv[0]);

    /* snapshot raw header for HMAC */
    long hend = ftell(f);
    hdr->raw_header_len = (size_t)hend;
    hdr->raw_header = malloc(hdr->raw_header_len);
    if (!hdr->raw_header) { fclose(f); return false; }
    fseek(f, 0, SEEK_SET);
    fread(hdr->raw_header, 1, hdr->raw_header_len, f);

    /* skip 32-byte SHA256 integrity hash, read the 32-byte HMAC */
    fseek(f, hend + 32, SEEK_SET);
    fread(hdr->payload_start, 1, 32, f);

    fclose(f);
    return true;

bad:
    fclose(f);
    fprintf(stderr, "[!] bad magic / truncated header\n");
    return false;
}

/* queue: fixed-size slots, no per-entry heap alloc */

static void q_push(crack_state *st, const char *pw)
{
    pthread_mutex_lock(&st->q_lock);
    while ((st->q_tail - st->q_head) >= st->q_cap && !st->found)
        pthread_cond_wait(&st->q_has_space, &st->q_lock);
    if (st->found) { pthread_mutex_unlock(&st->q_lock); return; }
    strncpy(st->q_buf[st->q_tail % st->q_cap], pw, MAX_PWD_LEN - 1);
    st->q_buf[st->q_tail % st->q_cap][MAX_PWD_LEN - 1] = '\0';
    st->q_tail++;
    pthread_cond_signal(&st->q_has_work);
    pthread_mutex_unlock(&st->q_lock);
}

static bool q_pop(crack_state *st, char *out)
{
    pthread_mutex_lock(&st->q_lock);
    while (st->q_tail == st->q_head) {
        if (st->q_done || st->found) {
            pthread_mutex_unlock(&st->q_lock);
            return false;
        }
        pthread_cond_wait(&st->q_has_work, &st->q_lock);
    }
    strncpy(out, st->q_buf[st->q_head % st->q_cap], MAX_PWD_LEN - 1);
    out[MAX_PWD_LEN - 1] = '\0';
    st->q_head++;
    pthread_cond_signal(&st->q_has_space);
    pthread_mutex_unlock(&st->q_lock);
    return true;
}

static void *worker(void *arg)
{
    crack_state *st = arg;
    char pw[MAX_PWD_LEN];

    while (g_running && !st->found && q_pop(st, pw)) {
        uint64_t n = __sync_add_and_fetch(&st->attempts, 1);
        bool ok    = attempt_password(st->hdr, pw);

        if (ok) {
            pthread_mutex_lock(&st->found_lock);
            if (!st->found) st->found = strdup(pw);
            pthread_mutex_unlock(&st->found_lock);
            pthread_mutex_lock(&st->q_lock);
            pthread_cond_broadcast(&st->q_has_work);
            pthread_cond_broadcast(&st->q_has_space);
            pthread_mutex_unlock(&st->q_lock);
        }

        if (n % 500 == 0 || ok)
            print_progress(st, st->verbose ? pw : NULL);

        if (st->throttle_us > 0)
            usleep(st->throttle_us);
    }
    return NULL;
}

static void banner(void)
{
    puts("  ____  _____  _____  _____  ___  _____  _____  _____ ");
    puts("  \\_  \\/   __\\/  _  \\/  _  \\/___\\/   __\\/   __\\/  _  \\");
    puts("---|  ||   __||  |  ||  |  ||   ||   __||   __||  _  <");
    puts("\\_____/\\_____/\\__|__/\\__|__/\\___/\\__/   \\_____/\\__|\\__\\");
    puts("");
    printf("  thc-jennifer v%s || Foxcorn Lab\n\n", VERSION);
}

static void usage(const char *prog)
{
    printf("usage: %s <db.kdbx> [wordlist] [-v] [-d] [-t <n>] [-T <us>]\n\n", prog);
    printf("  -v       print each candidate\n");
    printf("  -d       dump parsed header fields\n");
    printf("  -t <n>   threads (default %d)\n", DEFAULT_THREADS);
    printf("  -T <us>  throttle microseconds per attempt per thread\n\n");
}

/*
 * Wordlist lookup: an explicit path on the command line is used as-is.
 * Otherwise try $JENNIFER_WORDLIST, the source tree path, then the
 * installed path so a `make install` build works from any cwd.
 */
static FILE *open_wordlist(const char *want, const char **used_path)
{
    const char *cands[4];
    int n = 0;

    if (want && *want) {
        cands[n++] = want;
    } else {
        const char *env = getenv("JENNIFER_WORDLIST");
        if (env && *env)          cands[n++] = env;
        cands[n++] = DEFAULT_WORDLIST;
        cands[n++] = INSTALLED_WORDLIST;
    }

    for (int i = 0; i < n; i++) {
        FILE *f = fopen(cands[i], "r");
        if (f) {
            if (used_path) *used_path = cands[i];
            return f;
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, on_sigint);
    banner();

    if (argc < 2) { usage(argv[0]); return 1; }

    const char *kdbx     = argv[1];
    const char *wlpath   = NULL;   /* explicit wordlist from argv, or NULL */
    bool        verbose  = false;
    bool        debug    = false;
    int         nthreads = DEFAULT_THREADS;
    int         throttle = 0;

    for (int i = 2; i < argc; i++) {
        if      (strcmp(argv[i], "-v") == 0)               verbose  = true;
        else if (strcmp(argv[i], "-d") == 0)               debug    = true;
        else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) nthreads = atoi(argv[++i]);
        else if (strcmp(argv[i], "-T") == 0 && i+1 < argc) throttle = atoi(argv[++i]);
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
    { usage(argv[0]); return 0; }
        else                                                wlpath = argv[i];
        
    }
    if (nthreads < 1) nthreads = 1;

    kdbx_header hdr;
    if (!parse_header(kdbx, &hdr, debug)) return 1;

    const char *kdf_s =
        hdr.kdf == KDF_ARGON2D  ? "Argon2d"  :
        hdr.kdf == KDF_ARGON2ID ? "Argon2id" : "AES-KDF";

    printf("[*] kdbx v%d  kdf=%s", hdr.version, kdf_s);
    if (hdr.kdf == KDF_AES)
        printf("  rounds=%llu", (unsigned long long)hdr.transform_rounds);
    else
        printf("  t=%u m=%uKiB p=%u", hdr.argon2_t, hdr.argon2_m, hdr.argon2_p);
    puts("");

    const char *wl_used = NULL;
    FILE *wl = open_wordlist(wlpath, &wl_used);
    if (!wl) {
        fprintf(stderr,
                "[!] wordlist not found: %s\n"
                "[!] tried: $JENNIFER_WORDLIST, %s, %s\n",
                wlpath ? wlpath : "(none given)",
                DEFAULT_WORDLIST, INSTALLED_WORDLIST);
        return 1;
    }
    wlpath = wl_used;

    uint64_t total = 0;
    {
        char buf[STREAM_BUF]; size_t n;
        while ((n = fread(buf, 1, sizeof buf, wl)) > 0)
            for (size_t i = 0; i < n; i++) if (buf[i] == '\n') total++;
        rewind(wl);
    }

    printf("[*] wordlist=%s  candidates=%llu  threads=%d\n\n",
           wlpath, (unsigned long long)total, nthreads);

    crack_state st  = {0};
    st.hdr          = &hdr;
    st.verbose      = verbose;
    st.debug        = debug;
    st.total        = total;
    st.start        = time(NULL);
    st.q_cap        = nthreads * 64;
    st.throttle_us  = throttle;
    st.q_buf        = calloc(st.q_cap, sizeof *st.q_buf);
    if (!st.q_buf) { fprintf(stderr, "[!] alloc failed\n"); return 1; }
    pthread_mutex_init(&st.q_lock,     NULL);
    pthread_mutex_init(&st.found_lock, NULL);
    pthread_cond_init(&st.q_has_work,  NULL);
    pthread_cond_init(&st.q_has_space, NULL);

    pthread_t *threads = malloc(nthreads * sizeof(pthread_t));
    for (int i = 0; i < nthreads; i++)
        pthread_create(&threads[i], NULL, worker, &st);

    char line[MAX_PWD_LEN];
    while (g_running && !st.found && fgets(line, sizeof line, wl)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        q_push(&st, line);
    }

    pthread_mutex_lock(&st.q_lock);
    st.q_done = true;
    pthread_cond_broadcast(&st.q_has_work);
    pthread_mutex_unlock(&st.q_lock);

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    fclose(wl);
    fputs("\n", stderr);

    int rc;
    if (st.found) {
        printf("[+] cracked: %s\n", st.found);
        free(st.found);
        rc = 0;
    } else {
        puts("[-] exhausted, no match");
        rc = 1;
    }

    if (hdr.raw_header) free(hdr.raw_header);
    free(st.q_buf);
    free(threads);
    pthread_mutex_destroy(&st.q_lock);
    pthread_mutex_destroy(&st.found_lock);
    pthread_cond_destroy(&st.q_has_work);
    pthread_cond_destroy(&st.q_has_space);

    return rc;
}
