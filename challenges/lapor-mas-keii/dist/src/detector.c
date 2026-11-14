#define _GNU_SOURCE
#include "detector.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NGRAM_N      3
#define MAX_SENT     256
#define UNIQ_SLOTS   512
#define MAX_RULES    64
#define MAX_KW       32

static const char *STOPWORDS[] = {
    "yang", "dan", "di", "ke", "dari", "ini", "itu", "dengan", "untuk", "pada",
    "adalah", "akan", "atau", "juga", "tidak", "sudah", "saya", "kami", "kita",
    "mereka", "dia", "para", "sangat", "sekali", "agar", "serta", "oleh",
    "dalam", "sebagai", "karena", "namun", "tetapi", "dapat", "telah", "bisa",
};
#define NSTOP ((int)(sizeof(STOPWORDS) / sizeof(STOPWORDS[0])))

static struct {
    uint32_t nbuckets, ngram_n;
    int32_t  scale, bias, cap, w_mad10, w_stop1000, w_uniq1000;
    int32_t *ngram;
    int      threshold;
    int      nrules;
    char     kw[MAX_RULES][MAX_KW];
    int      pen[MAX_RULES];
    uint32_t stop_hash[NSTOP];
    int      loaded;
} D;

static long cdiv(long a, long b)
{
    long q = (a < 0 ? -a : a) / (b < 0 ? -b : b);
    return ((a < 0) != (b < 0)) ? -q : q;
}

static uint32_t fnv1a(const unsigned char *d, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= d[i];
        h *= 16777619u;
    }
    return h;
}

static int is_word_byte(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static int is_term(unsigned char c)
{
    return c == '.' || c == '!' || c == '?';
}

static void stylometrics(const unsigned char *p, size_t n,
                         long *mad10, long *stop1000, long *uniq1000)
{
    uint32_t table[UNIQ_SLOTS];
    int sent_len[MAX_SENT];
    memset(table, 0, sizeof(table));

    int nsent = 0, cur = 0, wc = 0, stopcount = 0, distinct = 0;

    size_t i = 0;
    while (i < n) {
        unsigned char c = p[i];
        if (is_word_byte(c)) {
            size_t j = i;
            while (j < n && is_word_byte(p[j])) j++;
            uint32_t h = fnv1a(p + i, j - i);
            wc++;
            cur++;
            for (int k = 0; k < NSTOP; k++)
                if (D.stop_hash[k] == h) { stopcount++; break; }
            if (h == 0) h = 1;
            uint32_t slot = h % UNIQ_SLOTS;
            while (table[slot] != 0 && table[slot] != h)
                slot = (slot + 1) % UNIQ_SLOTS;
            if (table[slot] == 0) { table[slot] = h; distinct++; }
            i = j;
            continue;
        }
        if (is_term(c)) {
            if (cur > 0) {
                if (nsent < MAX_SENT) sent_len[nsent++] = cur;
                cur = 0;
            }
        }
        i++;
    }
    if (cur > 0 && nsent < MAX_SENT) sent_len[nsent++] = cur;

    int denom = nsent ? nsent : 1;
    long total = 0;
    for (int k = 0; k < nsent; k++) total += sent_len[k];
    long mean = cdiv(total, denom);
    long mad_sum = 0;
    for (int k = 0; k < nsent; k++) {
        long d = sent_len[k] - mean;
        mad_sum += (d < 0 ? -d : d);
    }
    *mad10    = cdiv(mad_sum * 10, denom);
    *stop1000 = wc ? cdiv((long)stopcount * 1000, wc) : 0;
    *uniq1000 = wc ? cdiv((long)distinct * 1000, wc) : 0;
}

static size_t lower_copy(const char *text, size_t n, unsigned char *out, size_t cap)
{
    size_t m = n < cap ? n : cap;
    for (size_t i = 0; i < m; i++) {
        unsigned char c = (unsigned char)text[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
    }
    return m;
}

static long base_score(const unsigned char *p, size_t n)
{
    long base = D.bias;
    if (n >= NGRAM_N)
        for (size_t i = 0; i + NGRAM_N <= n; i++)
            base += D.ngram[fnv1a(p + i, NGRAM_N) % D.nbuckets];

    long mad10, stop1000, uniq1000;
    stylometrics(p, n, &mad10, &stop1000, &uniq1000);
    base += cdiv((long)D.w_mad10 * mad10, 100);
    base += cdiv((long)D.w_stop1000 * stop1000, 1000);
    base += cdiv((long)D.w_uniq1000 * uniq1000, 1000);

    if (base < 0) base = 0;
    long s = cdiv(base, D.scale);
    return s > 1000 ? 1000 : s;
}

int detector_score(const char *text, size_t n)
{
    static unsigned char buf[1024];
    size_t m = lower_copy(text, n, buf, sizeof buf);
    long s = base_score(buf, m);
    for (int r = 0; r < D.nrules; r++)
        if (memmem(buf, m, D.kw[r], strlen(D.kw[r])))
            s += D.pen[r];
    return s > 1000 ? 1000 : (int)s;
}

int detector_is_clean(const char *text, size_t n)
{
    return detector_score(text, n) < D.threshold;
}

int detector_threshold(void) { return D.threshold; }

static int load_bin(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "LMK1", 4) != 0) { fclose(f); return -1; }
    int32_t hdr[9];
    if (fread(hdr, 4, 9, f) != 9) { fclose(f); return -1; }
    D.nbuckets   = (uint32_t)hdr[0];
    D.ngram_n    = (uint32_t)hdr[1];
    D.scale      = hdr[2];
    D.bias       = hdr[3];
    D.cap        = hdr[4];
    D.w_mad10    = hdr[5];
    D.w_stop1000 = hdr[6];
    D.w_uniq1000 = hdr[7];
    if (D.scale <= 0 || D.nbuckets == 0 || D.nbuckets > (1u << 20)) { fclose(f); return -1; }
    D.ngram = calloc(D.nbuckets, sizeof(int32_t));
    if (!D.ngram) { fclose(f); return -1; }
    if (fread(D.ngram, sizeof(int32_t), D.nbuckets, f) != D.nbuckets) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static int load_conf(const char *path)
{
    D.threshold = 500;
    D.nrules = 0;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char key[64], word[MAX_KW]; int num;
        if (sscanf(line, "%63s %d", key, &num) == 2 && strcmp(key, "threshold") == 0) {
            D.threshold = num;
        } else if (sscanf(line, "%63s %31s %d", key, word, &num) == 3 &&
                   strcmp(key, "rule") == 0 && D.nrules < MAX_RULES) {
            for (char *q = word; *q; q++)
                if (*q >= 'A' && *q <= 'Z') *q += 32;
            strncpy(D.kw[D.nrules], word, MAX_KW - 1);
            D.kw[D.nrules][MAX_KW - 1] = '\0';
            D.pen[D.nrules] = num;
            D.nrules++;
        }
    }
    fclose(f);
    return 0;
}

int detector_load(const char *bin_path, const char *conf_path)
{
    for (int k = 0; k < NSTOP; k++)
        D.stop_hash[k] = fnv1a((const unsigned char *)STOPWORDS[k], strlen(STOPWORDS[k]));
    if (load_bin(bin_path) != 0) return -1;
    if (load_conf(conf_path) != 0) return -1;
    D.loaded = 1;
    return 0;
}
