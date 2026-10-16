/*
 * gen_tokens - generate src/tokens_gen.c from whatsmeow's binary/token/token.go
 *
 * usage: gen_tokens <path/to/whatsmeow/binary/token/token.go> <out.c>
 *
 * Plain C99 (replaces the former Python script). The generated file is
 * committed, so building cmeow never needs this tool.
 *
 * It understands exactly the subset of Go used by token.go: double-quoted
 * strings without escape sequences or non-ASCII bytes. Anything else aborts,
 * so a future change in whatsmeow fails loudly instead of corrupting tables.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct list {
    char **s;
    size_t n, cap;
};

struct rev {
    const char *s;
    int dict; /* -1 for single-byte tokens */
    int idx;
};

static void die(const char *msg)
{
    fprintf(stderr, "gen_tokens: %s\n", msg);
    exit(1);
}

static void *xrealloc(void *p, size_t n)
{
    void *r = realloc(p, n);
    if (r == NULL)
        die("out of memory");
    return r;
}

static void list_add(struct list *l, const char *s, size_t n)
{
    char *c;

    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->s = (char **)xrealloc(l->s, l->cap * sizeof(char *));
    }
    c = (char *)xrealloc(NULL, n + 1);
    memcpy(c, s, n);
    c[n] = '\0';
    l->s[l->n++] = c;
}

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *b;

    if (f == NULL)
        die("cannot open input");
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = (char *)xrealloc(NULL, (size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n)
        die("short read");
    b[n] = '\0';
    fclose(f);
    return b;
}

/* Read quoted strings from *p until the matching '}' (brace depth 0). */
static void read_strings(const char **p, struct list *out)
{
    const char *s = *p;
    int depth = 1;

    while (*s && depth > 0) {
        if (*s == '{') {
            depth++;
        } else if (*s == '}') {
            depth--;
        } else if (*s == '"') {
            const char *start = ++s;

            while (*s && *s != '"') {
                if (*s == '\\')
                    die("escape sequence in token string");
                if ((unsigned char)*s >= 0x80)
                    die("non-ASCII byte in token string");
                s++;
            }
            if (*s != '"')
                die("unterminated string");
            if (depth == 1)
                list_add(out, start, (size_t)(s - start));
        }
        s++;
    }
    if (depth != 0)
        die("unbalanced braces");
    *p = s;
}

static const char *find_after(const char *hay, const char *needle)
{
    const char *r = strstr(hay, needle);
    if (r == NULL) {
        fprintf(stderr, "gen_tokens: '%s' not found\n", needle);
        exit(1);
    }
    return r + strlen(needle);
}

static int cmp_rev(const void *a, const void *b)
{
    return strcmp(((const struct rev *)a)->s, ((const struct rev *)b)->s);
}

static void put_c_string(FILE *o, const char *s)
{
    fputc('"', o);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\')
            fputc('\\', o);
        fputc(*s, o);
    }
    fputc('"', o);
}

int main(int argc, char **argv)
{
    char *src;
    const char *p;
    struct list single = {0, 0, 0}, dicts[4];
    struct rev *all, *ssorted, *dsorted;
    size_t i, d, total, ns, nd, un_s = 0, un_d = 0, w;
    int dict_version = 0;
    FILE *o;

    if (argc != 3) {
        fprintf(stderr, "usage: %s token.go out.c\n", argv[0]);
        return 2;
    }
    src = slurp(argv[1]);
    memset(dicts, 0, sizeof(dicts));

    p = find_after(src, "SingleByteTokens = [...]string{");
    read_strings(&p, &single);

    p = find_after(src, "DoubleByteTokens = [...][]string{");
    for (d = 0; d < 4; d++) {
        p = strchr(p, '{');
        if (p == NULL)
            die("expected 4 double-byte dictionaries");
        p++;
        read_strings(&p, &dicts[d]);
    }

    p = strstr(src, "const DictVersion = ");
    if (p != NULL)
        dict_version = atoi(p + strlen("const DictVersion = "));

    /* ---- reverse indexes ---- */
    all = (struct rev *)xrealloc(NULL, (single.n + 1) * sizeof(*all));
    ssorted = (struct rev *)xrealloc(NULL, (single.n + 1) * sizeof(*all));
    for (i = 0; i < single.n; i++) {
        all[i].s = single.s[i];
        all[i].dict = -1;
        all[i].idx = (int)i;
    }
    /* qsort is not stable, so ties are resolved explicitly by index: LAST wins */
    ns = single.n;
    {
        size_t k;
        qsort(all, ns, sizeof(*all), cmp_rev);
        for (k = 0, w = 0; k < ns; k++) {
            if (all[k].s[0] == '\0')
                continue;
            if (w > 0 && strcmp(ssorted[w - 1].s, all[k].s) == 0) {
                if (all[k].idx > ssorted[w - 1].idx)
                    ssorted[w - 1] = all[k];
                continue;
            }
            ssorted[w++] = all[k];
        }
        un_s = w;
    }
    free(all);

    total = dicts[0].n + dicts[1].n + dicts[2].n + dicts[3].n;
    all = (struct rev *)xrealloc(NULL, (total + 1) * sizeof(*all));
    dsorted = (struct rev *)xrealloc(NULL, (total + 1) * sizeof(*all));
    nd = 0;
    for (d = 0; d < 4; d++)
        for (i = 0; i < dicts[d].n; i++) {
            all[nd].s = dicts[d].s[i];
            all[nd].dict = (int)d;
            all[nd].idx = (int)i;
            nd++;
        }
    qsort(all, nd, sizeof(*all), cmp_rev);
    for (i = 0, w = 0; i < nd; i++) {
        if (w > 0 && strcmp(dsorted[w - 1].s, all[i].s) == 0) {
            /* later dictionary / later index wins, as in Go's map overwrite */
            if (all[i].dict > dsorted[w - 1].dict ||
                (all[i].dict == dsorted[w - 1].dict && all[i].idx > dsorted[w - 1].idx))
                dsorted[w - 1] = all[i];
            continue;
        }
        dsorted[w++] = all[i];
    }
    un_d = w;

    /* ---- emit ---- */
    o = fopen(argv[2], "wb");
    if (o == NULL)
        die("cannot open output");
    fprintf(o, "/* GENERATED by tools/gen_tokens.c from whatsmeow binary/token/token.go - DO NOT EDIT.\n");
    fprintf(o, " * See include/common.h for license and attribution. */\n");
    fprintf(o, "#include \"token.h\"\n\n");
    fprintf(o, "const int cm_dict_version = %d;\n\n", dict_version);

    fprintf(o, "const char *const cm_single_tokens[] = {\n");
    for (i = 0; i < single.n; i++) {
        fprintf(o, "    ");
        put_c_string(o, single.s[i]);
        fprintf(o, ",\n");
    }
    fprintf(o, "};\n");
    fprintf(o, "const size_t cm_single_token_count = %lu;\n\n", (unsigned long)single.n);

    for (d = 0; d < 4; d++) {
        fprintf(o, "static const char *const cm_dict%lu[] = {\n", (unsigned long)d);
        for (i = 0; i < dicts[d].n; i++) {
            fprintf(o, "    ");
            put_c_string(o, dicts[d].s[i]);
            fprintf(o, ",\n");
        }
        fprintf(o, "};\n");
    }
    fprintf(o, "\nconst struct cm_dict cm_double_dicts[4] = {\n");
    for (d = 0; d < 4; d++)
        fprintf(o, "    { cm_dict%lu, %lu },\n", (unsigned long)d, (unsigned long)dicts[d].n);
    fprintf(o, "};\n\n");

    fprintf(o, "const struct cm_tok_single cm_tok_single_sorted[] = {\n");
    for (i = 0; i < un_s; i++) {
        fprintf(o, "    { ");
        put_c_string(o, ssorted[i].s);
        fprintf(o, ", %d },\n", ssorted[i].idx);
    }
    fprintf(o, "};\n");
    fprintf(o, "const size_t cm_tok_single_sorted_len = %lu;\n\n", (unsigned long)un_s);

    fprintf(o, "const struct cm_tok_double cm_tok_double_sorted[] = {\n");
    for (i = 0; i < un_d; i++) {
        fprintf(o, "    { ");
        put_c_string(o, dsorted[i].s);
        fprintf(o, ", %d, %d },\n", dsorted[i].dict, dsorted[i].idx);
    }
    fprintf(o, "};\n");
    fprintf(o, "const size_t cm_tok_double_sorted_len = %lu;\n", (unsigned long)un_d);
    if (fclose(o) != 0)
        die("write error");

    fprintf(stderr, "single=%lu dicts=[%lu,%lu,%lu,%lu] unique_single=%lu unique_double=%lu version=%d\n",
            (unsigned long)single.n, (unsigned long)dicts[0].n, (unsigned long)dicts[1].n,
            (unsigned long)dicts[2].n, (unsigned long)dicts[3].n, (unsigned long)un_s,
            (unsigned long)un_d, dict_version);
    return 0;
}
