#!/usr/bin/env python3
"""
Integrate LZ4KDR (speed-tuned Huawei LZ4KD derivative, dual BSD/GPL) into a
Linux 4.9 kernel as a zram compression back-end.

Files created:
    include/linux/lz4kdr.h
    lib/lz4kd/lz4kdr_private.h
    lib/lz4kd/lz4kdr_encode_private.h
    lib/lz4kd/lz4kdr_encode.c
    lib/lz4kd/lz4kdr_decode.c
    lib/lz4kd/version.h
    lib/lz4kd/Makefile
    crypto/lz4kd.c

Files patched (each a single anchored insertion, idempotent):
    lib/Kconfig                       -> config LZ4KDR_COMPRESS
    lib/Makefile                      -> obj-$(CONFIG_LZ4KDR_COMPRESS) += lz4kd/
    crypto/Kconfig                    -> config CRYPTO_LZ4KD
    crypto/Makefile                   -> obj-$(CONFIG_CRYPTO_LZ4KD) += lz4kd.o
    drivers/block/zram/zcomp.c        -> backends[] gains "lz4kd"

Run from the kernel tree root:  python3 ksu_lz4kd_patch.py
Set KROOT to patch another tree: KROOT=/path/to/kernel python3 ...
"""
import os
import sys

KROOT = os.environ.get("KROOT", ".")

SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lz4kdr_src")


def rd(rel):
    with open(os.path.join(KROOT, rel), "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def wr(rel, text):
    p = os.path.join(KROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def edit(rel, old, new, tag):
    s = rd(rel)
    if new in s:
        print("[skip] %s (%s)" % (rel, tag))
        return
    if old not in s:
        print("[FAIL] %s: anchor not found (%s)" % (rel, tag))
        sys.exit(1)
    wr(rel, s.replace(old, new, 1))
    print("[ok]   %s (%s)" % (rel, tag))


# ---------------------------------------------------------------- source drop

def copy_sources():
    pairs = [
        ("lz4kdr.h",                 "include/linux/lz4kdr.h"),
        ("lz4kdr_private.h",         "lib/lz4kd/lz4kdr_private.h"),
        ("lz4kdr_encode_private.h",  "lib/lz4kd/lz4kdr_encode_private.h"),
        ("lz4kdr_encode.c",          "lib/lz4kd/lz4kdr_encode.c"),
        ("lz4kdr_decode.c",          "lib/lz4kd/lz4kdr_decode.c"),
        ("version.h",                "lib/lz4kd/version.h"),
    ]
    for src, dst in pairs:
        s = open(os.path.join(SRC_DIR, src), "r", encoding="utf-8").read()
        # the private headers include <linux/lz4kdr.h> already; nothing to rewrite
        wr(dst, s)
        print("[ok]   %s <- lz4kdr_src/%s" % (dst, src))

    wr("lib/lz4kd/Makefile",
       "obj-$(CONFIG_LZ4KDR_COMPRESS) += lz4kdr_encode.o lz4kdr_decode.o\n")
    print("[ok]   lib/lz4kd/Makefile")


# --------------------------------------------------------------- crypto glue

CRYPTO_C = r'''/*
 * LZ4KDR compression algorithm for the Linux crypto API.
 *
 * LZ4KDR is a speed-tuned derivative of Huawei's LZ4KD; its compressed
 * bitstream is byte-for-byte compatible with upstream LZ4KD.  This file
 * adapts it to the crypto compression API so that zram can select it as
 * a back-end through crypto_comp_compress()/crypto_comp_decompress().
 *
 * Return-value contract (see zcomp_compress()/__zram_bvec_write()):
 *   crypto_comp_compress() returning non-zero makes zram abort the page
 *   write with "Compression failed!".  An incompressible page is *not* an
 *   error: zram stores it raw whenever the reported length is PAGE_SIZE.
 *   So encoder status 0 (incompressible) and any negative status are both
 *   reported back as a PAGE_SIZE result, never as an error.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/lz4kdr.h>

struct lz4kd_ctx {
	void *state;
	unsigned int state_bytes;
};

static int lz4kd_crypto_init(struct crypto_tfm *tfm)
{
	struct lz4kd_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned int bytes = lz4kdr_encode_state_bytes_min();

	if (!bytes)
		return -EINVAL;

	ctx->state_bytes = bytes;
	ctx->state = vmalloc(bytes);
	if (!ctx->state)
		return -ENOMEM;

	return 0;
}

static void lz4kd_crypto_exit(struct crypto_tfm *tfm)
{
	struct lz4kd_ctx *ctx = crypto_tfm_ctx(tfm);

	vfree(ctx->state);
	ctx->state = NULL;
}

static int lz4kd_compress_crypto(struct crypto_tfm *tfm, const u8 *src,
				 unsigned int slen, u8 *dst,
				 unsigned int *dlen)
{
	struct lz4kd_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	if (unlikely(!ctx->state))
		return -ENOMEM;

	/* out_limit = 0: accept anything the encoder produces, let
	 * __zram_bvec_write() decide between compressed and raw. */
	ret = lz4kdr_encode(ctx->state, src, dst, slen, *dlen, 0);

	if (ret > 0) {
		*dlen = (unsigned int)ret;
		return 0;
	}

	/* Incompressible (0) or refused (<0): hand zram a PAGE_SIZE
	 * length, which makes it keep the raw page. */
	*dlen = PAGE_SIZE;
	return 0;
}

static int lz4kd_decompress_crypto(struct crypto_tfm *tfm, const u8 *src,
				   unsigned int slen, u8 *dst,
				   unsigned int *dlen)
{
	int ret = lz4kdr_decode(src, dst, slen, *dlen);

	if (ret < 0)
		return -EINVAL;

	*dlen = (unsigned int)ret;
	return 0;
}

static struct crypto_alg alg_lz4kd = {
	.cra_name		= "lz4kd",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct lz4kd_ctx),
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(alg_lz4kd.cra_list),
	.cra_init		= lz4kd_crypto_init,
	.cra_exit		= lz4kd_crypto_exit,
	.cra_u			= { .compress = {
	.coa_compress		= lz4kd_compress_crypto,
	.coa_decompress		= lz4kd_decompress_crypto } }
};

static int __init lz4kd_mod_init(void)
{
	return crypto_register_alg(&alg_lz4kd);
}

static void __exit lz4kd_mod_fini(void)
{
	crypto_unregister_alg(&alg_lz4kd);
}

module_init(lz4kd_mod_init);
module_exit(lz4kd_mod_fini);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LZ4KD (LZ4KDR) compression algorithm");
MODULE_ALIAS_CRYPTO("lz4kd");
'''


# ------------------------------------------------------------------- patches

def patch_lib_kconfig():
    edit("lib/Kconfig",
         "config LZ4_COMPRESS\n",
         "config LZ4KDR_COMPRESS\n"
         "\ttristate\n"
         "\tdefault n\n"
         "\thelp\n"
         "\t  LZ4KDR: speed-tuned derivative of Huawei's LZ4KD.  Its output\n"
         "\t  format is compatible with upstream LZ4KD.  Select this from a\n"
         "\t  user (e.g. CRYPTO_LZ4KD) rather than directly.\n"
         "\n"
         "config LZ4_COMPRESS\n",
         "LZ4KDR_COMPRESS")


def patch_lib_makefile():
    s = rd("lib/Makefile")
    old = "obj-$(CONFIG_LZ4_COMPRESS) += lz4/"
    new = "obj-$(CONFIG_LZ4KDR_COMPRESS) += lz4kd/\n" + old
    edit("lib/Makefile", old, new, "lz4kd obj")


def patch_crypto_kconfig():
    edit("crypto/Kconfig",
         'config CRYPTO_LZ4\n',
         'config CRYPTO_LZ4KD\n'
         '\ttristate "LZ4KD compression algorithm"\n'
         '\tselect LZ4KDR_COMPRESS\n'
         '\thelp\n'
         '\t  LZ4KD, as implemented by the speed-tuned LZ4KDR encoder.\n'
         '\t  Provides a zram back-end that trades a slightly slower\n'
         '\t  decompressor for a faster compressor versus plain LZ4.\n'
         '\n'
         '\t  Only selectable on top of the LZ4KDR library.\n'
         '\n'
         'config CRYPTO_LZ4\n',
         "CRYPTO_LZ4KD")


def patch_crypto_makefile():
    s = rd("crypto/Makefile")
    old = "obj-$(CONFIG_CRYPTO_LZ4) += lz4.o\n"
    new = old + "obj-$(CONFIG_CRYPTO_LZ4KD) += lz4kd.o\n"
    edit("crypto/Makefile", old, new, "lz4kd obj")


def patch_zcomp():
    edit("drivers/block/zram/zcomp.c",
         "#if IS_ENABLED(CONFIG_CRYPTO_LZ4HC)\n\t\"lz4hc\",\n#endif\n",
         "#if IS_ENABLED(CONFIG_CRYPTO_LZ4HC)\n\t\"lz4hc\",\n#endif\n"
         "#if IS_ENABLED(CONFIG_CRYPTO_LZ4KD)\n\t\"lz4kd\",\n#endif\n",
         "backends[] lz4kd")


def main():
    copy_sources()
    wr("crypto/lz4kd.c", CRYPTO_C)
    print("[ok]   crypto/lz4kd.c")
    patch_lib_kconfig()
    patch_lib_makefile()
    patch_crypto_kconfig()
    patch_crypto_makefile()
    patch_zcomp()
    print("done")


if __name__ == "__main__":
    main()
