#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backport BPF_PROG_TYPE_CGROUP_DEVICE (Linux 4.15) into the Huawei Kirin970 4.9 BSP.

Why: Android 12+ init drops the cgroup v1 'devices' controller and instead
attaches a cgroup-device BPF program to enforce the device whitelist.
Without BPF_PROG_TYPE_CGROUP_DEVICE the A12+ userspace cannot initialise
device permissions, so the system never reaches a bootable state.

Semantics implemented here (diverges from 4.15 on purpose, to match this BSP):
  * fork stores a SINGLE 'struct bpf_prog *' per (cgroup, attach_type),
    there is no 'struct bpf_prog_array' / 'BPF_PROG_RUN_ARRAY',
    so we dereference one program and call BPF_PROG_RUN() directly.
  * fork has no 'struct bpf_prog_ops', only 'struct bpf_verifier_ops'.
  * fork verifier calls is_valid_access(off,size,type,enum bpf_reg_type *),
    not the 4.15 'struct bpf_insn_access_aux *' variant.
  * fork cgroup.h has no task_dfl_cgroup(); css_set has ->dfl_cgrp, so we
    use task_css_set(current)->dfl_cgrp.
  * the hook is placed inside security/device_cgroup.c's
    __devcgroup_check_permission() (the approach mainline adopted by 6.1)
    instead of the 4.15 inline wrapper in include/linux/device_cgroup.h.
    This covers both inode and mknod paths with a single edit.

No program attached => no restriction (returns 0), so behaviour is unchanged
for every boot that does not use cgroup-device BPF.

Idempotent: re-running is a no-op.
"""

import os
import sys

ROOT = os.environ.get("KROOT", ".")

UAPI = "include/uapi/linux/bpf.h"
BCH = "include/linux/bpf-cgroup.h"
BCG = "kernel/bpf/cgroup.c"
DVCG = "security/device_cgroup.c"
SYSC = "kernel/bpf/syscall.c"


def read(rel):
    p = os.path.join(ROOT, rel)
    with open(p, "r", encoding="utf-8", errors="surrogateescape") as f:
        return p, f.read()


def write(p, s):
    with open(p, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(s)


def patch_uapi():
    p, s = read(UAPI)
    if "BPF_PROG_TYPE_CGROUP_DEVICE" in s:
        print("[skip] %s already patched" % UAPI)
        return

    old = (
        "\tBPF_PROG_TYPE_CGROUP_SKB,\n"
        "};\n"
        "\n"
        "enum bpf_attach_type {\n"
        "\tBPF_CGROUP_INET_INGRESS,\n"
        "\tBPF_CGROUP_INET_EGRESS,\n"
        "\t__MAX_BPF_ATTACH_TYPE\n"
        "};\n"
        "\n"
        "#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE\n"
    )
    new = (
        "\tBPF_PROG_TYPE_CGROUP_SKB,\n"
        "\tBPF_PROG_TYPE_CGROUP_DEVICE = 15,\n"
        "};\n"
        "\n"
        "enum bpf_attach_type {\n"
        "\tBPF_CGROUP_INET_INGRESS,\n"
        "\tBPF_CGROUP_INET_EGRESS,\n"
        "\tBPF_CGROUP_DEVICE = 6,\n"
        "\t__MAX_BPF_ATTACH_TYPE\n"
        "};\n"
        "\n"
        "#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE\n"
        "\n"
        "struct bpf_cgroup_dev_ctx {\n"
        "\t/* access_type encoded as (access << 16) | type */\n"
        "\t__u32 access_type;\n"
        "\t__u32 major;\n"
        "\t__u32 minor;\n"
        "};\n"
    )
    assert old in s, "uapi anchor not found in %s" % UAPI
    s = s.replace(old, new, 1)
    write(p, s)
    print("[ok] %s: BPF_PROG_TYPE_CGROUP_DEVICE=15, BPF_CGROUP_DEVICE=6, ctx struct" % UAPI)


def patch_bpf_cgroup_h():
    p, s = read(BCH)
    if "__cgroup_bpf_check_dev_permission" in s:
        print("[skip] %s already patched" % BCH)
        return

    # 1) declaration, inserted before the wrapper-macro comment block.
    #    (the __cgroup_bpf_run_filter() prototype uses mixed tab/space
    #     indentation, so it is a poor anchor; this comment is unique.)
    old = "/* Wrappers for __cgroup_bpf_run_filter() guarded by cgroup_bpf_enabled. */\n"
    new = (
        "int __cgroup_bpf_check_dev_permission(short dev_type, u32 major, u32 minor,\n"
        "\t\t\t\t      short access, enum bpf_attach_type type);\n"
        "\n"
    ) + old
    assert old in s, "decl anchor not found in %s" % BCH
    s = s.replace(old, new, 1)

    # 2) runtime macro, inserted before the '#else' non-BPF branch
    old2 = "#else\n\nstruct cgroup_bpf {};\n"
    new2 = (
        "#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access)  \\\n"
        "({                                                                     \\\n"
        "\tint __ret = 0;                                                 \\\n"
        "\tif (cgroup_bpf_enabled)                                        \\\n"
        "\t\t__ret = __cgroup_bpf_check_dev_permission(type, major, minor, \\\n"
        "\t\t\t\t\t  access, BPF_CGROUP_DEVICE); \\\n"
        "\t__ret;                                                         \\\n"
        "})\n"
        "\n"
        "#else\n"
        "\n"
        "struct cgroup_bpf {};\n"
    )
    assert old2 in s, "#else anchor not found in %s" % BCH
    s = s.replace(old2, new2, 1)

    # 3) stub for the !CONFIG_CGROUP_BPF case
    old3 = "#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk,skb) ({ 0; })\n"
    new3 = old3 + (
        "#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type,major,minor,access) ({ 0; })\n"
    )
    assert old3 in s, "stub anchor not found in %s" % BCH
    s = s.replace(old3, new3, 1)

    write(p, s)
    print("[ok] %s: declaration + BPF_CGROUP_RUN_PROG_DEVICE_CGROUP (+ stub)" % BCH)


def patch_bpf_cgroup_c():
    p, s = read(BCG)
    if "__cgroup_bpf_check_dev_permission" in s:
        print("[skip] %s already patched" % BCG)
        return

    # BPF_PROG_RUN() lives in include/linux/filter.h;
    # late_initcall() lives in include/linux/init.h
    old_inc = "#include <net/sock.h>\n"
    new_inc = "#include <net/sock.h>\n#include <linux/filter.h>\n#include <linux/init.h>\n"
    assert old_inc in s, "include anchor not found in %s" % BCG
    s = s.replace(old_inc, new_inc, 1)

    tail = "\nEXPORT_SYMBOL(__cgroup_bpf_run_filter);\n"
    assert tail in s, "tail anchor not found in %s" % BCG

    add = r'''

/* ------------------------------------------------------------------ *
 * cgroup device controller program (BPF_PROG_TYPE_CGROUP_DEVICE)
 * Backported from Linux 4.15. Adapted for this BSP: one program per
 * (cgroup, attach_type), run with BPF_PROG_RUN() directly.
 * ------------------------------------------------------------------ */

static const struct bpf_func_proto *cgroup_dev_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		return NULL;
	}
}

static bool cgroup_dev_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       enum bpf_reg_type *reg_type)
{
	/* writes are never allowed on this context */
	if (type == BPF_WRITE)
		return false;

	if (off < 0 || off >= sizeof(struct bpf_cgroup_dev_ctx))
		return false;

	/* the verifier guarantees that size > 0 */
	if (off % size != 0)
		return false;

	if (size != sizeof(__u32))
		return false;

	return true;
}

static const struct bpf_verifier_ops cg_dev_verifier_ops = {
	.get_func_proto		= cgroup_dev_func_proto,
	.is_valid_access	= cgroup_dev_is_valid_access,
};

static struct bpf_prog_type_list cg_dev_type = {
	.ops	= &cg_dev_verifier_ops,
	.type	= BPF_PROG_TYPE_CGROUP_DEVICE,
};

static int __init register_cg_dev_ops(void)
{
	bpf_register_prog_type(&cg_dev_type);
	return 0;
}
late_initcall(register_cg_dev_ops);

/*
 * Returns 0 if the access is permitted, -EPERM otherwise.
 * No attached program means "no restriction".
 */
int __cgroup_bpf_check_dev_permission(short dev_type, u32 major, u32 minor,
				      short access, enum bpf_attach_type type)
{
	struct cgroup *cgrp;
	struct bpf_prog *prog;
	struct bpf_cgroup_dev_ctx ctx = {
		.access_type = (access << 16) | dev_type,
		.major = major,
		.minor = minor,
	};
	int allow;

	rcu_read_lock();

	cgrp = task_css_set(current)->dfl_cgrp;
	if (!cgrp) {
		rcu_read_unlock();
		return 0;
	}

	prog = rcu_dereference(cgrp->bpf.effective[type]);
	if (!prog) {
		rcu_read_unlock();
		return 0;
	}

	allow = BPF_PROG_RUN(prog, &ctx);

	rcu_read_unlock();

	return allow ? 0 : -EPERM;
}
EXPORT_SYMBOL(__cgroup_bpf_check_dev_permission);
'''

    s = s + add
    write(p, s)
    print("[ok] %s: __cgroup_bpf_check_dev_permission + verifier ops + prog type" % BCG)


def patch_device_cgroup():
    p, s = read(DVCG)
    if "BPF_CGROUP_RUN_PROG_DEVICE_CGROUP" in s:
        print("[skip] %s already patched" % DVCG)
        return

    old_inc = "#include <linux/mutex.h>\n"
    new_inc = "#include <linux/mutex.h>\n#include <linux/bpf-cgroup.h>\n"
    assert old_inc in s, "include anchor not found in %s" % DVCG
    s = s.replace(old_inc, new_inc, 1)

    old_fn = (
        "\tstruct dev_cgroup *dev_cgroup;\n"
        "\tbool rc;\n"
        "\n"
        "\trcu_read_lock();\n"
        "\tdev_cgroup = task_devcgroup(current);\n"
    )
    new_fn = (
        "\tstruct dev_cgroup *dev_cgroup;\n"
        "\tbool rc;\n"
        "\n"
        "\t/* Android 12+ enforces the device whitelist through a cgroup\n"
        "\t * BPF program instead of the cgroup v1 devices controller. */\n"
        "\tif (BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access))\n"
        "\t\treturn -EPERM;\n"
        "\n"
        "\trcu_read_lock();\n"
        "\tdev_cgroup = task_devcgroup(current);\n"
    )
    assert old_fn in s, "function anchor not found in %s" % DVCG
    s = s.replace(old_fn, new_fn, 1)

    write(p, s)
    print("[ok] %s: BPF hook in __devcgroup_check_permission()" % DVCG)


def patch_syscall():
    p, s = read(SYSC)
    if "BPF_PROG_TYPE_CGROUP_DEVICE" in s:
        print("[skip] %s already patched" % SYSC)
        return

    # bpf_prog_load() guards non-SOCKET_FILTER types behind CAP_SYS_ADMIN.
    # bpfloader runs as root, so leaving this as-is is fine; no edit needed.

    # 1) BPF_PROG_ATTACH: add a BPF_CGROUP_DEVICE case next to the INET ones.
    #    The body is duplicated rather than shared so that the diff stays
    #    obvious and each case reads on its own.
    old_full = (
        "\tcase BPF_CGROUP_INET_INGRESS:\n"
        "\tcase BPF_CGROUP_INET_EGRESS:\n"
        "\t\tprog = bpf_prog_get_type(attr->attach_bpf_fd,\n"
        "\t\t\t\t\t BPF_PROG_TYPE_CGROUP_SKB);\n"
        "\t\tif (IS_ERR(prog))\n"
        "\t\t\treturn PTR_ERR(prog);\n"
        "\n"
        "\t\tcgrp = cgroup_get_from_fd(attr->target_fd);\n"
        "\t\tif (IS_ERR(cgrp)) {\n"
        "\t\t\tbpf_prog_put(prog);\n"
        "\t\t\treturn PTR_ERR(cgrp);\n"
        "\t\t}\n"
        "\n"
        "\t\tret = cgroup_bpf_update(cgrp, prog, attr->attach_type,\n"
        "\t\t\t\t\tattr->attach_flags & BPF_F_ALLOW_OVERRIDE);\n"
        "\t\tif (ret)\n"
        "\t\t\tbpf_prog_put(prog);\n"
        "\t\tcgroup_put(cgrp);\n"
        "\t\tbreak;\n"
    )
    assert old_full in s, "attach anchor not found in %s" % SYSC
    # Rewrite as: collect prog for both types, then one shared cgrp + update body.
    new_full = (
        "\tcase BPF_CGROUP_INET_INGRESS:\n"
        "\tcase BPF_CGROUP_INET_EGRESS:\n"
        "\t\tprog = bpf_prog_get_type(attr->attach_bpf_fd,\n"
        "\t\t\t\t\t BPF_PROG_TYPE_CGROUP_SKB);\n"
        "\t\tif (IS_ERR(prog))\n"
        "\t\t\treturn PTR_ERR(prog);\n"
        "\n"
        "\t\tcgrp = cgroup_get_from_fd(attr->target_fd);\n"
        "\t\tif (IS_ERR(cgrp)) {\n"
        "\t\t\tbpf_prog_put(prog);\n"
        "\t\t\treturn PTR_ERR(cgrp);\n"
        "\t\t}\n"
        "\n"
        "\t\tret = cgroup_bpf_update(cgrp, prog, attr->attach_type,\n"
        "\t\t\t\t\tattr->attach_flags & BPF_F_ALLOW_OVERRIDE);\n"
        "\t\tif (ret)\n"
        "\t\t\tbpf_prog_put(prog);\n"
        "\t\tcgroup_put(cgrp);\n"
        "\t\tbreak;\n"
        "\n"
        "\tcase BPF_CGROUP_DEVICE:\n"
        "\t\tprog = bpf_prog_get_type(attr->attach_bpf_fd,\n"
        "\t\t\t\t\t BPF_PROG_TYPE_CGROUP_DEVICE);\n"
        "\t\tif (IS_ERR(prog))\n"
        "\t\t\treturn PTR_ERR(prog);\n"
        "\n"
        "\t\tcgrp = cgroup_get_from_fd(attr->target_fd);\n"
        "\t\tif (IS_ERR(cgrp)) {\n"
        "\t\t\tbpf_prog_put(prog);\n"
        "\t\t\treturn PTR_ERR(cgrp);\n"
        "\t\t}\n"
        "\n"
        "\t\tret = cgroup_bpf_update(cgrp, prog, attr->attach_type,\n"
        "\t\t\t\t\tattr->attach_flags & BPF_F_ALLOW_OVERRIDE);\n"
        "\t\tif (ret)\n"
        "\t\t\tbpf_prog_put(prog);\n"
        "\t\tcgroup_put(cgrp);\n"
        "\t\tbreak;\n"
    )
    s = s.replace(old_full, new_full, 1)

    # 2) BPF_PROG_DETACH: accept BPF_CGROUP_DEVICE (body is shared already).
    old_d = (
        "\tswitch (attr->attach_type) {\n"
        "\tcase BPF_CGROUP_INET_INGRESS:\n"
        "\tcase BPF_CGROUP_INET_EGRESS:\n"
        "\t\tcgrp = cgroup_get_from_fd(attr->target_fd);\n"
    )
    new_d = (
        "\tswitch (attr->attach_type) {\n"
        "\tcase BPF_CGROUP_INET_INGRESS:\n"
        "\tcase BPF_CGROUP_INET_EGRESS:\n"
        "\tcase BPF_CGROUP_DEVICE:\n"
        "\t\tcgrp = cgroup_get_from_fd(attr->target_fd);\n"
    )
    assert old_d in s, "detach anchor not found in %s" % SYSC
    s = s.replace(old_d, new_d, 1)

    write(p, s)
    print("[ok] %s: BPF_PROG_ATTACH/DETACH accept BPF_CGROUP_DEVICE" % SYSC)


def main():
    print("KROOT = %s" % os.path.abspath(ROOT))
    patch_uapi()
    patch_bpf_cgroup_h()
    patch_bpf_cgroup_c()
    patch_device_cgroup()
    patch_syscall()
    print("devcg backport patch applied")


if __name__ == "__main__":
    sys.exit(main())
