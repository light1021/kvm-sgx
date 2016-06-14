/*
 * (C) Copyright 2015 Intel Corporation
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Kai Huang <kai.huang@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include "sgx.h"
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/mman.h>

static LIST_HEAD(sgx_vm_epc_buf_list);
static DEFINE_SPINLOCK(sgx_vm_epc_buf_lock);

#define	__HANDLE_START	1
static __u32 sgx_vm_epc_buf_nr = 0;
static __u32 sgx_vm_epc_buf_handle_top = __HANDLE_START;

static struct sgx_vm_epc_buffer *__alloc_epc_buf(unsigned int nr_pages);
static void __free_epc_buf(struct sgx_vm_epc_buffer *buf);
static void __insert_epc_buf(struct sgx_vm_epc_buffer *buf);
static void __remove_epc_buf(struct sgx_vm_epc_buffer *buf);
static struct sgx_vm_epc_buffer *__find_epc_buf(__u32 handle);

static __u32 __get_next_epc_buf_handle(void)
{
	__u32 i;

	if ((sgx_vm_epc_buf_nr + __HANDLE_START) == sgx_vm_epc_buf_handle_top)
		return sgx_vm_epc_buf_handle_top++;
	/* If some buffers have been freed, reuse their handle */
	for (i = __HANDLE_START; i < sgx_vm_epc_buf_handle_top; i++) {
		if (!__find_epc_buf(i | ISGX_VM_EPC))
			return i;
	}
	/* should never reach here, just make compiler happy */
	return sgx_vm_epc_buf_handle_top++;
}

static struct sgx_vm_epc_buffer *__alloc_epc_buf(unsigned int nr_pages)
{
	struct sgx_vm_epc_buffer *buf;
	unsigned int i;

	buf = kmalloc(sizeof (*buf), GFP_KERNEL);
	if (!buf) {
		pr_err("%s: out of memory\n", __func__);
		goto err;
	}
	INIT_LIST_HEAD(&buf->buf_list);
	INIT_LIST_HEAD(&buf->page_list);

	buf->nr_pages = nr_pages;
	for (i = 0; i < nr_pages; i++) {
		struct sgx_epc_page *epg;

		/* FIXME: use ATOMIC ? */
		epg = sgx_alloc_vm_epc_page(0);
		if (!epg) {
			pr_err("%s: out of EPC\n", __func__);
			goto err;
		}
		list_add_tail(&epg->free_list, &buf->page_list);
	}

	buf->handle = __get_next_epc_buf_handle();
	/* Set magic to indicate EPC for virtual machine */
	buf->handle |= ISGX_VM_EPC;

	sgx_vm_epc_buf_nr++;

	return buf;
err:
	if (buf) {
		__free_epc_buf(buf);
	}
	return NULL;
}

static void __free_epc_buf(struct sgx_vm_epc_buffer *buf)
{
	unsigned int i = 0;
	struct list_head secs_list;
	int ret;

	INIT_LIST_HEAD(&secs_list);
	while (!list_empty(&buf->page_list)) {
		struct sgx_epc_page *epg = list_first_entry(&buf->page_list,
				struct sgx_epc_page, free_list);
		list_del(&epg->free_list);
		ret = sgx_free_vm_epc_page(epg);
		if (!ret)
			i++;
		else if (ret == SGX_CHILD_PRESENT)
			list_add(&epg->free_list, &secs_list);
		else
			pr_err("Unexpected error code when EREMOVE EPC for "
					"KVM guest: pa 0x%lx, err %d\n",
					(unsigned long)epg->pa, ret);
	}

	while (!list_empty(&secs_list)) {
		struct sgx_epc_page *epg = list_first_entry(&secs_list,
				struct sgx_epc_page, free_list);

		list_del(&epg->free_list);
		ret = sgx_free_vm_epc_page(epg);
		if (!ret)
			i++;
		else
			pr_err("Unexpected error code when EREMOVE EPC for "
					"KVM guest: pa 0x%lx, err %d\n",
					(unsigned long)epg->pa, ret);
	}

	if (i < buf->nr_pages)
		pr_err("Freed less pages (0x%x) than buf->nr_pages (0x%x)\n",
				i, buf->nr_pages);

	sgx_vm_epc_buf_nr--;
	kfree(buf);
}

static void __insert_epc_buf(struct sgx_vm_epc_buffer *buf)
{
	list_add_tail(&buf->buf_list, &sgx_vm_epc_buf_list);
}

static void __remove_epc_buf(struct sgx_vm_epc_buffer *buf)
{
	list_del(&buf->buf_list);
}

static struct sgx_vm_epc_buffer *__find_epc_buf(__u32 handle)
{
	struct list_head *entry;
	list_for_each(entry, &sgx_vm_epc_buf_list) {
		struct sgx_vm_epc_buffer *buf = list_entry(entry,
				struct sgx_vm_epc_buffer, buf_list);
		if (buf->handle == handle)
			return buf;
	}
	return NULL;
}

struct sgx_vm_epc_buffer *sgx_find_vm_epc_buffer(__u32 handle)
{
	struct sgx_vm_epc_buffer *buf;

	spin_lock(&sgx_vm_epc_buf_lock);
	buf = __find_epc_buf(handle);
	spin_unlock(&sgx_vm_epc_buf_lock);

	return buf;
}

int sgx_alloc_vm_epc_buffer(unsigned int npages, __u32 *handlep)
{
	struct sgx_vm_epc_buffer *buf;

	pr_info("%s: nr_pages = 0x%lx\n", __func__,
			(unsigned long)npages);

	if (!npages) {
		pr_info("%s: npages = 0..\n", __func__);
		return -EINVAL;
	}

	spin_lock(&sgx_vm_epc_buf_lock);
	buf = __alloc_epc_buf(npages);
	if (!buf) {
		spin_unlock(&sgx_vm_epc_buf_lock);
		pr_err("%s: alloc_epc_buf failed\n", __func__);
		return -EINVAL;
	}

	__insert_epc_buf(buf);

	*handlep = buf->handle;

	spin_unlock(&sgx_vm_epc_buf_lock);

	return 0;
}

int sgx_free_vm_epc_buffer(__u32 handle)
{
	struct sgx_vm_epc_buffer *buf;

	pr_info("%s: buf handle = 0x%x\n", __func__, handle);

	spin_lock(&sgx_vm_epc_buf_lock);
	buf = __find_epc_buf(handle);
	if (!buf) {
		pr_info("%s: __find_epc_buf failed\n", __func__);
		spin_unlock(&sgx_vm_epc_buf_lock);
		return -EINVAL;
	}
	__remove_epc_buf(buf);
	__free_epc_buf(buf);
	spin_unlock(&sgx_vm_epc_buf_lock);

	pr_info("%s: succeed.\n", __func__);
	return 0;
}

int sgx_map_vm_epc_buffer(struct vm_area_struct *vma, __u32 handle)
{
	unsigned long addr, npages;
	struct list_head *entry;
	struct sgx_epc_page *epg;
	struct sgx_vm_epc_buffer *buf;

	pr_info("%s: handle = 0x%lx\n", __func__, (unsigned long)handle);

	buf = sgx_find_vm_epc_buffer(handle);
	if (!buf) {
		pr_err("%s: sgx_find_vm_epc_buffer failed\n", __func__);
		return -EINVAL;
	}

	npages = ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT);
	if (buf->nr_pages != npages) {
		pr_err("%s: buf size doesn't match with vma size: "
				"buf->nr_pages 0x%lx, vma->nr_pages 0x%lx\n",
				__func__, (unsigned long)buf->nr_pages,
				(unsigned long)npages);
		return -EINVAL;
	}

	/* FIXME: vm_insert_pfn means VM_MAPPFN cannot co-exists with below 3
	 * flags */
	vma->vm_flags &= ~(VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC);

	addr = vma->vm_start;
	list_for_each(entry, &buf->page_list) {
		epg = list_entry(entry, struct sgx_epc_page, free_list);
		if (vm_insert_pfn(vma, addr, epg->pa >> PAGE_SHIFT)) {
			pr_err("%s: vm_insert_pfn failed: "
					"addr: 0x%lx, epg->pa: 0x%lx\n",
					__func__, (unsigned long)addr,
					(unsigned long)epg->pa);
			return -EINVAL;
		}
		addr += PAGE_SIZE;
	}
	pr_info("%s: leave...\n", __func__);

	return 0;
}
