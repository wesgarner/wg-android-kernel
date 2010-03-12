/* arch/arm/mach-msm/hw3d.c
 *
 * Register/Interrupt access for userspace 3D library.
 *
 * Copyright (C) 2007 Google, Inc.
 * Author: Brian Swetland <swetland@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/time.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/clk.h>
#include <linux/android_pmem.h>
#include <mach/board.h>

static DEFINE_SPINLOCK(hw3d_lock);
static DECLARE_WAIT_QUEUE_HEAD(hw3d_queue);
static int hw3d_pending;
static int hw3d_disabled;

static struct clk *grp_clk;
static struct clk *imem_clk;
DECLARE_MUTEX(hw3d_sem);
static unsigned int hw3d_granted;
static struct file *hw3d_granted_file;

static irqreturn_t hw3d_irq_handler(int irq, void *data)
{
	unsigned long flags;

	spin_lock_irqsave(&hw3d_lock, flags);
	if (!hw3d_disabled) {
		disable_irq(INT_GRAPHICS);
		hw3d_disabled = 1;
	}
	hw3d_pending = 1;
	spin_unlock_irqrestore(&hw3d_lock, flags);

	wake_up(&hw3d_queue);

	return IRQ_HANDLED;
}

static void hw3d_disable_interrupt(void)
{
	unsigned long flags;
	spin_lock_irqsave(&hw3d_lock, flags);
	if (!hw3d_disabled) {
		disable_irq(INT_GRAPHICS);
		hw3d_disabled = 1;
	}
	spin_unlock_irqrestore(&hw3d_lock, flags);
}

static long hw3d_wait_for_interrupt(void)
{
	unsigned long flags;
	int ret;

	for (;;) {
		spin_lock_irqsave(&hw3d_lock, flags);
		if (hw3d_pending) {
			hw3d_pending = 0;
			spin_unlock_irqrestore(&hw3d_lock, flags);
			return 0;
		}
		if (hw3d_disabled) {
			hw3d_disabled = 0;
			enable_irq(INT_GRAPHICS);
		}
		spin_unlock_irqrestore(&hw3d_lock, flags);

		ret = wait_event_interruptible(hw3d_queue, hw3d_pending);
		if (ret < 0) {
			hw3d_disable_interrupt();
			return ret;
		}
	}

	return 0;
}

#define HW3D_REGS_LEN 0x100000

static long hw3d_revoke_gpu(struct file *file)
{
<<<<<<< HEAD:arch/arm/mach-msm/hw3d.c
	int ret = 0;
	unsigned long user_start, user_len;
	struct pmem_region region = {.offset = 0x0, .len = HW3D_REGS_LEN};

	down(&hw3d_sem);
	if (!hw3d_granted) {
		goto end;
	}
	/* revoke the pmem region completely */
	if ((ret = pmem_remap(&region, file, PMEM_UNMAP)))
		goto end;
	get_pmem_user_addr(file, &user_start, &user_len);
	/* reset the gpu */
	clk_disable(grp_clk);
	clk_disable(imem_clk);
	hw3d_granted = 0;
end:
	up(&hw3d_sem);
=======
	struct hw3d_info *info = hw3d_info;
	if (MAJOR(file->f_dentry->d_inode->i_rdev) == MISC_MAJOR &&
	    (is_master(info, file) || is_client(info, file)))
		return 1;
	return 0;
}

void put_msm_hw3d_file(struct file *file)
{
	if (!is_msm_hw3d_file(file))
		return;
	fput(file);
}

int get_msm_hw3d_file(int fd, int region, uint32_t offs, unsigned long *pbase,
		      unsigned long *len, struct file **filp)
{
	struct hw3d_info *info = hw3d_info;
	struct file *file;
	struct hw3d_data *data;
	int ret = 0;

	if (unlikely(region >= HW3D_NUM_REGIONS)) {
		VDBG("hw3d: invalid region %d requested\n", region);
		return -EINVAL;
	} else if (unlikely(offs >= info->regions[region].size)) {
		VDBG("hw3d: offset %08x outside of the requested region %d\n",
		     offs, region);
		return -EINVAL;
	}

	file = fget(fd);
	if (unlikely(file == NULL)) {
		pr_info("%s: requested data from file descriptor that doesn't "
			"exist.", __func__);
		return -EINVAL;
	} else if (!is_msm_hw3d_file(file)) {
		ret = -1;
		goto err;
	}

	data = file->private_data;
	if (unlikely(!data)) {
		VDBG("hw3d: invalid file\n");
		ret = -EINVAL;
		goto err;
	}

	mutex_lock(&data->mutex);
	if (unlikely(!data->vmas[region])) {
		mutex_unlock(&data->mutex);
		VDBG("hw3d: requested hw3d region is not mapped\n");
		ret = -ENOENT;
		goto err;
	}

	*pbase = info->regions[region].pbase;
	*filp = file;
	*len = data->vmas[region]->vm_end - data->vmas[region]->vm_start;
	mutex_unlock(&data->mutex);
	return 0;

err:
	fput(file);
>>>>>>> 9ec61c8... [ARM] msm: hw3d: Clean up the interface to get file from fd:arch/arm/mach-msm/hw3d.c
	return ret;
}

static long hw3d_grant_gpu(struct file *file)
{
	int ret = 0;
	struct pmem_region region = {.offset = 0x0, .len = HW3D_REGS_LEN};

	down(&hw3d_sem);
	if (hw3d_granted) {
		ret = -1;
		goto end;
	}
	/* map the registers */
	if ((ret = pmem_remap(&region, file, PMEM_MAP)))
		goto end;
	clk_enable(grp_clk);
	clk_enable(imem_clk);
	hw3d_granted = 1;
	hw3d_granted_file = file;
end:
	up(&hw3d_sem);
	return ret;
}

static int hw3d_release(struct inode *inode, struct file *file)
{
	down(&hw3d_sem);
	/* if the gpu is in use, and its inuse by the file that was released */
	if (hw3d_granted && (file == hw3d_granted_file)) {
		clk_disable(grp_clk);
		clk_disable(imem_clk);
		hw3d_granted = 0;
		hw3d_granted_file = NULL;
	}
	up(&hw3d_sem);
	return 0;
}

static long hw3d_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case HW3D_REVOKE_GPU:
			return hw3d_revoke_gpu(file);
			break;
		case HW3D_GRANT_GPU:
			return hw3d_grant_gpu(file);
			break;
		case HW3D_WAIT_FOR_INTERRUPT:
			return hw3d_wait_for_interrupt();
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

static struct android_pmem_platform_data pmem_data = {
	.name = "hw3d",
	.start = 0xA0000000,
	.size = 0x100000,
	.no_allocator = 1,
	.cached = 0,
};

static int __init hw3d_init(void)
{
	int ret;

	grp_clk = clk_get(NULL, "grp_clk");
	if (IS_ERR(grp_clk))
		return PTR_ERR(grp_clk);
	
	imem_clk = clk_get(NULL, "imem_clk");
	if (IS_ERR(imem_clk)) {
		clk_put(grp_clk);
		return PTR_ERR(imem_clk);
	}
	ret = request_irq(INT_GRAPHICS, hw3d_irq_handler,
			  IRQF_TRIGGER_HIGH, "hw3d", 0);
	if (ret) {
		clk_put(grp_clk);
		clk_put(imem_clk);
		return ret;
	}
	hw3d_disable_interrupt();
	hw3d_granted = 0;

	return pmem_setup(&pmem_data, hw3d_ioctl, hw3d_release);
}

device_initcall(hw3d_init);
