/*
 * Description:
 * Device Driver for the Software-based TPM Emulator
 *
 * Copyright (C) 2004, 2006  Mario Strasser <mast@gmx.net>,
 *                           Heiko Stamer <stamer@gaos.org>
 * Project Homepage: http://tpm-emulator.berlios.de/
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "tpm.h"
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/devfs_fs_kernel.h>


/************************************************************************/

static struct semaphore tpm_emu_cdev_rmutex;

static struct {
  uint8_t *data;
  size_t size;
} tpm_emu_cdev_rbuffer;


static struct semaphore tpm_emu_cdev_wmutex;

static struct {
  uint8_t *data;
  size_t size;
} tpm_emu_cdev_wbuffer;


#define STATE_IS_OPEN 0
static uint32_t tpm_emu_cdev_state;

static int
tpm_emu_cdev_open(struct inode *inode, struct file *file)
{
	printk(KERN_DEBUG "%s()\n", __FUNCTION__);
	if (test_and_set_bit(STATE_IS_OPEN, (void*)&tpm_emu_cdev_state))
		return -EBUSY;
	return 0;
}

static int
tpm_emu_cdev_release(struct inode *inode, struct file *file)
{
	printk(KERN_DEBUG "%s()\n", __FUNCTION__);
	clear_bit(STATE_IS_OPEN, (void*)&tpm_emu_cdev_state);
	down(&tpm_emu_cdev_rmutex);
	if (tpm_emu_cdev_rbuffer.data != NULL) {
	    kfree(tpm_emu_cdev_rbuffer.data);
	    tpm_emu_cdev_rbuffer.data = NULL;
	}
	up(&tpm_emu_cdev_rmutex);
	down(&tpm_emu_cdev_wmutex);
	if (tpm_emu_cdev_wbuffer.data != NULL) {
	    kfree(tpm_emu_cdev_wbuffer.data);
	    tpm_emu_cdev_wbuffer.data = NULL;
	}
	up(&tpm_emu_cdev_wmutex);
	return 0;
}

static ssize_t
tpm_emu_cdev_read(struct file *filp, char __user *buf, size_t count,
		  loff_t *fpos)
{
	ssize_t retval = 0;
	printk(KERN_DEBUG "%s(%d)[in]\n", __FUNCTION__, count);
	
	down(&tpm_emu_cdev_rmutex);
	if ((size_t)*fpos >= tpm_emu_cdev_rbuffer.size)
		goto out;
	
	if (tpm_emu_cdev_rbuffer.data != NULL) {
		count = min(count, tpm_emu_cdev_rbuffer.size - (size_t)*fpos);
		count -= copy_to_user(buf,
			&tpm_emu_cdev_rbuffer.data[*fpos], count);
		*fpos += count;
		retval = count;
		if (tpm_emu_cdev_rbuffer.size == (size_t)*fpos) {
		        kfree(tpm_emu_cdev_rbuffer.data);
			tpm_emu_cdev_rbuffer.data = NULL;
		}
	}

out:
	up(&tpm_emu_cdev_rmutex);
	printk(KERN_DEBUG "%s(%d)[out]\n", __FUNCTION__, retval);
	return retval;
}

static ssize_t
tpm_emu_cdev_write(struct file *filp, const char __user *buf, size_t count,
		   loff_t *fpos)
{
	ssize_t retval = 0;
	printk(KERN_DEBUG "%s(%d)[in]\n", __FUNCTION__, count);

	down(&tpm_emu_cdev_wmutex);
	if (tpm_emu_cdev_wbuffer.data == NULL) {
		tpm_emu_cdev_wbuffer.data = kmalloc(count, GFP_KERNEL);
		if (tpm_emu_cdev_wbuffer.data == NULL) {
			retval = -ENOMEM;
			goto out;
		}
		tpm_emu_cdev_wbuffer.size = count;
		*fpos = 0;
		if (copy_from_user(&tpm_emu_cdev_wbuffer.data[*fpos],
				   buf, count)) {
			retval = -EFAULT;
			goto out;
		}
		*fpos += count;
		retval = count;
	}

out:
	up(&tpm_emu_cdev_wmutex);
	printk(KERN_DEBUG "%s(%d)[out]\n", __FUNCTION__, retval);
	return retval;
}

static int
tpm_emu_cdev_ioctl(struct inode *inode, struct file *file,
	unsigned int cmd, unsigned long arg)
{
	printk(KERN_DEBUG "%s(%d, %p)\n", __FUNCTION__, cmd, (char*)arg);
	return -ENOTTY;
}

/************************************************************************/

static int tpm_emu_recv(struct tpm_chip *chip, u8 * buf, size_t count)
{
	ssize_t retval = 0;
	printk(KERN_DEBUG "%s(%d)[in]\n", __FUNCTION__, count);

	/* Receiving Data */
	down(&tpm_emu_cdev_wmutex);
	if (tpm_emu_cdev_wbuffer.data == NULL)
	{
		retval = 0;
		goto out;
	}
	if (tpm_emu_cdev_wbuffer.size > count)
	{
		retval = -EIO;
		goto out;
	}
	memcpy(buf, tpm_emu_cdev_wbuffer.data, tpm_emu_cdev_wbuffer.size);
	retval = tpm_emu_cdev_wbuffer.size;
	kfree(tpm_emu_cdev_wbuffer.data);
	tpm_emu_cdev_wbuffer.data = NULL;
	
out:
	up(&tpm_emu_cdev_wmutex);
	printk(KERN_DEBUG "%s(%d)[out]\n", __FUNCTION__, retval);
	return retval;
}

static int tpm_emu_send(struct tpm_chip *chip, u8 * buf, size_t count)
{
	ssize_t retval = 0;
	printk(KERN_DEBUG "%s(%d)[in]\n", __FUNCTION__, count);
	
	/* Sending Data */
	down(&tpm_emu_cdev_rmutex);
	if (tpm_emu_cdev_rbuffer.data != NULL)
	{
		kfree(tpm_emu_cdev_rbuffer.data);
		tpm_emu_cdev_rbuffer.data = NULL;
		retval = -EIO;
		goto out;
	}
	tpm_emu_cdev_rbuffer.data = kmalloc(count, GFP_KERNEL);
	if (tpm_emu_cdev_rbuffer.data == NULL) {
		retval = -ENOMEM;
		goto out;
	}
	tpm_emu_cdev_rbuffer.size = count;
	memcpy(tpm_emu_cdev_rbuffer.data, buf, count);
	retval = count;
out:
	up(&tpm_emu_cdev_rmutex);
	printk(KERN_DEBUG "%s(%d)[out]\n", __FUNCTION__, retval);
	return retval;
}

static void tpm_emu_cancel(struct tpm_chip *chip)
{
	down(&tpm_emu_cdev_rmutex);
	if (tpm_emu_cdev_rbuffer.data != NULL)
	{
		kfree(tpm_emu_cdev_rbuffer.data);
		tpm_emu_cdev_rbuffer.data = NULL;
	}
	up(&tpm_emu_cdev_rmutex);
}

static u8 tpm_emu_status(struct tpm_chip *chip)
{
	u8 status = 0;
	
	/* Querying Status */
	down(&tpm_emu_cdev_wmutex);
	if (tpm_emu_cdev_wbuffer.data != NULL)
		status = 1;
	up(&tpm_emu_cdev_wmutex);
	return status;
}

static DEVICE_ATTR(pubek, S_IRUGO, tpm_show_pubek, NULL);
static DEVICE_ATTR(pcrs, S_IRUGO, tpm_show_pcrs, NULL);
static DEVICE_ATTR(caps, S_IRUGO, tpm_show_caps, NULL);
static DEVICE_ATTR(cancel, S_IWUSR | S_IWGRP, NULL, tpm_store_cancel);

static struct attribute *tpm_emu_attrs[] = {
	&dev_attr_pubek.attr,
	&dev_attr_pcrs.attr,
	&dev_attr_caps.attr,
	&dev_attr_cancel.attr,
	NULL,
};

static struct attribute_group tpm_emu_attr_grp = {
	.attrs = tpm_emu_attrs,
};

static struct file_operations tpm_emu_ops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.open = tpm_open,
	.read = tpm_read,
	.write = tpm_write,
	.release = tpm_release,
};

static struct tpm_vendor_specific tpm_emu = {
	.recv = tpm_emu_recv,
	.send = tpm_emu_send,
	.cancel = tpm_emu_cancel,
	.status = tpm_emu_status,
	.req_complete_mask = 1,
	.req_complete_val = 1,
	.req_canceled = 2,
	.attr_group = &tpm_emu_attr_grp,
	.miscdev = { .fops = &tpm_emu_ops, },
};

static struct platform_device *tpm_emu_pdev;

static struct device_driver tpm_emu_drv = {
	.name = "tpm_emu",
	.bus = &platform_bus_type, 
	.owner = THIS_MODULE,
	.suspend = tpm_pm_suspend,
	.resume = tpm_pm_resume,
};

static struct file_operations tpm_emu_cdev_ops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.open = tpm_emu_cdev_open,
	.read = tpm_emu_cdev_read,
	.write = tpm_emu_cdev_write,
	.release = tpm_emu_cdev_release,
	.ioctl = tpm_emu_cdev_ioctl,
};

struct tpm_emu_struct {
    dev_t region;
    struct cdev cdev;
};

static struct tpm_emu_struct tpm_emu_cdev;

static int __init init_tpm_emu(void)
{
	int rc = 0;

	printk(KERN_NOTICE \
		"Device Driver for the Software-based TPM Emulator\n");
	sema_init(&tpm_emu_cdev_rmutex, 1);
	sema_init(&tpm_emu_cdev_wmutex, 1);
	tpm_emu_cdev_state = 0;
	tpm_emu_cdev_rbuffer.data = NULL;
	tpm_emu_cdev_wbuffer.data = NULL;
	driver_register(&tpm_emu_drv);
	
	rc = alloc_chrdev_region(&tpm_emu_cdev.region, 0, 1, "tpm_emu");
	if (rc < 0)
		goto err_unreg_drv;
	cdev_init(&tpm_emu_cdev.cdev, &tpm_emu_cdev_ops);
	tpm_emu_cdev.cdev.owner = THIS_MODULE;
	tpm_emu_cdev.cdev.ops = &tpm_emu_cdev_ops;
	rc = cdev_add(&tpm_emu_cdev.cdev, tpm_emu_cdev.region, 1);
	if (rc)
		printk(KERN_NOTICE "Error %d returned from cdev_add()", rc);
	
	devfs_mk_cdev(tpm_emu_cdev.region, S_IFCHR | S_IRUGO | S_IWUGO,
		      "tpm_emu");

	if (IS_ERR
	    (tpm_emu_pdev =
	     platform_device_register_simple("tpm_emu", -1, NULL, 0))) {
		    rc = PTR_ERR(tpm_emu_pdev);
		    goto err_unreg_chrdev_region;
	}

	rc = tpm_register_hardware(&tpm_emu_pdev->dev, &tpm_emu);
	if (rc < 0)
		goto err_unreg_pdev;
	return 0;

err_unreg_pdev:
	platform_device_unregister(tpm_emu_pdev);
err_unreg_chrdev_region:
	unregister_chrdev_region(tpm_emu_cdev.region, 1);
err_unreg_drv:
	driver_unregister(&tpm_emu_drv);
	return rc;
}

static void __exit cleanup_tpm_emu(void)
{
	struct tpm_chip *chip = dev_get_drvdata(&tpm_emu_pdev->dev);
	
	if (chip) {
		tpm_remove_hardware(chip->dev);
		platform_device_unregister(tpm_emu_pdev);
	}
	devfs_remove("tpm_emu");
	cdev_del(&tpm_emu_cdev.cdev);
	unregister_chrdev_region(tpm_emu_cdev.region, 1);

	if (tpm_emu_cdev_rbuffer.data != NULL)
	{
		kfree(tpm_emu_cdev_rbuffer.data);
		tpm_emu_cdev_rbuffer.data = NULL;
	}
	if (tpm_emu_cdev_wbuffer.data != NULL)
	{
		kfree(tpm_emu_cdev_wbuffer.data);
		tpm_emu_cdev_wbuffer.data = NULL;
	}

	driver_unregister(&tpm_emu_drv);
}

module_init(init_tpm_emu);
module_exit(cleanup_tpm_emu);

MODULE_AUTHOR("Heiko Stamer <stamer@gaos.org>");
MODULE_DESCRIPTION("Device Driver for the Software-based TPM Emulator");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
