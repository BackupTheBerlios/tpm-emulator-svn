/* Software-Based Trusted Platform Module (TPM) Emulator for Linux 
 * Copyright (C) 2004 Mario Strasser <mast@gmx.net>,
 *
 * This module is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, 
 * or (at your option) any later version.  
 *
 * This module is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 *
 * $Id$
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include "linux_module.h"
#include "tpm/tpm_emulator.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mario Strasser <mast@gmx.net>");
MODULE_DESCRIPTION("Trusted Platform Module (TPM) Emulator");
MODULE_SUPPORTED_DEVICE(TPM_DEVICE_NAME);

/* module startup parameters */
char *startup = "save";
MODULE_PARM(startup, "s");
MODULE_PARM_DESC(startup, " Sets the startup mode of the TPM. "
  "Possible values are 'clear', 'save' (default) and 'deactivated.");
char *storage_file = "/var/tpm/tpm_emulator-1.2.0.1";
MODULE_PARM(storage_file, "s");
MODULE_PARM_DESC(storage_file, " Sets the persistent-data storage " 
  "file of the TPM.");

/* TPM lock */
static struct semaphore tpm_mutex;

/* TPM command response */
static struct {
  uint8_t *data;
  uint32_t size;
} tpm_response;

/* module state */
#define STATE_IS_OPEN 0
static uint32_t module_state;

static int tpm_open(struct inode *inode, struct file *file)
{
  debug("%s()", __FUNCTION__);
  if (test_and_set_bit(STATE_IS_OPEN, (void*)&module_state)) return -EBUSY;
  return 0;
}

static int tpm_release(struct inode *inode, struct file *file)
{
  debug("%s()", __FUNCTION__);
  clear_bit(STATE_IS_OPEN, (void*)&module_state);
  return 0;
}

static ssize_t tpm_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
  debug("%s(%d)", __FUNCTION__, count);
  down(&tpm_mutex);
  if (tpm_response.data != NULL) {
    count = min(count, (size_t)tpm_response.size - (size_t)*ppos);
    count -= copy_to_user(buf, &tpm_response.data[*ppos], count);
    *ppos += count;
  } else {
    count = 0;
  }
  up(&tpm_mutex);
  return count;
}

static ssize_t tpm_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
  debug("%s(%d)", __FUNCTION__, count);
  down(&tpm_mutex);
  *ppos = 0;
  if (tpm_response.data != NULL) kfree(tpm_response.data);
  if (tpm_handle_command(buf, count, &tpm_response.data, 
                         &tpm_response.size) != 0) { 
    count = -1;
    tpm_response.data = NULL;
  }
  up(&tpm_mutex);
  return count;
}

static int tpm_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
  debug("%s(%d, %ld)", __FUNCTION__, cmd, arg);
  return -1;
}

struct file_operations fops = {
  .owner   = THIS_MODULE,
  .open    = tpm_open,
  .release = tpm_release,
  .read    = tpm_read,
  .write   = tpm_write,
  .ioctl   = tpm_ioctl,
};

static struct miscdevice tpm_dev = {
  .minor      = TPM_DEVICE_MINOR, 
  .name       = TPM_DEVICE_NAME, 
  .fops       = &fops,
};

int __init init_tpm_module(void)
{
  int res = misc_register(&tpm_dev);
  if (res != 0) {
    error("misc_register() failed for minor %d\n", TPM_DEVICE_MINOR);
    return res;
  }
  /* initialize variables */
  sema_init(&tpm_mutex, 1);
  module_state = 0;
  tpm_response.data = NULL;    
  /* initialize TPM emulator */
  if (!strcmp(startup, "clear")) {
    tpm_emulator_init(1);
  } else if (!strcmp(startup, "save")) { 
    tpm_emulator_init(2);
  } else if (!strcmp(startup, "deactivated")) {
    tpm_emulator_init(3);
  } else {
    error("invalid startup mode '%s'; must be 'clear', "
      "'save' (default) or 'deactivated", startup);
    misc_deregister(&tpm_dev);
    return -EINVAL;
  }
  return 0;
}

void __exit cleanup_tpm_module(void)
{
  tpm_emulator_shutdown();
  misc_deregister(&tpm_dev);
}

module_init(init_tpm_module);
module_exit(cleanup_tpm_module);

