/* Copyright 2015 yiyuanzhong@gmail.com (Yiyuan Zhong)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>

#include "fullnat.h"

#define PROCFS_FILENAME "fullnat_mode"
#define PROCFS_BUFFER_LENGTH 16

static ssize_t procfs_write(struct file *file,
                            const char *buffer,
                            size_t length,
                            loff_t *offset)
{
    char buf[PROCFS_BUFFER_LENGTH + 1];
    unsigned long ret;
    char *ptr;

    if (*offset) {
        return -EINVAL;
    } else if (!length) {
        return 0;
    }

    *offset += length;
    if (length > PROCFS_BUFFER_LENGTH) {
        return -EINVAL;
    }

    if (copy_from_user(buf, buffer, length)) {
        return -EFAULT;
    }

    buf[length] = '\0';
    ret = simple_strtoul(buf, &ptr, 10);
    if (ptr == buf) {
        return -EINVAL;
    } else if (*ptr != '\r' && *ptr != '\n' && *ptr != '\0') {
        return -EINVAL;
    }

    if (fullnat_mode_set((int)ret)) {
        return -EINVAL;
    }

    return length;
}

static int procfs_seq_show(struct seq_file *p, void *v)
{
    seq_printf(p, "%d\n", fullnat_mode_get());
    return 0;
}

static int procfs_open(struct inode *inode, struct file *file)
{
    if (!try_module_get(THIS_MODULE)) {
        return -EPERM;
    }

    return single_open(file, procfs_seq_show, NULL);
}

static int procfs_close(struct inode *inode, struct file *file)
{
    single_release(inode, file);
    module_put(THIS_MODULE);
    return 0;
}

static struct file_operations g_fileops = {
    .open    = procfs_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .write   = procfs_write,
    .release = procfs_close,
};

int procfs_initialize(void)
{
    if (!proc_create_data(PROCFS_FILENAME,
                          S_IRUGO | S_IWUSR,
                          init_net.proc_net,
                          &g_fileops,
                          NULL)) {

        return -ENOMEM;
    }

    return 0;
}

void procfs_shutdown(void)
{
    remove_proc_entry(PROCFS_FILENAME, init_net.proc_net);
}
