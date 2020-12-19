// SPDX-License-Identifier: GPL-2.0
/* hello.c */
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

int chardev_init(void);
void chardev_exit(void);

static int device_open(struct inode*, struct file*);
static int device_close(struct inode*, struct file*);
static ssize_t device_read(struct file*, char* __user, size_t, loff_t*);
static ssize_t device_write(struct file*, const char* __user, size_t, loff_t*);

struct cdev* mcdev; /* name of character driver */
int major_number;   /* major number extracted by dev_t*/
dev_t dev_num;      /* major number that the kernel gives*/

#define DEVICENAME "hellochar"
#define CIRCULAR_BUFFER_SIZE 256

struct circular_buffer
{
    char* data;
    size_t size;
    size_t data_start;
    size_t data_end;
    struct mutex buffer_mutex;
    struct mutex write_mutex;
    struct mutex read_mutex;
    struct semaphore fill_count;
    struct semaphore empty_count;
};

struct circular_buffer* main_buffer;

/* Create circular buffer with given size. Return NULL on memory allocation
 * error.
 */
static struct circular_buffer* create_circular_buffer(size_t size);

/* Destroy circular buffer.
 */
static void destroy_circular_buffer(struct circular_buffer* buffer);

/* Write userspace data pointed by `data` with size `size` to circular buffer
 * `buffer`, `size` should not be larger than buffer size.
 */
static ssize_t write_circular_buffer_block(struct circular_buffer* buffer,
                                           const char* __user data,
                                           size_t size,
                                           bool* interrupted);

/* Write userspace data pointed by `data` with size `size` to circular bufer
 * `buffer`, block when there is not enough space in buffer.
 */
static ssize_t write_circular_buffer(struct circular_buffer* buffer,
                                     const char* __user data,
                                     size_t size);

/* Read data from to circular buffer `buffer` to userspace memory pointed by
 * `data` with size `size`, `size` should not be larger than buffer size.
 */
static ssize_t read_circular_buffer_block(struct circular_buffer* buffer,
                                          char* __user data,
                                          size_t size,
                                          bool* interrupted);

/* Read data from to circular buffer `buffer` to userspace memory pointed by
 * `data` with size `size`, block if buffer is empty.
 */
static ssize_t read_circular_buffer(struct circular_buffer* buffer,
                                    char* __user data,
                                    size_t size);

static struct circular_buffer*
create_circular_buffer(size_t size)
{
    char* data = kmalloc(size, GFP_KERNEL);
    if (data == NULL)
        return NULL;
    struct circular_buffer* buffer =
      kmalloc(sizeof(struct circular_buffer), GFP_KERNEL);
    if (buffer == NULL) {
        kfree(data);
        return NULL;
    }
    buffer->data = data;
    buffer->size = size;
    buffer->data_start = 0;
    buffer->data_end = 0;
    mutex_init(&(buffer->buffer_mutex));
    mutex_init(&(buffer->write_mutex));
    mutex_init(&(buffer->read_mutex));
    sema_init(&(buffer->fill_count), 0);
    sema_init(&(buffer->empty_count), size);
    return buffer;
}

static void
destroy_circular_buffer(struct circular_buffer* buffer)
{
    kfree(buffer->data);
    kfree(buffer);
}

static ssize_t
write_circular_buffer_block(struct circular_buffer* buffer,
                            const char* __user data,
                            size_t size,
                            bool* interrupted)
{
    pr_info("[HelloChar] write_circular_buffer_block() called with buffer=%p, "
            "data=%p, size=%lu\n",
            buffer,
            data,
            size);
    *interrupted = false;
    if (size > buffer->size)
        return -EDOM;
	int i;
    for (i = 0; i < size; i++)
        if (down_interruptible(&(buffer->empty_count)) < 0) {
            size = i;
            *interrupted = true;
            break;
        }

    if (size == 0)
        return 0;

    mutex_lock(&(buffer->buffer_mutex));

    ssize_t result = size;
    size_t data_end = buffer->data_end;
    buffer->data_end = (data_end + size) % buffer->size;

    mutex_unlock(&(buffer->buffer_mutex));

    if ((data_end + size) > buffer->size) {
        size_t first_read_size = buffer->size - data_end;
        if (copy_from_user(buffer->data + data_end, data, first_read_size) != 0)
            result = -EFAULT;
        else if (copy_from_user(buffer->data,
                                data + first_read_size,
                                size - first_read_size) != 0)
            result = -EFAULT;
    } else {
        if (copy_from_user(buffer->data + data_end, data, size) != 0)
            result = -EFAULT;
    }

    for (i = 0; i < size; i++)
        up(&(buffer->fill_count));

    return result;
}

static ssize_t
write_circular_buffer(struct circular_buffer* buffer,
                      const char* __user data,
                      size_t size)
{
    if (mutex_lock_interruptible(&(buffer->write_mutex)) < 0)
        return 0;
    ssize_t total = 0;
    bool interrupted = false;
    while (size > buffer->size) {
        ssize_t result =
          write_circular_buffer_block(buffer, data, buffer->size, &interrupted);
        pr_info("[HelloChar] write_circular_buffer_block result is %ld\n",
                result);
        if (result < 0) {
            mutex_unlock(&(buffer->write_mutex));
            return result;
        }
        total += result;
        if (interrupted) {
            mutex_unlock(&(buffer->write_mutex));
            return total;
        }
        size -= buffer->size;
        data += buffer->size;
    }
    size_t result =
      write_circular_buffer_block(buffer, data, size, &interrupted);
    pr_info("[HelloChar] write_circular_buffer_block result is %ld\n", result);
    if (result < 0) {
        mutex_unlock(&(buffer->write_mutex));
        return result;
    }
    total += result;
    mutex_unlock(&(buffer->write_mutex));
    return total;
}

static ssize_t
read_circular_buffer_block(struct circular_buffer* buffer,
                           char* __user data,
                           size_t size,
                           bool* interrupted)
{
    pr_info("[HelloChar] read_circular_buffer_block() called with buffer=%p, "
            "data=%p, size=%lu\n",
            buffer,
            data,
            size);
    *interrupted = false;
    if (size == 0)
        return 0;
    if (size > buffer->size)
        return -EDOM;

    if (down_interruptible(&(buffer->fill_count)) != 0) {
        *interrupted = true;
        return 0;
    }
int i;
    for (i = 1; i < size; i++)
        if (down_trylock(&(buffer->fill_count)) != 0) {
            size = i;
            break;
        }

    if (size == 0)
        return 0;

    mutex_lock(&(buffer->buffer_mutex));

    ssize_t result = size;
    size_t data_start = buffer->data_start;
    buffer->data_start = (buffer->data_start + size) % buffer->size;

    mutex_unlock(&(buffer->buffer_mutex));

    if ((data_start + size) > buffer->size) {
        size_t first_read_size = buffer->size - data_start;
        if (copy_to_user(data, buffer->data + data_start, first_read_size) != 0)
            result = -EFAULT;
        else if (copy_to_user(data + first_read_size,
                              buffer->data,
                              size - first_read_size) != 0)
            result = -EFAULT;
    } else {
        if (copy_to_user(data, buffer->data + data_start, size) != 0)
            result = -EFAULT;
    }
    for (i = 0; i < size; i++)
        up(&(buffer->empty_count));

    return result;
}

static ssize_t
read_circular_buffer(struct circular_buffer* buffer,
                     char* __user data,
                     size_t size)
{
    if (mutex_lock_interruptible(&(buffer->read_mutex)) < 0)
        return 0;
    ssize_t total = 0;
    bool interrupted = false;
    while (size > 0) {
        ssize_t result = read_circular_buffer_block(
          buffer,
          data,
          (size > buffer->size) ? buffer->size : size,
          &interrupted);
        pr_info("[HelloChar] read_circular_buffer_block result is %ld\n",
                result);
        if (result < 0) {
            mutex_unlock(&(buffer->read_mutex));
            return result;
        }
        total += result;
        size -= result;
        data += result;
        if (interrupted)
            break;
    }
    mutex_unlock(&(buffer->read_mutex));
    return total;
}

static int
device_open(struct inode* inode, struct file* fp)
{
    pr_info("[HelloChar] open() called\n");

    if (main_buffer == NULL)
        main_buffer = create_circular_buffer(CIRCULAR_BUFFER_SIZE);
    if (main_buffer == NULL)
        return -ENOMEM;
    fp->private_data = main_buffer;

    return 0;
}

static int
device_close(struct inode* inode, struct file* fp)
{
    pr_info("[HelloChar] close() called\n");
    return 0;
}

static ssize_t
device_read(struct file* fp, char* __user data, size_t length, loff_t* pos)
{
    pr_info("[HelloChar] read() called with length=%lu\n", length);
    return read_circular_buffer(fp->private_data, data, length);
}

static ssize_t
device_write(struct file* fp,
             const char* __user data,
             size_t length,
             loff_t* pos)
{
    pr_info("[HelloChar] write() called with length=%lu\n", length);
    return write_circular_buffer(fp->private_data, data, length);
}

struct file_operations fops = {
    /* these are the file operations provided by our driver */
    .owner = THIS_MODULE,    /* prevents unloading when operations are in use*/
    .open = device_open,     /* to open the device*/
    .write = device_write,   /* to write to the device*/
    .read = device_read,     /* to read the device*/
    .release = device_close, /* to close the device*/
};

int
chardev_init(void)
{
    /* we will get the major number dynamically this is recommended please read
     * ldd3*/
    int ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICENAME);
    if (ret < 0) {
        pr_alert("[HelloChar] failed to allocate major number\n");
        return ret;
    } else
        pr_info("[HelloChar] major number allocated succesfully\n");
    major_number = MAJOR(dev_num);
    pr_info("[HelloChar] major number of device is %d\n", major_number);
    pr_info("[HelloChar] please use mknod /dev/%s c %d 0\n",
            DEVICENAME,
            major_number);

    mcdev =
      cdev_alloc();     /* create, allocate and initialize our cdev structure*/
    mcdev->ops = &fops; /* fops stand for our file operations*/
    mcdev->owner = THIS_MODULE;

    /* we have created and initialized our cdev structure now we need to
    add it to the kernel*/
    ret = cdev_add(mcdev, dev_num, 1);
    if (ret < 0) {
        pr_alert("[HelloChar] device adding to kernel failed\n");
        return ret;
    } else
        pr_info("[HelloChar] device added to kernel succesfully\n");

    return 0;
}

void
chardev_exit(void)
{
    if (main_buffer != NULL)
        destroy_circular_buffer(main_buffer);

    cdev_del(mcdev); /*removing the structure that we added previously*/

    unregister_chrdev_region(dev_num, 1);
    pr_info("[HelloChar] driver has exited\n");
}

MODULE_AUTHOR("Yakushov Yevgeny and Jesus");
MODULE_DESCRIPTION("HelloChar");
MODULE_LICENSE("GPL");

module_init(chardev_init);
module_exit(chardev_exit);

