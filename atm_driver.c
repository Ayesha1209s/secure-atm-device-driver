/**
 * ============================================================================
 * Project: Secure ATM PIN Authenticator Device Driver
 * File:    atm_driver.c
 * Author:  Advanced Systems & Kernel Security Engineering
 * License: GPL
 * 
 * Description:
 *   Production-grade Linux Loadable Kernel Module (LKM) character device driver.
 *   Simulates a hardware-isolated secure cryptoprocessor (HSM) for ATM PIN
 *   verification directly within privileged kernel space.
 *
 * Real-World Financial Security Policies:
 *   1. Hardware-level PIN validation in privileged Kernel Space.
 *   2. Dynamic User PIN Provisioning via "SET_PIN:<PIN>".
 *   3. Timing-attack resistant constant-time comparison via crypto_memneq().
 *   4. Enforced lock-out policy: Max 3 failed attempts triggers temporary security hold.
 *   5. 24-Hour Cooldown Timer: Automatic counter reset upon cooldown expiration
 *      (Accelerated to 30 seconds by default for live evaluation & testing).
 *   6. Bank Officer Master PUK Override: Secure reset token ("PUK:778899") to
 *      instantly clear security holds following in-branch customer verification.
 *   7. Explicit zeroization of sensitive buffers (memzero_explicit).
 *   8. Concurrency protection via kernel mutex.
 * ============================================================================
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/crypto.h>
#include <linux/timekeeping.h>

#define DRIVER_NAME         "atm_auth"
#define CLASS_NAME          "atm_security"
#define STATUS_BUFFER_LEN   128
#define PIN_MAX_LEN         16
#define MAX_FAILED_ATTEMPTS 3

/* Module Metadata */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Systems & Security Engineering Group");
MODULE_DESCRIPTION("Secure ATM PIN Authenticator Character Device Driver with Custom PIN Provisioning");
MODULE_VERSION("1.2.0");

/* Configurable Module Parameters */
static char *master_pin = "2580";
module_param(master_pin, charp, 0400);
MODULE_PARM_DESC(master_pin, "Default master authentication PIN stored in kernel memory (default: '2580')");

static char *master_puk = "778899";
module_param(master_puk, charp, 0400);
MODULE_PARM_DESC(master_puk, "Bank Officer Master PUK code for in-branch unlock (default: '778899')");

static unsigned int cooldown_sec = 30;
module_param(cooldown_sec, uint, 0644);
MODULE_PARM_DESC(cooldown_sec, "Security hold cooldown duration in seconds (default: 30s for demo, 86400 for 24h)");

/* Internal Driver State Representation */
struct atm_device_state {
    dev_t dev_num;                      /* Dynamic Major and Minor device number */
    struct cdev cdev;                   /* Character device registration object */
    struct class *dev_class;            /* Sysfs class pointer */
    struct device *dev_device;          /* Sysfs device pointer */
    struct mutex state_lock;            /* Mutex preventing race conditions */

    int failed_attempts;                /* Count of consecutive failed PIN entries */
    bool is_locked;                     /* Lockout trigger flag */
    bool is_authenticated;              /* Session authorization flag */
    time64_t lockout_timestamp;         /* Timestamp when lockout was triggered */
    char stored_pin[PIN_MAX_LEN + 1];   /* Guarded PIN in kernel address space */
    char stored_puk[PIN_MAX_LEN + 1];   /* Guarded PUK in kernel address space */
};

static struct atm_device_state g_atm_dev;

/* Forward Declarations of VFS Operations */
static int     atm_open(struct inode *inode, struct file *file);
static int     atm_release(struct inode *inode, struct file *file);
static ssize_t atm_read(struct file *file, char __user *user_buffer, size_t count, loff_t *ppos);
static ssize_t atm_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos);

/* Linux Virtual File System (VFS) Operations Dispatch Table */
static const struct file_operations atm_fops = {
    .owner   = THIS_MODULE,
    .open    = atm_open,
    .release = atm_release,
    .read    = atm_read,
    .write   = atm_write,
};

static void check_and_update_cooldown(void)
{
    if (g_atm_dev.is_locked) {
        time64_t now = ktime_get_real_seconds();
        if ((now - g_atm_dev.lockout_timestamp) >= (time64_t)cooldown_sec) {
            g_atm_dev.is_locked = false;
            g_atm_dev.failed_attempts = 0;
            g_atm_dev.lockout_timestamp = 0;
            pr_info("%s: [SECURITY RESTORE] Cooldown period expired. Account unlocked automatically.\n",
                    DRIVER_NAME);
        }
    }
}

static int atm_open(struct inode *inode, struct file *file)
{
    if (!mutex_trylock(&g_atm_dev.state_lock)) {
        pr_warn("%s: Device is currently busy with another active process\n", DRIVER_NAME);
        return -EBUSY;
    }

    check_and_update_cooldown();
    pr_info("%s: Device opened by process [PID: %d]\n", DRIVER_NAME, current->pid);
    mutex_unlock(&g_atm_dev.state_lock);
    return 0;
}

static int atm_release(struct inode *inode, struct file *file)
{
    mutex_lock(&g_atm_dev.state_lock);
    g_atm_dev.is_authenticated = false;
    pr_info("%s: Device closed. Session revoked for process [PID: %d]\n", DRIVER_NAME, current->pid);
    mutex_unlock(&g_atm_dev.state_lock);
    return 0;
}

static ssize_t atm_read(struct file *file, char __user *user_buffer, size_t count, loff_t *ppos)
{
    char status_str[STATUS_BUFFER_LEN];
    int len;
    const char *status_str_label;
    int cooldown_remaining = 0;

    if (*ppos > 0)
        return 0;

    if (!user_buffer)
        return -EINVAL;

    mutex_lock(&g_atm_dev.state_lock);

    check_and_update_cooldown();

    if (g_atm_dev.is_locked) {
        time64_t now = ktime_get_real_seconds();
        time64_t elapsed = now - g_atm_dev.lockout_timestamp;
        if (elapsed < (time64_t)cooldown_sec) {
            cooldown_remaining = (int)(cooldown_sec - elapsed);
        }
        status_str_label = "LOCKED";
    } else if (g_atm_dev.is_authenticated) {
        status_str_label = "AUTHENTICATED";
    } else {
        status_str_label = "READY";
    }

    len = snprintf(status_str, sizeof(status_str),
                   "STATUS=%s;FAILED=%d;MAX=%d;LOCKED=%d;COOLDOWN=%d\n",
                   status_str_label,
                   g_atm_dev.failed_attempts,
                   MAX_FAILED_ATTEMPTS,
                   g_atm_dev.is_locked ? 1 : 0,
                   cooldown_remaining);

    mutex_unlock(&g_atm_dev.state_lock);

    if (len < 0)
        return -EFAULT;

    if (count < (size_t)len)
        return -EINVAL;

    if (copy_to_user(user_buffer, status_str, len)) {
        pr_err("%s: Failed copy_to_user during status query\n", DRIVER_NAME);
        return -EFAULT;
    }

    *ppos += len;
    return len;
}

static ssize_t atm_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos)
{
    char kernel_input[32];
    size_t copy_len;
    size_t input_len;
    bool is_match;

    if (!user_buffer || count == 0)
        return -EINVAL;

    mutex_lock(&g_atm_dev.state_lock);

    check_and_update_cooldown();

    copy_len = min(count, (size_t)(sizeof(kernel_input) - 1));
    if (copy_from_user(kernel_input, user_buffer, copy_len)) {
        pr_err("%s: Memory transfer fault: copy_from_user failed\n", DRIVER_NAME);
        mutex_unlock(&g_atm_dev.state_lock);
        return -EFAULT;
    }
    kernel_input[copy_len] = '\0';

    input_len = strcspn(kernel_input, "\r\n");
    kernel_input[input_len] = '\0';

    /* 1. Dynamic User PIN Provisioning ("SET_PIN:<NEW_PIN>") */
    if (strncmp(kernel_input, "SET_PIN:", 8) == 0) {
        const char *new_pin = kernel_input + 8;
        size_t new_len = strlen(new_pin);
        if (new_len > 0 && new_len <= PIN_MAX_LEN) {
            strncpy(g_atm_dev.stored_pin, new_pin, PIN_MAX_LEN);
            g_atm_dev.stored_pin[PIN_MAX_LEN] = '\0';
            g_atm_dev.failed_attempts = 0;
            g_atm_dev.is_locked = false;
            g_atm_dev.lockout_timestamp = 0;
            pr_info("%s: [CONFIG] User provisioned custom PIN securely in Kernel HSM.\n", DRIVER_NAME);
            memzero_explicit(kernel_input, sizeof(kernel_input));
            mutex_unlock(&g_atm_dev.state_lock);
            return count;
        }
    }

    /* 2. Bank Officer Master PUK Override Token ("PUK:<CODE>") */
    if (strncmp(kernel_input, "PUK:", 4) == 0) {
        const char *puk_candidate = kernel_input + 4;
        size_t puk_len = strlen(puk_candidate);
        size_t stored_puk_len = strlen(g_atm_dev.stored_puk);

        if (puk_len == stored_puk_len &&
            crypto_memneq(puk_candidate, g_atm_dev.stored_puk, stored_puk_len) == 0) {
            g_atm_dev.is_locked = false;
            g_atm_dev.failed_attempts = 0;
            g_atm_dev.lockout_timestamp = 0;
            g_atm_dev.is_authenticated = false;
            pr_info("%s: [BANK OVERRIDE SUCCESS] Master PUK accepted. Security hold removed.\n",
                    DRIVER_NAME);
            memzero_explicit(kernel_input, sizeof(kernel_input));
            mutex_unlock(&g_atm_dev.state_lock);
            return count;
        } else {
            pr_warn("%s: [BANK OVERRIDE REJECTED] Invalid Master PUK entered.\n", DRIVER_NAME);
            memzero_explicit(kernel_input, sizeof(kernel_input));
            mutex_unlock(&g_atm_dev.state_lock);
            return -EACCES;
        }
    }

    /* 3. Lockout Enforcement for standard PIN entries */
    if (g_atm_dev.is_locked) {
        time64_t now = ktime_get_real_seconds();
        int rem = (int)(cooldown_sec - (now - g_atm_dev.lockout_timestamp));
        pr_alert("%s: [SECURITY REJECTION] Card locked. Cooldown hold active (%d sec remaining).\n",
                 DRIVER_NAME, rem > 0 ? rem : 0);
        memzero_explicit(kernel_input, sizeof(kernel_input));
        mutex_unlock(&g_atm_dev.state_lock);
        return -EPERM;
    }

    /* 4. Constant-Time PIN Comparison */
    {
        size_t stored_len = strlen(g_atm_dev.stored_pin);
        if (input_len == stored_len) {
            is_match = (crypto_memneq(kernel_input, g_atm_dev.stored_pin, stored_len) == 0);
        } else {
            is_match = false;
        }
    }

    /* 5. State Machine Update */
    if (is_match) {
        g_atm_dev.is_authenticated = true;
        g_atm_dev.failed_attempts = 0;
        pr_info("%s: [AUTH SUCCESS] PIN verified. Session granted for PID %d.\n",
                DRIVER_NAME, current->pid);
    } else {
        g_atm_dev.is_authenticated = false;
        g_atm_dev.failed_attempts++;
        pr_warn("%s: [AUTH FAILURE] Invalid PIN entered. Attempt %d of %d.\n",
                DRIVER_NAME, g_atm_dev.failed_attempts, MAX_FAILED_ATTEMPTS);

        if (g_atm_dev.failed_attempts >= MAX_FAILED_ATTEMPTS) {
            g_atm_dev.is_locked = true;
            g_atm_dev.lockout_timestamp = ktime_get_real_seconds();
            pr_alert("%s: [SECURITY CRITICAL] 3 Failed attempts! 24-Hour Security Hold initiated (%u sec cooldown).\n",
                     DRIVER_NAME, cooldown_sec);
        }
    }

    /* 6. Sensitive Memory Scrubbing */
    memzero_explicit(kernel_input, sizeof(kernel_input));

    mutex_unlock(&g_atm_dev.state_lock);
    return count;
}

static int __init atm_driver_init(void)
{
    int ret;

    pr_info("%s: Initializing Secure ATM PIN Authenticator LKM (v1.2)...\n", DRIVER_NAME);

    mutex_init(&g_atm_dev.state_lock);
    g_atm_dev.failed_attempts = 0;
    g_atm_dev.is_locked = false;
    g_atm_dev.is_authenticated = false;
    g_atm_dev.lockout_timestamp = 0;

    strncpy(g_atm_dev.stored_pin, master_pin, PIN_MAX_LEN);
    g_atm_dev.stored_pin[PIN_MAX_LEN] = '\0';

    strncpy(g_atm_dev.stored_puk, master_puk, PIN_MAX_LEN);
    g_atm_dev.stored_puk[PIN_MAX_LEN] = '\0';

    ret = alloc_chrdev_region(&g_atm_dev.dev_num, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        pr_err("%s: Failed alloc_chrdev_region (err=%d)\n", DRIVER_NAME, ret);
        return ret;
    }

    cdev_init(&g_atm_dev.cdev, &atm_fops);
    g_atm_dev.cdev.owner = THIS_MODULE;

    ret = cdev_add(&g_atm_dev.cdev, g_atm_dev.dev_num, 1);
    if (ret < 0) {
        pr_err("%s: Failed cdev_add (err=%d)\n", DRIVER_NAME, ret);
        goto err_unregister_chrdev;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    g_atm_dev.dev_class = class_create(CLASS_NAME);
#else
    g_atm_dev.dev_class = class_create(THIS_MODULE, CLASS_NAME);
#endif

    if (IS_ERR(g_atm_dev.dev_class)) {
        pr_err("%s: Failed to create sysfs class '%s'\n", DRIVER_NAME, CLASS_NAME);
        ret = PTR_ERR(g_atm_dev.dev_class);
        goto err_cdev_del;
    }

    g_atm_dev.dev_device = device_create(g_atm_dev.dev_class, NULL, g_atm_dev.dev_num, NULL, DRIVER_NAME);
    if (IS_ERR(g_atm_dev.dev_device)) {
        pr_err("%s: Failed to create device node /dev/%s\n", DRIVER_NAME, DRIVER_NAME);
        ret = PTR_ERR(g_atm_dev.dev_device);
        goto err_class_destroy;
    }

    pr_info("%s: Driver ready. Dynamic PINs enabled. Cooldown: %u sec.\n",
            DRIVER_NAME, cooldown_sec);
    return 0;

err_class_destroy:
    class_destroy(g_atm_dev.dev_class);
err_cdev_del:
    cdev_del(&g_atm_dev.cdev);
err_unregister_chrdev:
    unregister_chrdev_region(g_atm_dev.dev_num, 1);
    mutex_destroy(&g_atm_dev.state_lock);
    return ret;
}

static void __exit atm_driver_exit(void)
{
    pr_info("%s: Unloading driver and zeroizing cryptographic credentials...\n", DRIVER_NAME);

    memzero_explicit(g_atm_dev.stored_pin, sizeof(g_atm_dev.stored_pin));
    memzero_explicit(g_atm_dev.stored_puk, sizeof(g_atm_dev.stored_puk));

    if (g_atm_dev.dev_device)
        device_destroy(g_atm_dev.dev_class, g_atm_dev.dev_num);

    if (g_atm_dev.dev_class)
        class_destroy(g_atm_dev.dev_class);

    cdev_del(&g_atm_dev.cdev);
    unregister_chrdev_region(g_atm_dev.dev_num, 1);
    mutex_destroy(&g_atm_dev.state_lock);

    pr_info("%s: Driver deregistered cleanly.\n", DRIVER_NAME);
}

module_init(atm_driver_init);
module_exit(atm_driver_exit);
