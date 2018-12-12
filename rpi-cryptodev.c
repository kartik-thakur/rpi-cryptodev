#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/crypto.h>

#include "rpi-cryptodev.h"

static int rpi_cryptodev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int rpi_cryptodev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long rpi_cryptodev_aes(__user struct aes_req *arg)
{
	long ret = 0L;
	struct aes_req req;
	u8 *key, *iv = NULL, *text;
	//u32 copy_size;

	if (copy_from_user(&req, arg, sizeof(req))) {
		ret = -EINVAL;
		pr_err("rpi-cryptodev: aes: error copying arg\n");
		goto aes_out_ret;
	}

	if (req.key_size > AES_MAX_KEYSIZE) {
		ret = -EINVAL;
		pr_err("rpi-cryptodev: aes: invalid keysize\n");
		goto aes_out_ret;
	}

	if (req.iv && (req.iv_size > AES_MAX_IVSIZE)) {
		ret = -EINVAL;
		pr_err("rpi-cryptodev: aes: invalid ivlen\n");
		goto aes_out_ret;
	}

	key = kmalloc(req.key_size, GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		pr_err("rpi-cryptodev: aes: error allocating memory\n");
		goto aes_out_ret;
	}

	if (copy_from_user(key, req.key, req.key_size)) {
		ret = -EINVAL;
		pr_err("rpi-cryptodev: aes: error copying key\n");
		goto aes_out_key;
	}

	if (req.iv) {
		iv = kmalloc(req.iv_size, GFP_KERNEL);
		if (!iv) {
			ret = -ENOMEM;
			pr_err("rpi-cryptodev: aes:"
			       "error allocaing memory\n");
			goto aes_out_key;
		}

		if(copy_from_user(iv, req.iv, req.iv_size)) {
			ret = -EINVAL;
			pr_err("rpi-cryptodev: aes:"
			       "error copying iv\n");
			goto aes_out_iv;
		}
	}

	/*processing request in chunks of PAGE_SIZE*/

aes_out_iv:
	if (iv)
		kfree(iv);
aes_out_key:
	kfree(key);
aes_out_ret:
	return ret;
}

static long rpi_cryptodev_ioctl(struct file *filp, unsigned int ioctl,
				unsigned long arg)
{
	long ret = 0L;

	switch(ioctl) {
	case RPI_CRYPTO_AES:
		ret = rpi_cryptodev_aes((__user struct aes_req*)arg);
		break;
	default:
		pr_err("rpi-cryptodev: invalid operation\n");
	}
	return ret;
}

static struct file_operations rpi_cryptodev_fops = {
	.owner = THIS_MODULE,
	.open = rpi_cryptodev_open,
	.release = rpi_cryptodev_release,
	.unlocked_ioctl = rpi_cryptodev_ioctl,
};

static struct miscdevice rpi_cryptodev = {
	.name = "rpi-cryptodev",
	.fops = &rpi_cryptodev_fops,
};

static int __init rpi_cryptodev_init(void)
{
	return misc_register(&rpi_cryptodev);
}

static void __exit rpi_cryptodev_exit(void)
{
	misc_deregister(&rpi_cryptodev);
}

module_init(rpi_cryptodev_init);
module_exit(rpi_cryptodev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kartik kartik.thakur@hotmail.com");
