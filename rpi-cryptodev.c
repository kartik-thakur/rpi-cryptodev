#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/internal/skcipher.h>

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
	u8 *key, *iv = NULL;
	u64 copy_size;
	void *inbuf,  *outbuf;
	struct scatterlist sg_in, sg_out;
	char alg[5][9] = {
				"aes(ecb)",
				"aes(cbc)",
				"aes(xts)",
				"aes(ofb)",
				"aes(ctr)"
			 };
	struct crypto_skcipher *tfm;
	struct skcipher_request *sk_req;

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

	if (req.iv && req.iv_size && (req.iv_size > AES_MAX_IVSIZE)) {
		ret = -EINVAL;
		pr_err("rpi-cryptodev: aes: invalid ivlen\n");
		goto aes_out_ret;
	}

	if (req.op > AES_CTR) {
		ret = -EINVAL;
		pr_err("rpi-cryptodev: aes: invalid operation\n");
		goto aes_out_ret;
	}

	/**
	 * For performance improvements @mask can be changed to
	 * CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC
	 * if req.op is not AES_CBC.
	 */
	tfm = crypto_alloc_skcipher(alg[req.op], 0, 0);
	if(IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("rpi-cryptodev: aes: error allocating tfm\n");
		goto aes_out_ret;
	}

	sk_req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if(!sk_req) {
		ret = -ENOMEM;
		pr_err("rpi-cryptodev: aes: error allocating memory\n");
		goto aes_out_tfm;
	}

	key = kmalloc(req.key_size, GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		pr_err("rpi-cryptodev: aes: error allocating memory\n");
		goto aes_out_sk_req;
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

	inbuf = (void *)__get_free_page(GFP_KERNEL);
	if (!inbuf) {
		ret = -ENOMEM;
		pr_err("rpi-cryptodev: aes: error allocating memory\n");
		goto aes_out_iv;
	}

	outbuf = (void *)__get_free_page(GFP_KERNEL);
	if (!outbuf) {
		ret = -ENOMEM;
		pr_err("rpi-cryptodev: aes: error allocating memory\n");
		goto aes_out_inbuf;
	}

	/*processing request in chunks of PAGE_SIZE*/
	while(req.text_size) {
		copy_size = req.text_size < PAGE_SIZE ?
			    req.text_size : PAGE_SIZE;

		if (copy_from_user(inbuf, req.text, copy_size)) {
			ret = -EINVAL;
			pr_err("rpi-cryptodev: aes: error copying text");
			goto aes_out_outbuf;
		}

		sg_init_one(&sg_in, inbuf, copy_size);
		sg_init_one(&sg_out, outbuf, copy_size);

		req.text += copy_size;
		req.text_size -= copy_size;
	}

aes_out_outbuf:
	free_page((unsigned long)outbuf);
aes_out_inbuf:
	free_page((unsigned long)inbuf);
aes_out_iv:
	if (iv)
		kfree(iv);
aes_out_key:
	kfree(key);
aes_out_sk_req:
	skcipher_request_free(sk_req);
aes_out_tfm:
	crypto_free_skcipher(tfm);
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
MODULE_AUTHOR("Kartik <kartik.thakur@hotmail.com">);
