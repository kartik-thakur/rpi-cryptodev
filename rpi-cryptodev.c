#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/internal/skcipher.h>

#include "rpi-cryptodev.h"


struct request_status {
	struct completion	request;
	int			status;
};

static void get_request_status(struct crypto_async_request *req, int err)
{
	struct request_status *req_status = req->data;

	if (err != -EINPROGRESS) {
		req_status->status = err;
		complete(&(req_status->request));
	}
}

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
	long err = 0L;
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
	u32 alg_type = 0;
	struct crypto_skcipher *tfm;
	struct skcipher_request *sk_req;
	struct request_status status;
	bool is_iv_set = false;

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
	 * For performance improvements @type is changed to
	 * CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC
	 * if req.op is not AES_CBC.
	 */
	if (req.op == AES_CBC)
		alg_type = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC;

	tfm = crypto_alloc_skcipher(alg[req.op], alg_type, 0);
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

	crypto_skcipher_setkey(tfm, key, req.key_size);
	init_completion(&status.request);

	skcipher_request_set_callback(sk_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      get_request_status, &status);

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

		if (iv && !is_iv_set) {
			skcipher_request_set_crypt(sk_req, &sg_in, &sg_out,
						   copy_size, iv);
			is_iv_set = true;
		} else {
			skcipher_request_set_crypt(sk_req, &sg_in, &sg_out,
						   copy_size, iv);
		}

		reinit_completion(&status.request);

		err = req.encrypt ?
			crypto_skcipher_encrypt(sk_req) :
			crypto_skcipher_decrypt(sk_req);

		if ((err == -EINPROGRESS || err == -EBUSY)) {
			err = wait_for_completion_timeout(&status.request,
						msecs_to_jiffies(5000));

			if (err == 0)
				goto aes_out_outbuf;
			if (status.status < 0) {
				ret = status.status;
				pr_err("rpi-cryptodev: aes: "
				       "operation failed\n");
				goto aes_out_outbuf;
			}
		} else if (err < 0) {
			ret = err;
			pr_err("rpi-cryptodev: aes: operation failed\n");
			goto aes_out_outbuf;
		}

		if (copy_to_user(req.out, outbuf, copy_size)) {
			ret = -EINVAL;
			pr_err("rpi-cryptodev: aes: copy to user failed");
			goto aes_out_outbuf;
		}
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
MODULE_AUTHOR("Kartik <kartik.thakur@hotmail.com>");
