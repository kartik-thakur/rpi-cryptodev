#ifndef __RPI_CRYPTODEV_H__
#define __RPI_CRYPTODEV_H__

#include <uapi/asm-generic/ioctl.h>

#define MAGIC 'c'
#define RPI_CRYPTO_AES_NUM 100

#define AES_MAX_KEYSIZE	32
#define AES_MAX_IVSIZE	32

enum aes_ops {
	AES_ECB,
	AES_CBC,
	AES_XTS,
	AES_OFB,
	AES_CTR
};

/*
 * RSA ops are currently disabled
enum rsa_ops {
	RSA_ENCRYPT,
	RSA_DECRYPT,
	RSA_SIGN,
	RSA_VERIFY,
};
*/


/**
 * aes_req - aes operation request definition
 * @op: see aes_ops definition
 * @encrypt: true if @text must be encrypted false otherwise
 * @key: key definition
 * @key_size: key size in bytes
 * @iv: initialization vector
 * @iv_size: initialization vector size
 * @text: text definition
 * @text_size: size of text in bytes
 */
struct aes_req {
	enum aes_ops	op;
	bool		encrypt;
	__user __u8	*key;
	__u8		key_size;
	__user __u8	*iv;
	__u8		iv_size;
	__user __u8	*text;
	__u64		text_size;
};
#define RPI_CRYPTO_AES _IOWR(MAGIC, RPI_CRYPTO_AES_NUM, struct aes_req)

#endif
