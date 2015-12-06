/*
 * Copyright (c) 2015, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Portions Copyright (c) 2015 PADL Software Pty Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "krb5_locl.h"

/*
 * SP800-108 KDF
 */

/**
 * As described in SP800-108 5.1 (for HMAC)
 *
 * @param context	Kerberos 5 context
 * @param kdc_K1	Base key material.
 * @param kdf_label	A string that identifies the purpose for the derived key.
 * @param kdf_context   A binary string containing parties, nonce, etc.
 * @param md		Message digest function to use for PRF.
 * @param kdf_K0	Derived key data.
 *
 * @return Return an error code for an failure or 0 on success.
 * @ingroup krb5_crypto
 */
krb5_error_code
_krb5_SP800_108_HMAC_KDF(krb5_context context,
			 krb5_data *kdf_K1,
			 krb5_data *kdf_label,
			 krb5_data *kdf_context,
			 const EVP_MD *md,
			 krb5_data *kdf_K0)
{
    HMAC_CTX c;
    unsigned char *p = kdf_K0->data;
    size_t i, n, left = kdf_K0->length;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int h = EVP_MD_size(md);
    const size_t L = kdf_K0->length;

    heim_assert(md != NULL, "SP800-108 KDF internal error");

    HMAC_CTX_init(&c);

    n = L / h;

    for (i = 0; i <= n; i++) {
	unsigned char tmp[4];
	size_t len;

	HMAC_Init_ex(&c, kdf_K1->data, kdf_K1->length, md, NULL);

	_krb5_put_int(tmp, i + 1, 4);
	HMAC_Update(&c, tmp, 4);
	HMAC_Update(&c, kdf_label->data, kdf_label->length);
	HMAC_Update(&c, (unsigned char *)"", 1);
	if (kdf_context)
	    HMAC_Update(&c, kdf_context->data, kdf_context->length);
	_krb5_put_int(tmp, L * 8, 4);
	HMAC_Update(&c, tmp, 4);

	HMAC_Final(&c, hmac, &h);
	len = h > left ? left : h;
	memcpy(p, hmac, len);
	p += len;
	left -= len;
    }

    HMAC_CTX_cleanup(&c);

    return 0;
}

/**
 * As described in SP800-108 5.1
 *
 * @param context	Kerberos 5 context
 * @param kdc_K1	Base key material.
 * @param kdf_label	A string that identifies the purpose for the derived key.
 * @param kdf_context   A binary string containing parties, nonce, etc.
 * @param cipher	Cipher function for AEAD modes (CCM/GCM)
 * @param kdf_K0	Derived key data.
 *
 * @return Return an error code for an failure or 0 on success.
 * @ingroup krb5_crypto
 */
krb5_error_code
_krb5_SP800_108_KDF_cipher(krb5_context context,
			   krb5_data *kdf_K1,
			   krb5_data *kdf_label,
			   krb5_data *kdf_context,
			   const EVP_CIPHER *cipher,
			   krb5_data *kdf_K0)
{
    unsigned char *p = kdf_K0->data;
    size_t i, n, left = kdf_K0->length;
    unsigned char mac[16];
    unsigned int h = sizeof(mac);
    const size_t L = kdf_K0->length;
    EVP_CIPHER_CTX c;
    int outlen;

    heim_assert(cipher != NULL, "SP800-108 KDF internal error");

    EVP_CIPHER_CTX_init(&c);
    memset(mac, 0, sizeof(mac));

    n = L / h;
    if (n == 0)
	n = 1;

    /*
     * Chose feedback mode as it was used in draft-kanno-krbwg-camellia-ccm-03
     */
    for (i = 1; i <= n; i++) {
	unsigned char tmp[4];
	size_t len;

	if (EVP_CipherInit_ex(&c, cipher, NULL, kdf_K1->data, NULL, 1) != 1)
	    return KRB5_CRYPTO_INTERNAL;

	/* not as elegantly abstracted as one might like */
	switch (EVP_CIPHER_nid(cipher)) {
	case NID_aes_128_gcm:
	case NID_aes_192_gcm:
	case NID_aes_256_gcm:
	    EVP_CIPHER_CTX_ctrl(&c, EVP_CTRL_GCM_SET_IVLEN, sizeof(mac), NULL);
            EVP_CIPHER_CTX_ctrl(&c, EVP_CTRL_GCM_SET_IV_FIXED, -1, mac);
            EVP_CIPHER_CTX_ctrl(&c, EVP_CTRL_GCM_IV_GEN, sizeof(mac), mac);
	    break;
	default:
	    break;
	}

	_krb5_put_int(tmp, i, 4);
	if (EVP_CipherUpdate(&c, NULL, &outlen, tmp, 4) != 1)
	    return KRB5_CRYPTO_INTERNAL;
	if (EVP_CipherUpdate(&c, NULL, &outlen,
			     kdf_label->data, kdf_label->length) != 1)
	    return KRB5_CRYPTO_INTERNAL;

	if (EVP_CipherUpdate(&c, NULL, &outlen, (unsigned char *)"", 1) != 1)
	    return KRB5_CRYPTO_INTERNAL;
	if (kdf_context) {
	    if (EVP_CipherUpdate(&c, NULL, &outlen,
				 kdf_context->data, kdf_context->length) != 1)
		return KRB5_CRYPTO_INTERNAL;
	}
	_krb5_put_int(tmp, L * 8, 4);
	if (EVP_CipherUpdate(&c, NULL, &outlen, tmp, 4) != 1)
	    return KRB5_CRYPTO_INTERNAL;
	if (EVP_CipherFinal(&c, NULL, &outlen) != 1)
	    return KRB5_CRYPTO_INTERNAL;
	EVP_CIPHER_CTX_ctrl(&c, EVP_CTRL_GCM_GET_TAG, sizeof(mac), mac);
	len = h > left ? left : h;
	memcpy(p, mac, len);
	p += len;
	left -= len;
    }

    EVP_CIPHER_CTX_cleanup(&c);

    return 0;
}