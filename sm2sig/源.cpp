#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string.h>
#include "openssl/applink.c"

int ossl_sm2_compute_z_digest(uint8_t* out,
    const uint8_t* id,
    const size_t id_len,
    const EC_KEY* key)
{
    const EC_GROUP* group = EC_KEY_get0_group(key);
    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    EVP_MD_CTX* hash = NULL;
    BIGNUM* p = BN_CTX_get(ctx);
    BIGNUM* a = BN_CTX_get(ctx);
    BIGNUM* b = BN_CTX_get(ctx);
    BIGNUM* xG = BN_CTX_get(ctx);
    BIGNUM* yG = BN_CTX_get(ctx);
    BIGNUM* xA = BN_CTX_get(ctx);
    BIGNUM* yA = BN_CTX_get(ctx);
    int p_bytes = 0;
    uint8_t* buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;
    unsigned int buf_len = 32;
    hash = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash, EVP_sm3(), NULL);

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        return 0;
    }
    entl = (uint16_t)(8 * id_len);
    e_byte = entl >> 8;
    EVP_DigestUpdate(hash, &e_byte, 1);
    e_byte = entl & 0xFF;
    EVP_DigestUpdate(hash, &e_byte, 1);
    EVP_DigestUpdate(hash, id, id_len);
    EC_GROUP_get_curve(group, p, a, b, ctx);
    p_bytes = BN_num_bytes(p);
    buf = (uint8_t*)OPENSSL_zalloc(p_bytes);
    BN_bn2binpad(a, buf, p_bytes);
    EVP_DigestUpdate(hash, buf, p_bytes);
    BN_bn2binpad(b, buf, p_bytes);
    EVP_DigestUpdate(hash, buf, p_bytes);
    EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group), xG, yG, ctx);
    BN_bn2binpad(xG, buf, p_bytes);
    EVP_DigestUpdate(hash, buf, p_bytes);
    BN_bn2binpad(yG, buf, p_bytes);
    EVP_DigestUpdate(hash, buf, p_bytes);
    EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(key), xA, yA, ctx);
    BN_bn2binpad(xA, buf, p_bytes);
    EVP_DigestUpdate(hash, buf, p_bytes);
    BN_bn2binpad(yA, buf, p_bytes);
    EVP_DigestUpdate(hash, buf, p_bytes);
    EVP_DigestFinal_ex(hash, out, &buf_len);
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return 1;
}

static BIGNUM* sm2_compute_msg_hash(
    const EC_KEY* key,
    const uint8_t* id,
    const size_t id_len,
    const uint8_t* msg, size_t msg_len)
{
    EVP_MD_CTX* hash = EVP_MD_CTX_new();
    const int md_size = 32;
    uint8_t* z = NULL;
    BIGNUM* e = NULL;
    EVP_MD* fetched_digest = NULL;
    ossl_sm2_compute_z_digest(z, id, id_len, key);
    EVP_DigestInit(hash, EVP_sm3());
    EVP_DigestUpdate(hash, z, md_size);
    EVP_DigestUpdate(hash, msg, msg_len);
    EVP_DigestFinal(hash, z, NULL);
    e = BN_bin2bn(z, md_size, NULL);
    OPENSSL_free(z);
    EVP_MD_CTX_free(hash);
    return e;
}

static ECDSA_SIG* sm2_sig_gen(const EC_KEY* key, const BIGNUM* e)
{
    const BIGNUM* dA = EC_KEY_get0_private_key(key);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    ECDSA_SIG* sig = NULL;
    EC_POINT* kG = NULL;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* k = NULL;
    BIGNUM* rk = NULL;
    BIGNUM* r = NULL;
    BIGNUM* s = NULL;
    BIGNUM* x1 = NULL;
    BIGNUM* tmp = NULL;
    kG = EC_POINT_new(group);
    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    rk = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    r = BN_new();
    s = BN_new();
    for (;;) {
        BN_priv_rand_range(k, order);
        EC_POINT_mul(group, kG, k, NULL, NULL, ctx);
        EC_POINT_get_affine_coordinates(group, kG, x1, NULL, ctx);
        BN_mod_add(r, e, x1, order, ctx);
        if (BN_is_zero(r))
            continue;

        BN_add(rk, r, k);
        if (BN_cmp(rk, order) == 0)
            continue;
        BN_add(s, dA, BN_value_one());
        BN_mod_inverse(s, s, EC_GROUP_get0_order(group), ctx);
        BN_mod_mul(tmp, dA, r, order, ctx);
        BN_sub(tmp, k, tmp);
        BN_mod_mul(s, s, tmp, order, ctx);

        if (BN_is_zero(s))
            continue;

        sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(sig, r, s);
        break;
    }
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    return sig;
}

static int sm2_sig_verify(const EC_KEY* key, const ECDSA_SIG* sig,
    const BIGNUM* e)
{
    int ret = 0;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* pt = NULL;
    BIGNUM* t = NULL;
    BIGNUM* x1 = NULL;
    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    pt = EC_POINT_new(group);
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    ECDSA_SIG_get0(sig, &r, &s);
    BN_mod_add(t, r, s, order, ctx);
    EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx);
    EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx);
    BN_mod_add(t, e, x1, order, ctx);
    if (BN_cmp(r, t) == 0)
        ret = 1;
    EC_POINT_free(pt);
    BN_CTX_free(ctx);
    return ret;
}

ECDSA_SIG* ossl_sm2_do_sign(const EC_KEY* key,
    const uint8_t* id,
    const size_t id_len,
    const uint8_t* msg, size_t msg_len)
{
    BIGNUM* e = NULL;
    ECDSA_SIG* sig = NULL;

    e = sm2_compute_msg_hash(key, id, id_len, msg, msg_len);
    sig = sm2_sig_gen(key, e);

    BN_free(e);
    return sig;
}

int ossl_sm2_do_verify(const EC_KEY* key,
    const ECDSA_SIG* sig,
    const uint8_t* id,
    const size_t id_len,
    const uint8_t* msg, size_t msg_len)
{
    BIGNUM* e = NULL;
    int ret = 0;

    e = sm2_compute_msg_hash(key, id, id_len, msg, msg_len);
    ret = sm2_sig_verify(key, sig, e);
    BN_free(e);
    return ret;
}

int ossl_sm2_internal_sign(const unsigned char* dgst, int dgstlen,
    unsigned char* sig, unsigned int* siglen,
    EC_KEY* eckey)
{
    BIGNUM* e = NULL;
    ECDSA_SIG* s = NULL;
    int sigleni;
    int ret = -1;

    e = BN_bin2bn(dgst, dgstlen, NULL);

    s = sm2_sig_gen(eckey, e);

    sigleni = i2d_ECDSA_SIG(s, &sig);
    *siglen = (unsigned int)sigleni;

    ret = 1;
    ECDSA_SIG_free(s);
    BN_free(e);
    return ret;
}

int ossl_sm2_internal_verify(const unsigned char* dgst, int dgstlen,
    const unsigned char* sig, int sig_len,
    EC_KEY* eckey)
{
    ECDSA_SIG* s = NULL;
    BIGNUM* e = NULL;
    const unsigned char* p = sig;
    unsigned char* der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    d2i_ECDSA_SIG(&s, &p, sig_len);
    derlen = i2d_ECDSA_SIG(s, &der);
    e = BN_bin2bn(dgst, dgstlen, NULL);
    ret = sm2_sig_verify(eckey, s, e);
    OPENSSL_free(der);
    BN_free(e);
    ECDSA_SIG_free(s);
    return ret;
}
int   main()
{
    EC_KEY* key1 = EC_KEY_new();
    EC_GROUP* group1;
    int ret, size, i;
    unsigned int sig_len;
    unsigned char* signature;
    unsigned char digest[20] = { 0 };
    BIO* berr;
    if (key1 == NULL)
    {
        printf("EC_KEY_new err!\n");
        return -1;
    }
    group1 = EC_GROUP_new_by_curve_name(1172);
    if (group1 == NULL)
    {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }
    ret = EC_KEY_set_group(key1, group1);
    if (ret != 1)
    {
        printf("EC_KEY_set_group err.\n");
        return -1;
    }
    ret = EC_KEY_generate_key(key1);
    if (ret != 1)
    {
        printf("EC_KEY_generate_key err.\n");
        return -1;
    }
    ret = EC_KEY_check_key(key1);
    if (ret != 1)
    {
        printf("check key err.\n");
        return -1;
    }
    size = ECDSA_size(key1);
    printf("size %d \n", size);
    signature = (unsigned char*)malloc(size);
    ERR_load_crypto_strings();
    berr = BIO_new(BIO_s_file());
    BIO_set_fp(berr, stdout, BIO_NOCLOSE);
    // 签名数据
    ret = ossl_sm2_internal_sign(digest, 20, signature, &sig_len, key1);
    if (ret != 1)
    {
        ERR_print_errors(berr);
        printf("sign err!\n");
        return -1;
    }
    // 验证签名 
    ret = ossl_sm2_internal_verify(digest, 20, signature, sig_len, key1);
    if (ret != 1)
    {
        ERR_print_errors(berr);
        printf("sm2_verify err!\n");
        return -1;
    }
    printf("test ok!\n");
    BIO_free(berr);
    EC_KEY_free(key1);
    free(signature);
    return 0;
}