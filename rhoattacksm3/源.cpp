#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include<vector>
#include<iostream>
using namespace std;


const int checkbytes = 4;
const int attackbytes = checkbytes + 1;
class attblock
{
public:
    unsigned char block[attackbytes];
    bool random()
    {
        for (int i = 0;i < checkbytes;i++)
            block[i] = rand();
        return 1;
    }
    bool randomset()
    {
        block[attackbytes-1] = rand();
        return 1;
    }
    bool write(unsigned char* in)
    {
        for (int i = 0;i < checkbytes;i++)
            block[i] = in[i];
        return 1;
    }
    bool operator==(attblock other)
    {
        bool flag = 1;
        for (int i = 0;i < attackbytes;i++)
            if (block[i] != other.block[i])
                flag = 0;
        return flag;
    }
    bool operator<(attblock other)const
    {
        for (int i = 0;i < attackbytes;i++)
        {
            if (block[i] < other.block[i])
                return true;
            if (block[i] > other.block[i])
                return false;
        }
        return false;
    }
    bool operator=(attblock other)
    {
        bool flag = 1;
        for (int i = 0;i < attackbytes;i++)
            block[i] = other.block[i];
        return flag;
    }
    bool attackcheck(attblock other)
    {
        bool flag = 1;
        for (int i = 0;i < checkbytes;i++)
            if (block[i] != other.block[i])
                flag = 0;
        return flag;
    }
};

bool openssl_sm3_hash(const unsigned char* input, int inputsize,
    unsigned char* buffer)
{
    unsigned int buf_len = 32;
    if (inputsize == 0)
        return false;

    memset(buffer, 0, buf_len);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // ÉèÖÃÊ¹ÓÃSM3
    if (!EVP_DigestInit_ex(ctx, EVP_sm3(), NULL)) {
        cout << "Failed to init" << endl;
        return false;
    }

    if (!EVP_DigestUpdate(ctx, input, inputsize)) {
        cout << "Failed to update" << endl;
        return false;
    }

    if (!EVP_DigestFinal_ex(ctx, buffer, &buf_len)) {
        cout << "Failed to final" << endl;
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}
int main()
{
    srand(time(0));
    BIGNUM* a = BN_new();
    BN_dec2bn(&a, "0");
    BIGNUM* one = BN_new();
    BN_dec2bn(&one, "1");
    BIGNUM* j = BN_new();
    attblock tryblock1;
    attblock tryblock2;
    attblock tryblockmem;
    unsigned char buf[32];
    unsigned char buf1[32];
    bool flag1 = 1;
    bool flag2 = 1;
    tryblock1.random();
    tryblock1.randomset();
    tryblock2 = tryblock1;
    tryblockmem = tryblock1;
    char* p;
    while (flag1) {
        while (flag2) {
            openssl_sm3_hash(tryblock1.block, attackbytes, buf);
            tryblock1.write(buf);
            openssl_sm3_hash(tryblock2.block, attackbytes, buf);
            tryblock2.write(buf);
            openssl_sm3_hash(tryblock2.block, attackbytes, buf);
            tryblock2.write(buf);
            if (tryblock1.attackcheck(tryblock2)) {
                p = BN_bn2dec(a);
                printf("a=%s\n", p);
                flag2 = 0;
            }
            else {
                BN_add(a, a, one);
            }
        }
        flag2 = 1;
        bool ko;
        tryblock2 = tryblockmem;
        p = BN_bn2dec(a);
        for (BN_dec2bn(&j, "0");BN_cmp(j,a)==-1;BN_add(j, j, one)) {
            openssl_sm3_hash(tryblock1.block, attackbytes, buf);
            openssl_sm3_hash(tryblock2.block, attackbytes, buf1);
            ko = 1;
            for (int i = 0;i < checkbytes;i++)
                if (buf[i] != buf1[i])
                    ko = 0;
            if (ko){
                for (int i = 0;i < attackbytes;i++)
                    cout << hex << (unsigned int)(unsigned char)(tryblock1.block[i]) << " " << hex << (unsigned int)(unsigned char)(tryblock2.block[i]) << endl;
                flag1 = 0;
                break;
            }
            tryblock1.write(buf);
            tryblock2.write(buf1);
        }
        tryblock1.random();
        tryblock1.randomset();
        tryblock2 = tryblock1;
        tryblockmem = tryblock1;
        BN_dec2bn(&a, "0");
    }

    return 0;
}