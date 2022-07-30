#include <openssl/evp.h>
#include <openssl/aes.h>
#include<vector>
#include<iostream>
#include <map>
using namespace std;


const int checkbytes = 5;
const int attackbytes = checkbytes+1;
class attblock
{public:
    unsigned char block[attackbytes];
    bool random()
    {
        for (int i = 0;i < attackbytes;i++)
            block[i] = rand();
        return 1;
    }
    bool write(unsigned char* in)
    {
        for (int i = 0;i < attackbytes;i++)
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
};

class outblock
{
public:
    unsigned char block[checkbytes];
    bool random()
    {
        for (int i = 0;i < checkbytes;i++)
            block[i] = rand();
        return 1;
    }
    bool write(unsigned char* in)
    {
        for (int i = 0;i < checkbytes;i++)
            block[i] = in[i];
        return 1;
    }
    bool operator==(outblock other)
    {
        bool flag = 1;
        for (int i = 0;i < checkbytes;i++)
            if (block[i] != other.block[i])
                flag = 0;
        return flag;
    }
    bool operator<(outblock other)const
    {
        for (int i = 0;i < checkbytes;i++)
        {
            if (block[i] < other.block[i])
                return true;
            if (block[i] > other.block[i])
                return false;
        }
        return false;
    }
};
bool openssl_sm3_hash(const unsigned char* input,int inputsize,
    unsigned char* buffer)
{
    unsigned int buf_len = 32;
    if (inputsize==0)
        return false;

    memset(buffer, 0, buf_len);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // …Ë÷√ π”√SM3
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
    map<outblock, attblock> dic;
    attblock tryblock;
    outblock temp;
    unsigned char buf[32];
    bool flag = 1;
    while (flag) {
        tryblock.random();
        openssl_sm3_hash(tryblock.block, attackbytes, buf);
        temp.write(buf);
        if (dic.count(temp) == 0)
            dic[temp] = tryblock;
        else{
            if (!(dic[temp] == tryblock)) {
                for (int i = 0;i < attackbytes;i++)
                    cout << hex << (unsigned int)(unsigned char)(dic[temp].block[i]) << " " << hex << (unsigned int)(unsigned char)(tryblock.block[i]) << endl;
                flag = 0;
                for (int i = 0;i < 32;i++)
                    cout << hex << (unsigned int)(unsigned char)buf[i] << endl;
                openssl_sm3_hash(dic[temp].block, attackbytes, buf);
                cout << endl;
                for (int i = 0;i < 32;i++)
                    cout << hex << (unsigned int)(unsigned char)buf[i] << endl;}            
            }
    }

    return 0;
}