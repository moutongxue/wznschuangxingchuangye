#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include<queue>
#include "openssl/sha.h"
using namespace std;

bool sha256(unsigned char* hash, const char* str, int strsize) {
    //unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strsize);
    SHA256_Final(hash, &sha256);
    return 1;
}bool sha256_0(unsigned char* hash, const char* str, int strsize) {
    const char tmp = 0;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &tmp, 1);
    SHA256_Update(&sha256, str, strsize);
    SHA256_Final(hash, &sha256);
    return 1;
}bool sha256_1(unsigned char* hash, const unsigned char* str0, const unsigned char* str1) {
    const char tmp = 1;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &tmp, 1);
    SHA256_Update(&sha256, str0, SHA256_DIGEST_LENGTH);
    SHA256_Update(&sha256, str1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash, &sha256);
    return 1;
}
class mknode{
public:
    unsigned char hash[SHA256_DIGEST_LENGTH];
    mknode* parent;
    mknode* lchild;
    mknode* rchild;
    mknode(){
        parent = lchild = rchild = NULL;
    }
    ~mknode(){}
    bool havechild(mknode* l,mknode*r)
    {
        lchild = l;
        rchild = r;
        l->parent = r->parent = this;
        sha256_1(hash, lchild->hash, rchild->hash);
        return 1;
    }
};
class proof {
public:
    bool ans;
    vector<mknode*> pro;
    vector<bool>path;
    proof(mknode* in)
    {
        ans = true;
        pro.push_back(in);
    }
    proof(mknode* in,mknode* in1)
    {
        ans = false;
        pro.push_back(in);
        pro.push_back(in1);
    }
};
bool cmp(mknode* l,mknode* r)
{
    for (int i = 0;i < SHA256_DIGEST_LENGTH;i++)
    {
        if (l->hash[i] < r->hash[i])
            return true;
        if (l->hash[i] > r->hash[i])
            return false;
    }
    return true;
}
bool equ(mknode* l, mknode* r)
{
    for (int i = 0;i < SHA256_DIGEST_LENGTH;i++)
    {
        if (l->hash[i] != r->hash[i])
            return false;
    }
    return true;
}
class mktree {
public:
    mknode* topnode;
    vector<mknode*> leafnodes;
    mktree()
    {
        topnode = NULL;
    }
    bool addleaf(vector<string> in)
    {
        mknode* temp;
        for (auto ins : in)
        {
            temp = new mknode;
            sha256_0(temp->hash, ins.c_str(), ins.size());
            leafnodes.push_back(temp);
        }
        sort(leafnodes.begin(), leafnodes.end(),cmp);
        return 1;
    }
    bool settree()
    {
        int leafsize = leafnodes.size();
        int height = 1;
        int temp = 1;
        queue<mknode*> waitdone;
        while (leafsize >= temp) {
            temp = 2 * temp;
            height++;
        }
        temp = temp / 2;
        int i = 0;
        mknode* tmpnode;
        for (leafsize;leafsize > temp;leafsize--)
        {
            tmpnode = new mknode;
            tmpnode->havechild(leafnodes[i], leafnodes[i + 1]);
            i = i + 2;
            waitdone.push(tmpnode);
        }
        for (i;i < leafnodes.size();i++)
        {
            waitdone.push(leafnodes[i]);
        }
        mknode* tmpnode0;
        mknode* tmpnode1;
        while (waitdone.size() != 1)
        {
            tmpnode = new mknode;
            tmpnode0 = waitdone.front();
            waitdone.pop();
            tmpnode1 = waitdone.front();
            waitdone.pop();
            tmpnode->havechild(tmpnode0, tmpnode1);
            waitdone.push(tmpnode);
        }
        topnode = waitdone.front();
        return 1;
    }
    proof findhash(mknode* aim)
    {
        int little = 0;
        int big = leafnodes.size()-1;
        while (big - little > 1)
        {
            if (equ(leafnodes[(little + big) / 2], aim))
                return proof(leafnodes[(little + big) / 2]);
            if (cmp(leafnodes[(little + big) / 2], aim))
                little= (little + big) / 2;
            else
                big= (little + big) / 2;
        }
        if (equ(leafnodes[little], aim))
            return proof(leafnodes[little]);
        if (equ(leafnodes[big], aim))
            return proof(leafnodes[big]);
        return proof(leafnodes[little], leafnodes[big]);
    }
    proof proofing(string  in){
        mknode* temp = new mknode;
        sha256_0(temp->hash, in.c_str(), in.size());
        proof tmppr =findhash(temp);
        if (tmppr.ans) {
            mknode* pathfind = tmppr.pro[0];
            while (pathfind != topnode) {
                if (pathfind->parent->lchild == pathfind) {
                    tmppr.path.push_back(true);
                    tmppr.pro.push_back(pathfind->parent->rchild);
                }
                else {
                    tmppr.path.push_back(false);
                    tmppr.pro.push_back(pathfind->parent->lchild);
                }
                pathfind = pathfind->parent;
            }
        }
        else {
            mknode* pathfind = tmppr.pro[0];
            while (pathfind != topnode) {
                if (pathfind->parent->lchild == pathfind) {
                    tmppr.path.push_back(true);
                }
                else {
                    tmppr.path.push_back(false);
                    tmppr.pro.push_back(pathfind->parent->lchild);
                }
                pathfind = pathfind->parent;
            }
            pathfind = tmppr.pro[1];
            while (pathfind != topnode) {
                if (pathfind->parent->lchild == pathfind)
                    tmppr.pro.push_back(pathfind->parent->rchild);
                pathfind = pathfind->parent;
            }
        }
        return tmppr;
    }
};

int main()
{
    mktree tree;
    vector<string> a;
    a.push_back("aa");
    a.push_back("no");
    a.push_back("no1");
    a.push_back("no3");
    a.push_back("no2");
    a.push_back("no4");
    a.push_back("no5");
    a.push_back("no6");
    a.push_back("no7");
    a.push_back("no9");
    a.push_back("no8");
    a.push_back("no0");
    tree.addleaf(a);
    tree.settree();
    proof p = tree.proofing("aa");
    mknode test = *p.pro[0];
    for (int i = 0;i < p.path.size();i++)
    {
        if (p.path[i])
            sha256_1(test.hash, test.hash, p.pro[i + 1]->hash);
        else
            sha256_1(test.hash, p.pro[i + 1]->hash, test.hash);
    }
    if(equ(&test, tree.topnode))
    cout << "存在性验证成功" << endl;
    p = tree.proofing("aa1");
    test = *p.pro[0];
    mknode test1 = *p.pro[1];
    int lefts = count(p.path.begin(), p.path.end(), false);
    int i = 0;
    while (!p.path[i])
    {
        sha256_1(test.hash, p.pro[i + 2]->hash, test.hash);
        i++;
    }
    int rc;
    for (rc = 2 + lefts;rc < (p.pro.size() - p.path.size() -1);rc++)
        sha256_1(test1.hash, test1.hash, p.pro[rc]->hash);
    int lc = i + 2;
    sha256_1(test.hash, test.hash, test1.hash);
    i++;
    for (i;i < p.path.size();i++)
    {
        if (p.path[i])
            sha256_1(test.hash, test.hash, p.pro[rc++]->hash);
        else
            sha256_1(test.hash, p.pro[lc++]->hash, test.hash);
    }
    if (equ(&test, tree.topnode))
        cout << "不存在性验证成功" << endl;
    return 0;
}
