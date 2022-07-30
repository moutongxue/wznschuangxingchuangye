#include <stdlib.h>
#include <iostream>
using namespace std;

static const enum
{
	A = 0,
	B = 1,
	C = 2,
	D = 3,
	E = 4,
	F = 5,
	G = 6,
	H = 7
};

static const unsigned int IV[8] =
{
	0x7380166F,	0x4914B2B9,
	0x172442D7,	0xDA8A0600,
	0xA96F30BC,	0x163138AA,
	0xE38DEE4D,	0xB0FB0E4E,
};
static unsigned int T[64] = { 0 };
static void _init_T()
{
	int i = 0;
	for (; i < 16; i++)
		T[i] = 0x79CC4519;
	for (; i < 64; i++)
		T[i] = 0x7A879D8A;
}

static unsigned int _rotate_left_move(const unsigned int nValue, const unsigned int nBit)
{
	return ((nValue << nBit) & 0xFFFFFFFF | ((nValue & 0xFFFFFFFF) >> (32 - nBit)));
}

static unsigned int _FF(const unsigned int X, const unsigned int Y, const unsigned int Z, const unsigned int j)
{
	if (0 <= j && j < 16)
		return (X ^ Y ^ Z);
	else if (16 <= j && j < 64)
		return ((X & Y) | (X & Z) | (Y & Z));

	return 0;
}

static unsigned int _GG(const unsigned int X, const unsigned int Y, const unsigned int Z, const unsigned int j)
{
	if (0 <= j && j < 16)
		return (X ^ Y ^ Z);
	else if (16 <= j && j < 64)
		return ((X & Y) | ((~X) & Z));

	return 0;
}

static unsigned int _P0(const unsigned int X)
{
	return (X ^ (_rotate_left_move(X, 9)) ^ (_rotate_left_move(X, 17)));
}

static unsigned int _P1(const unsigned int X)
{
	return (X ^ (_rotate_left_move(X, 15)) ^ (_rotate_left_move(X, 23)));
}

static unsigned int _CF(unsigned char* ucpSrcMsg, unsigned int nHash[8])
{
	unsigned int W68[68] = { 0 };
	unsigned int W64[64] = { 0 };
	int j = 0;
	for (j = 0; j < 16; j++)
	{
		W68[j] = ((unsigned int)ucpSrcMsg[j * 4 + 0] << 24) & 0xFF000000
			| ((unsigned int)ucpSrcMsg[j * 4 + 1] << 16) & 0x00FF0000
			| ((unsigned int)ucpSrcMsg[j * 4 + 2] << 8) & 0x0000FF00
			| ((unsigned int)ucpSrcMsg[j * 4 + 3] << 0) & 0x000000FF;
	}
	for (j = 16; j < 68; j++)
	{
		W68[j] = _P1(W68[j - 16] ^ W68[j - 9] ^ (_rotate_left_move(W68[j - 3], 15))) ^ (_rotate_left_move(W68[j - 13], 7)) ^ W68[j - 6];
	}
	for (j = 0; j < 64; j++)
	{
		W64[j] = W68[j] ^ W68[j + 4];
	}
	unsigned int A_G[8] = { 0 };
	for (j = 0; j < 8; j++)
	{
		A_G[j] = nHash[j];
	}
	unsigned int SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0;
	for (j = 0; j < 64; j++)
	{
		SS1 = _rotate_left_move((_rotate_left_move(A_G[A], 12) + A_G[E] + _rotate_left_move(T[j], j % 32)), 7);
		SS2 = SS1 ^ (_rotate_left_move(A_G[A], 12));
		TT1 = _FF(A_G[A], A_G[B], A_G[C], j) + A_G[D] + SS2 + W64[j];
		TT2 = _GG(A_G[E], A_G[F], A_G[G], j) + A_G[H] + SS1 + W68[j];
		A_G[D] = A_G[C];
		A_G[C] = _rotate_left_move(A_G[B], 9);
		A_G[B] = A_G[A];
		A_G[A] = TT1;
		A_G[H] = A_G[G];
		A_G[G] = _rotate_left_move(A_G[F], 19);
		A_G[F] = A_G[E];
		A_G[E] = _P0(TT2);
	}

	for (j = 0; j < 8; j++)
	{
		nHash[j] = A_G[j] ^ nHash[j];
	}

	return 0;
}

unsigned int sm3(const char* ucpSrcData,	unsigned int nSrcLen,	unsigned char* ucpHash)
{
	_init_T();
	unsigned int nGroupNum = (nSrcLen + 1 + 8 + 64) / 64;
	unsigned char* ucpMsgBuf = (unsigned char*)malloc(nGroupNum * 64);
	memset(ucpMsgBuf, 0, nGroupNum * 64);
	memcpy(ucpMsgBuf, ucpSrcData, nSrcLen);
	ucpMsgBuf[nSrcLen] = 0x80;

	int i = 0;
	for (i = 0; i < 8; i++)
	{
		ucpMsgBuf[nGroupNum * 64 - i - 1] = ((unsigned long long)(nSrcLen * 8) >> (i * 8)) & 0xFF;
	}

	unsigned int nHash[8] = { 0 };
	for (int i = 0; i < 8; i++)
	{
		nHash[i] = IV[i];
	}

	for (i = 0; i < nGroupNum; i++)
	{
		_CF(&ucpMsgBuf[i * 64], nHash);
	}

	free(ucpMsgBuf);

	for (i = 0; i < 8; i++)
	{
		ucpHash[i * 4 + 0] = (unsigned char)((nHash[i] >> 24) & 0xFF);
		ucpHash[i * 4 + 1] = (unsigned char)((nHash[i] >> 16) & 0xFF);
		ucpHash[i * 4 + 2] = (unsigned char)((nHash[i] >> 8) & 0xFF);
		ucpHash[i * 4 + 3] = (unsigned char)((nHash[i] >> 0) & 0xFF);
	}
	return nGroupNum;
}
int main()
{
	unsigned char hashmem[32];
	unsigned char hashmemat[32];
	string a, aex;
	cin >> a;
	int as = a.size();
	int ns = ((as + 1 + 8 + 64) / 64) * 64;
	aex = a;
	aex.append(1, 0x80);
	while (aex.size() < ns - 8)
		aex.append(1, 0x00);
	for (int i = 7; i >= 0; i--)
		aex.append(1, ((unsigned long long)(as * 8) >> (i * 8)) & 0xFF);
	unsigned char extend[64];
	memset(extend, 0, 64);
	extend[0] = 0x80;
	for (int i = 0; i < 8; i++)
	{
		extend[63 - i] = ((unsigned long long)(aex.size() * 8) >> (i * 8)) & 0xFF;
	}
	sm3(a.c_str(), a.size(), hashmem);
	for (int i = 0;i < 8;i++)
	{
		hashmem[4 * i + 3]=exchange(hashmem[4 * i + 0], hashmem[4 * i + 3]);
		hashmem[4 * i + 2]=exchange(hashmem[4 * i + 1], hashmem[4 * i + 2]);
	}
	_CF(extend, (unsigned int*)hashmem);
	for (int i = 0;i < 8;i++)
	{
		hashmem[4 * i + 3] = exchange(hashmem[4 * i + 0], hashmem[4 * i + 3]);
		hashmem[4 * i + 2] = exchange(hashmem[4 * i + 1], hashmem[4 * i + 2]);
	}
	sm3(aex.c_str(), aex.size(), hashmemat);
	for (int i = 0;i < 32;i++)
		cout << hex << (int)hashmem[i] <<" " << hex << (int)hashmemat[i] << endl;
	bool flag = 1;
	for (int i = 0;i < 32;i++)
		if (hashmem[i] != hashmemat[i])
			flag = 0;
	if (flag)
		cout << "长度扩展攻击成功" << endl;
	return 0;
}