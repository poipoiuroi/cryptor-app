#pragma once
#ifndef _CRYPTOR_H_
#define _CRYPTOR_H_

#include "include.h"

using T1 = const std::vector<uint8_t>&;
using T2 = const std::wstring&;

class Cryptor
{
public:
	std::vector<uint8_t> encrypt_bin(T1 data, T1 key);
	std::vector<uint8_t> decrypt_bin(T1 data, T1 key);
	void encrypt_file(T2 ipath, T2 opath, T1 key);
	void decrypt_file(T2 ipath, T2 opath, T1 key);
	std::vector<uint8_t> b64_enc(T1 input);
	std::vector<uint8_t> b64_dec(T1 input);
	std::vector<uint8_t> sha256(const std::string& input);
};

inline Cryptor* g_cryptor()
{
	static Cryptor cryptor;
	return &cryptor;
}

#endif