#pragma once
#ifndef _CRYPTORT_H_
#define _CRYPTORT_H_

#include <string>
#include <array>
#include <vector>
#include <windows.h>

struct CryptorT
{
	bool encrypt_bin(
		const std::vector<uint8_t>& indata,
		const std::array<uint8_t, 32>& key,
		std::vector<uint8_t>& outdata) noexcept;

	bool decrypt_bin(
		const std::vector<uint8_t>& indata,
		const std::array<uint8_t, 32>& key,
		std::vector<uint8_t>& outdata) noexcept;

	bool encrypt_file(
		const std::wstring& ipath,
		const std::wstring& opath,
		const std::array<uint8_t, 32>& key) noexcept;

	bool decrypt_file(
		const std::wstring& ipath,
		const std::wstring& opath,
		const std::array<uint8_t, 32>& key) noexcept;

	std::vector<uint8_t> b64_enc(const std::vector<uint8_t>& input) noexcept;

	std::vector<uint8_t> b64_dec(const std::vector<uint8_t>& input) noexcept;

	std::array<uint8_t, 32> sha256(const std::string& input) noexcept;
};

inline CryptorT* g_cryptor()
{
	static CryptorT cryptor;
	return &cryptor;
}

#endif
