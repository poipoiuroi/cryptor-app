#include "cryptort.h"
#include "aes256.h"
#include "sha256.h"

__forceinline uint64_t fast_rand64() noexcept
{
	static thread_local uint64_t x = __rdtsc() | 1;
	x ^= x >> 17;
	x *= 0x2545F4914F6CDD1DULL;
	return _rotr64(x, static_cast<unsigned>(x >> 59));
}

__forceinline std::array<uint8_t, 16> random_iv() noexcept
{
	uint64_t r0 = fast_rand64();
	uint64_t r1 = fast_rand64();

	std::array<uint8_t, 16> iv;
	memcpy(&iv[0], &r0, 8);
	memcpy(&iv[8], &r1, 8);
	return iv;
}

__forceinline bool pkcs7_pad(const std::vector<uint8_t>& indata, std::vector<uint8_t>& outdata) noexcept
{
	const size_t in_size = indata.size();
	const uint8_t pad = static_cast<uint8_t>(aes256_t::AES_BLOCK - (in_size % aes256_t::AES_BLOCK));

	outdata.resize(in_size + pad);

	uint8_t* dst = outdata.data();
	const uint8_t* src = indata.data();

	__movsb(dst, src, in_size);
	__stosb(dst + in_size, pad, pad);

	return true;
}

__forceinline bool pkcs7_unpad(const std::vector<uint8_t>& indata, std::vector<uint8_t>& outdata) noexcept
{
	const size_t len = indata.size();
	if (len == 0) return false;

	const uint8_t pad = indata[len - 1];
	if (pad == 0 || pad > aes256_t::AES_BLOCK)
	{
		if (&outdata != &indata)
			outdata = indata;
		return true;
	}

	const size_t new_size = len - pad;
	if (outdata.size() != new_size)
		outdata.resize(new_size);

	if (outdata.data() != indata.data())
		__movsb(outdata.data(), indata.data(), new_size);

	return true;
}

bool CryptorT::encrypt_bin(
	const std::vector<uint8_t>& indata,
	const std::array<uint8_t, 32>& key,
	std::vector<uint8_t>& outdata) noexcept
{
	const std::array<uint8_t, 16> iv = random_iv();

	std::vector<uint8_t> padded;
	if (!pkcs7_pad(indata, padded))
		return false;

	const size_t padded_len = padded.size();
	outdata.resize(16 + padded_len);

	uint8_t* out_ptr = outdata.data();
	std::memcpy(out_ptr, iv.data(), 16);

	aes256_t aes(key.data());

	__m128i feedback = _mm_loadu_si128((const __m128i*)iv.data());

	uint8_t* dst = out_ptr + 16;
	const uint8_t* src = padded.data();

	for (size_t i = 0; i < padded_len; i += 16)
	{
		__m128i block = _mm_loadu_si128((const __m128i*)(src + i));
		block = _mm_xor_si128(block, feedback);
		_mm_store_si128((__m128i*)(dst + i), block);
		aes.encrypt_block(dst + i);
		feedback = _mm_load_si128((const __m128i*)(dst + i));
	}

	return true;
}

bool CryptorT::decrypt_bin(
	const std::vector<uint8_t>& indata,
	const std::array<uint8_t, 32>& key,
	std::vector<uint8_t>& outdata) noexcept
{
	if (indata.size() < 16 || ((indata.size() - 16) % 16) != 0)
		return false;

	const uint8_t* iv = indata.data();
	const uint8_t* src = indata.data() + 16;
	const size_t enc_len = indata.size() - 16;

	std::vector<uint8_t> dec(enc_len);

	aes256_t aes(key.data());
	__m128i feedback = _mm_loadu_si128((const __m128i*)iv);

	uint8_t* dst = dec.data();

	for (size_t i = 0; i < enc_len; i += 16)
	{
		__m128i block = _mm_loadu_si128((const __m128i*)(src + i));
		__m128i decrypted = block;
		aes.decrypt_block((uint8_t*)&decrypted);
		decrypted = _mm_xor_si128(decrypted, feedback);
		_mm_storeu_si128((__m128i*)(dst + i), decrypted);
		feedback = block;
	}

	return pkcs7_unpad(dec, outdata);
}

bool CryptorT::encrypt_file(
	const std::wstring& ipath,
	const std::wstring& opath,
	const std::array<uint8_t, 32>& key) noexcept
{
	constexpr size_t BLOCK_SIZE = aes256_t::AES_BLOCK;
	constexpr size_t BUFFER_SIZE = 1 << 20;

	HANDLE hin = CreateFileW(ipath.c_str(), GENERIC_READ, FILE_SHARE_READ, 0,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, 0);

	if (hin == INVALID_HANDLE_VALUE)
		return false;

	HANDLE hout = CreateFileW(opath.c_str(), GENERIC_WRITE, 0, 0,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (hout == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hin);
		return false;
	}

	const std::array<uint8_t, 16> iv = random_iv();
	DWORD written = 0;
	if (!WriteFile(hout, iv.data(), BLOCK_SIZE, &written, 0))
	{
		CloseHandle(hin);
		CloseHandle(hout);
		return false;
	}

	aes256_t aes(key.data());
	__m128i feedback = _mm_loadu_si128((const __m128i*)iv.data());

	std::vector<uint8_t> buffer(BUFFER_SIZE);
	DWORD bytes_read = 0;
	bool last_block = false;

	while (!last_block)
	{
		if (!ReadFile(hin, buffer.data(), static_cast<DWORD>(BUFFER_SIZE), &bytes_read, 0) || bytes_read == 0)
			break;

		size_t processed = 0;
		size_t to_process = bytes_read - (bytes_read % BLOCK_SIZE);

		for (; processed < to_process; processed += BLOCK_SIZE)
		{
			__m128i block = _mm_loadu_si128((__m128i*) & buffer[processed]);
			block = _mm_xor_si128(block, feedback);
			_mm_storeu_si128((__m128i*) & buffer[processed], block);
			aes.encrypt_block(&buffer[processed]);
			feedback = _mm_loadu_si128((__m128i*) & buffer[processed]);
		}

		if (processed < static_cast<size_t>(bytes_read))
		{
			std::vector<uint8_t> partial(buffer.begin() + processed, buffer.begin() + bytes_read);
			if (!pkcs7_pad(partial, partial))
			{
				CloseHandle(hin);
				CloseHandle(hout);
				return false;
			}

			for (size_t i = 0; i < partial.size(); i += BLOCK_SIZE)
			{
				__m128i block = _mm_loadu_si128((__m128i*) & partial[i]);
				block = _mm_xor_si128(block, feedback);
				_mm_storeu_si128((__m128i*) & partial[i], block);
				aes.encrypt_block(&partial[i]);
				feedback = _mm_loadu_si128((__m128i*) & partial[i]);
			}

			if (!WriteFile(hout, buffer.data(), static_cast<DWORD>(processed), &written, 0) ||
				!WriteFile(hout, partial.data(), static_cast<DWORD>(partial.size()), &written, 0))
			{
				CloseHandle(hin);
				CloseHandle(hout);
				return false;
			}

			last_block = true;
			break;
		}
		else
		{
			if (!WriteFile(hout, buffer.data(), static_cast<DWORD>(processed), &written, 0))
			{
				CloseHandle(hin);
				CloseHandle(hout);
				return false;
			}
		}
	}

	CloseHandle(hin);
	CloseHandle(hout);
	return true;
}

bool CryptorT::decrypt_file(
	const std::wstring& ipath,
	const std::wstring& opath,
	const std::array<uint8_t, 32>& key) noexcept
{
	constexpr size_t BLOCK_SIZE = aes256_t::AES_BLOCK;
	constexpr size_t BUFFER_SIZE = 1 << 20;

	HANDLE hin = CreateFileW(ipath.c_str(), GENERIC_READ, FILE_SHARE_READ, 0,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, 0);

	if (hin == INVALID_HANDLE_VALUE)
		return false;

	HANDLE hout = CreateFileW(opath.c_str(), GENERIC_WRITE, 0, 0,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (hout == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hin);
		return false;
	}

	std::array<uint8_t, BLOCK_SIZE> iv;
	DWORD read = 0;
	if (!ReadFile(hin, iv.data(), BLOCK_SIZE, &read, 0) || read != BLOCK_SIZE)
	{
		CloseHandle(hin);
		CloseHandle(hout);
		return false;
	}

	aes256_t aes(key.data());
	__m128i feedback = _mm_loadu_si128((const __m128i*)iv.data());

	std::vector<uint8_t> buffer(BUFFER_SIZE);
	std::vector<uint8_t> output;

	DWORD bytes_read = 0;
	bool eof = false;
	DWORD written = 0;

	while (!eof)
	{
		if (!ReadFile(hin, buffer.data(), static_cast<DWORD>(BUFFER_SIZE), &bytes_read, 0))
		{
			CloseHandle(hin);
			CloseHandle(hout);
			return false;
		}

		if (bytes_read == 0)
			break;

		if (bytes_read % BLOCK_SIZE != 0)
		{
			CloseHandle(hin);
			CloseHandle(hout);
			return false;
		}

		size_t block_count = bytes_read / BLOCK_SIZE;
		output.resize(bytes_read);

		for (size_t i = 0; i < block_count; ++i)
		{
			__m128i encrypted = _mm_loadu_si128((__m128i*) & buffer[i * BLOCK_SIZE]);
			aes.decrypt_block(&buffer[i * BLOCK_SIZE]);
			__m128i plain = _mm_xor_si128(_mm_loadu_si128((__m128i*) & buffer[i * BLOCK_SIZE]), feedback);
			_mm_storeu_si128((__m128i*) & output[i * BLOCK_SIZE], plain);
			feedback = encrypted;
		}

		if (bytes_read < BUFFER_SIZE)
		{
			std::vector<uint8_t> unpadded(output.begin(), output.end());
			if (!pkcs7_unpad(unpadded, unpadded))
			{
				CloseHandle(hin);
				CloseHandle(hout);
				return false;
			}
			if (!WriteFile(hout, unpadded.data(), static_cast<DWORD>(unpadded.size()), &written, 0))
			{
				CloseHandle(hin);
				CloseHandle(hout);
				return false;
			}
			break;
		}
		else
		{
			if (!WriteFile(hout, output.data(), bytes_read, &written, 0))
			{
				CloseHandle(hin);
				CloseHandle(hout);
				return false;
			}
		}
	}

	CloseHandle(hin);
	CloseHandle(hout);
	return true;
}

std::vector<uint8_t> CryptorT::b64_enc(const std::vector<uint8_t>& input) noexcept
{
	static constexpr char enc_table[64]
	{
		'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
		'Q','R','S','T','U','V','W','X','Y','Z',
		'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
		'q','r','s','t','u','v','w','x','y','z',
		'0','1','2','3','4','5','6','7','8','9','+','/'
	};

	const size_t in_len = input.size();
	const size_t out_len = ((in_len + 2) / 3) * 4;

	std::vector<uint8_t> output;
	output.reserve(out_len);

	size_t i = 0;
	while (i + 2 < in_len)
	{
		uint32_t val = (input[i] << 16) | (input[i + 1] << 8) | input[i + 2];
		output.push_back(enc_table[(val >> 18) & 0x3F]);
		output.push_back(enc_table[(val >> 12) & 0x3F]);
		output.push_back(enc_table[(val >> 6) & 0x3F]);
		output.push_back(enc_table[val & 0x3F]);
		i += 3;
	}

	if (i < in_len)
	{
		uint32_t val = input[i] << 16;
		output.push_back(enc_table[(val >> 18) & 0x3F]);
		if (i + 1 < in_len)
		{
			val |= input[i + 1] << 8;
			output.push_back(enc_table[(val >> 12) & 0x3F]);
			output.push_back(enc_table[(val >> 6) & 0x3F]);
		}
		else
		{
			output.push_back(enc_table[(val >> 12) & 0x3F]);
			output.push_back('=');
		}
		output.push_back('=');
	}

	return output;
}

std::vector<uint8_t> CryptorT::b64_dec(const std::vector<uint8_t>& input) noexcept
{
	static constexpr uint8_t dec_table[256]
	{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
		0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	std::vector<uint8_t> output;
	output.reserve((input.size() / 4) * 3);

	uint32_t val = 0;
	int bits = 0;

	for (uint8_t c : input)
	{
		if (c == '=') break;

		uint8_t d = dec_table[c];
		if (d == 0xFF) return {};

		val = (val << 6) | d;
		bits += 6;

		if (bits >= 8)
		{
			bits -= 8;
			output.push_back((val >> bits) & 0xFF);
		}
	}

	return output;
}

std::array<uint8_t, 32> CryptorT::sha256(const std::string& input) noexcept
{
	std::array<uint8_t, 32> hash{};

	sha256_t ctx;
	ctx.update(input.data(), input.size());
	ctx.finish(hash.data());

	return hash;
}
