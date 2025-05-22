#include "include.h"
#include "aes256cbc.h"
#include "sha256.h"

std::vector<uint8_t> random_iv()
{
	std::vector<uint8_t> iv(16);
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<uint32_t> dis(0, 255);
	for (auto& s : iv) s = dis(gen);
	return iv;
}

std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& data)
{
	size_t pl = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
	std::vector<uint8_t> pd = data;
	pd.insert(pd.end(), pl, static_cast<uint8_t>(pl));
	return pd;
}

std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& data)
{
	if (data.empty()) return {};
	size_t pl = data.back();
	if (pl == 0 || pl > 16) return data;
	return std::vector<uint8_t>(data.begin(), data.end() - pl);
}

std::vector<uint8_t> Cryptor::encrypt_bin(T1 data, T1 key)
{
	if (key.size() != 32) return {};

	std::vector<uint8_t> iv = random_iv();
	std::vector<uint8_t> pad_data = pkcs7_pad(data);
	std::vector<uint8_t> enc_data;

	AES_CTX ctx;
	AES_EncryptInit(&ctx, key.data(), iv.data());

	for (size_t i = 0; i < pad_data.size(); i += AES_BLOCK_SIZE)
	{
		uint8_t block[AES_BLOCK_SIZE];
		uint8_t enc_block[AES_BLOCK_SIZE];

		for (size_t j = 0; j < AES_BLOCK_SIZE; ++j)
		{
			block[j] = pad_data[i + j];
		}

		AES_Encrypt(&ctx, block, enc_block);
		enc_data.insert(enc_data.end(), enc_block, enc_block + AES_BLOCK_SIZE);
	}

	enc_data.insert(enc_data.begin(), iv.begin(), iv.end());
	return enc_data;
}

std::vector<uint8_t> Cryptor::decrypt_bin(T1 data, T1 key)
{
	if (key.size() != 32) return {};
	if (data.size() < 16) return {};

	std::vector<uint8_t> iv(data.begin(), data.begin() + 16);
	std::vector<uint8_t> enc_data(data.begin() + 16, data.end());
	std::vector<uint8_t> dec_data;

	AES_CTX ctx;
	AES_DecryptInit(&ctx, key.data(), iv.data());

	for (size_t i = 0; i < enc_data.size(); i += AES_BLOCK_SIZE)
	{
		uint8_t block[AES_BLOCK_SIZE];
		uint8_t dec_block[AES_BLOCK_SIZE];

		for (size_t j = 0; j < AES_BLOCK_SIZE; ++j)
		{
			block[j] = enc_data[i + j];
		}

		AES_Decrypt(&ctx, block, dec_block);
		dec_data.insert(dec_data.end(), dec_block, dec_block + AES_BLOCK_SIZE);
	}

	return pkcs7_unpad(dec_data);
}

void Cryptor::encrypt_file(T2 ipath, T2 opath, T1 key)
{
	std::ifstream infile(ipath, std::ios::binary);
	if (!infile.is_open()) return;

	std::ofstream outfile(opath, std::ios::binary);
	if (!outfile.is_open()) return;

	std::vector<uint8_t> iv = random_iv();

	outfile.write(reinterpret_cast<const char*>(iv.data()), iv.size());

	AES_CTX ctx;
	AES_EncryptInit(&ctx, key.data(), iv.data());

	std::vector<uint8_t> buffer(16);
	while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || infile.gcount() > 0)
	{
		size_t bytes_read = infile.gcount();

		if (bytes_read < 16) 
		{
			buffer.resize(bytes_read);
			buffer = pkcs7_pad(buffer);
		}

		std::vector<uint8_t> encrypted_block(16);
		AES_Encrypt(&ctx, buffer.data(), encrypted_block.data());

		outfile.write(reinterpret_cast<const char*>(encrypted_block.data()), encrypted_block.size());
	}

	infile.close();
	outfile.close();
}

void Cryptor::decrypt_file(T2 ipath, T2 opath, T1 key)
{
	std::ifstream infile(ipath, std::ios::binary);
	if (!infile.is_open()) return;

	std::ofstream outfile(opath, std::ios::binary);
	if (!outfile.is_open()) return;

	std::vector<uint8_t> iv(16);
	infile.read(reinterpret_cast<char*>(iv.data()), iv.size());
	if (infile.gcount() != 16) return;

	AES_CTX ctx;
	AES_DecryptInit(&ctx, key.data(), iv.data());

	std::vector<uint8_t> buffer(16);

	while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()))
	{
		size_t bytes_read = infile.gcount();

		std::vector<uint8_t> decrypted_block(16);
		AES_Decrypt(&ctx, buffer.data(), decrypted_block.data());

		if (infile.peek() == EOF)
		{
			decrypted_block = pkcs7_unpad(decrypted_block);
		}

		outfile.write(reinterpret_cast<const char*>(decrypted_block.data()), decrypted_block.size());
	}

	infile.close();
	outfile.close();
}

std::vector<uint8_t> Cryptor::b64_enc(T1 input)
{
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::vector<uint8_t> encoded;
	size_t bits = 0;
	int val = 0;

	for (uint8_t c : input) {
		val = (val << 8) + c;
		bits += 8;
		while (bits >= 6) {
			bits -= 6;
			encoded.push_back(static_cast<uint8_t>(base64_chars[(val >> bits) & 0x3F]));
		}
	}

	if (bits > 0) {
		val <<= 6 - bits;
		encoded.push_back(static_cast<uint8_t>(base64_chars[val & 0x3F]));
	}

	while (encoded.size() % 4 != 0) {
		encoded.push_back('=');
	}

	return encoded;
}

std::vector<uint8_t> Cryptor::b64_dec(T1 input)
{
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::vector<uint8_t> decoded;
	size_t bits = 0;
	int val = 0;

	for (uint8_t c : input) {
		if (c == '=') {
			break;
		}

		size_t index = base64_chars.find(c);
		if (index == std::string::npos) return {};

		val = (val << 6) + static_cast<int>(index);
		bits += 6;

		if (bits >= 8) {
			bits -= 8;
			decoded.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
		}
	}

	return decoded;
}

std::vector<uint8_t> Cryptor::sha256(const std::string& input)
{
	std::vector<uint8_t> hash(SHA256_LENGTH);
	sha256_context ctx;
	sha256_starts(&ctx);
	sha256_update(&ctx, input.data(), input.size());
	sha256_finish(&ctx, hash.data());
	return hash;
}