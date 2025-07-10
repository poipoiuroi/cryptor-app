#pragma once
#include <stdint.h>
#include <intrin.h>

struct alignas(32) sha256_t
{
private:
	uint32_t state[8];
	uint64_t total = 0;
	uint8_t buffer[64]{};

	__forceinline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (~x & z); }
	__forceinline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); }
	__forceinline uint32_t ep0(uint32_t x) noexcept { return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22); }
	__forceinline uint32_t ep1(uint32_t x) noexcept { return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25); }
	__forceinline uint32_t sig0(uint32_t x) noexcept { return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3); }
	__forceinline uint32_t sig1(uint32_t x) noexcept { return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10); }

	static constexpr uint32_t k[64]
	{
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	void process() noexcept
	{
		uint32_t w[64];
		for (int i = 0; i < 16; ++i)
			w[i] = (uint32_t(buffer[i * 4 + 0]) << 24) |
			(uint32_t(buffer[i * 4 + 1]) << 16) |
			(uint32_t(buffer[i * 4 + 2]) << 8) |
			(uint32_t(buffer[i * 4 + 3]));

		for (int i = 16; i < 64; ++i)
			w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16];

		uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
		uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

		for (int i = 0; i < 64; ++i)
		{
			uint32_t t1 = h + ep1(e) + ch(e, f, g) + k[i] + w[i];
			uint32_t t2 = ep0(a) + maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		state[0] += a; state[1] += b; state[2] += c; state[3] += d;
		state[4] += e; state[5] += f; state[6] += g; state[7] += h;
	}

public:
	explicit sha256_t() { reset(); }

	inline void reset() noexcept
	{
		total = 0;
		state[0] = 0x6a09e667; state[1] = 0xbb67ae85;
		state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
		state[4] = 0x510e527f; state[5] = 0x9b05688c;
		state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
	}

	void update(const void* __restrict input, uint64_t len) noexcept
	{
		const uint8_t* data = static_cast<const uint8_t*>(input);
		uint64_t filled = total & 63;
		total += len;

		if (filled)
		{
			uint64_t need = 64 - filled;
			if (len < need)
			{
				__movsb(buffer + filled, data, size_t(len));
				return;
			}
			__movsb(buffer + filled, data, size_t(need));
			process();
			data += need;
			len -= need;
		}

		while (len >= 64)
		{
			__movsb(buffer, data, 64);
			process();
			data += 64;
			len -= 64;
		}

		if (len) __movsb(buffer, data, size_t(len));
	}

	void finish(void* __restrict output) noexcept
	{
		uint8_t lenbuf[8];
		uint64_t bits = total << 3;
		for (int i = 0; i < 8; ++i)
			lenbuf[7 - i] = static_cast<uint8_t>(bits >> (i * 8));

		uint64_t last = total & 63;
		buffer[last++] = 0x80;

		if (last > 56)
		{
			memset(buffer + last, 0, 64 - last);
			process();
			last = 0;
		}

		memset(buffer + last, 0, 56 - last);
		for (int i = 0; i < 8; ++i) buffer[56 + i] = lenbuf[i];

		process();

		uint8_t* out = static_cast<uint8_t*>(output);
		for (int i = 0; i < 8; ++i)
		{
			out[i * 4 + 0] = static_cast<uint8_t>(state[i] >> 24);
			out[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
			out[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
			out[i * 4 + 3] = static_cast<uint8_t>(state[i]);
		}
	}
};
