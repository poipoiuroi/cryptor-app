#pragma once
#include <cstdint>
#include <intrin.h>

struct alignas(16) aes256_t
{
	static constexpr size_t AES_BLOCK = 16;
	static constexpr size_t Nr = 14;

	__m128i round_keys[Nr + 1];

	__forceinline void assist_1(__m128i* __restrict tmp1, __m128i* __restrict tmp2)
	{
		__m128i tmp4;
		*tmp2 = _mm_shuffle_epi32(*tmp2, 0xff);
		tmp4 = _mm_slli_si128(*tmp1, 4);
		*tmp1 = _mm_xor_si128(*tmp1, tmp4);
		tmp4 = _mm_slli_si128(tmp4, 4);
		*tmp1 = _mm_xor_si128(*tmp1, tmp4);
		tmp4 = _mm_slli_si128(tmp4, 4);
		*tmp1 = _mm_xor_si128(*tmp1, tmp4);
		*tmp1 = _mm_xor_si128(*tmp1, *tmp2);
	}

	__forceinline void assist_2(__m128i* __restrict tmp1, __m128i* __restrict tmp3)
	{
		__m128i tmp2, tmp4;
		tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x0);
		tmp2 = _mm_shuffle_epi32(tmp4, 0xaa);
		tmp4 = _mm_slli_si128(*tmp3, 4);
		*tmp3 = _mm_xor_si128(*tmp3, tmp4);
		tmp4 = _mm_slli_si128(tmp4, 4);
		*tmp3 = _mm_xor_si128(*tmp3, tmp4);
		tmp4 = _mm_slli_si128(tmp4, 4);
		*tmp3 = _mm_xor_si128(*tmp3, tmp4);
		*tmp3 = _mm_xor_si128(*tmp3, tmp2);
	}

	__forceinline void encrypt_block(uint8_t* __restrict block) const
	{
		__m128i state = _mm_load_si128(reinterpret_cast<const __m128i*>(block));
		state = _mm_xor_si128(state, round_keys[0]);

		state = _mm_aesenc_si128(state, round_keys[1]);
		state = _mm_aesenc_si128(state, round_keys[2]);
		state = _mm_aesenc_si128(state, round_keys[3]);
		state = _mm_aesenc_si128(state, round_keys[4]);
		state = _mm_aesenc_si128(state, round_keys[5]);
		state = _mm_aesenc_si128(state, round_keys[6]);
		state = _mm_aesenc_si128(state, round_keys[7]);
		state = _mm_aesenc_si128(state, round_keys[8]);
		state = _mm_aesenc_si128(state, round_keys[9]);
		state = _mm_aesenc_si128(state, round_keys[10]);
		state = _mm_aesenc_si128(state, round_keys[11]);
		state = _mm_aesenc_si128(state, round_keys[12]);
		state = _mm_aesenc_si128(state, round_keys[13]);
		state = _mm_aesenclast_si128(state, round_keys[14]);

		_mm_store_si128(reinterpret_cast<__m128i*>(block), state);
	}

	__forceinline void decrypt_block(uint8_t* __restrict block) const
	{
		__m128i state = _mm_load_si128(reinterpret_cast<const __m128i*>(block));
		state = _mm_xor_si128(state, round_keys[Nr]);

		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 1]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 2]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 3]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 4]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 5]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 6]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 7]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 8]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 9]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 10]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 11]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 12]));
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_keys[Nr - 13]));
		state = _mm_aesdeclast_si128(state, round_keys[0]);

		_mm_store_si128(reinterpret_cast<__m128i*>(block), state);
	}

	explicit aes256_t(const uint8_t user_key[32])
	{
		__m128i tmp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(user_key));
		__m128i tmp3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(user_key + 16));
		__m128i tmp2;

		round_keys[0] = tmp1;
		round_keys[1] = tmp3;

		tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
		assist_1(&tmp1, &tmp2);
		round_keys[2] = tmp1;

		assist_2(&tmp1, &tmp3);
		round_keys[3] = tmp3;

		tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
		assist_1(&tmp1, &tmp2);
		round_keys[4] = tmp1;

		assist_2(&tmp1, &tmp3);
		round_keys[5] = tmp3;

		tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
		assist_1(&tmp1, &tmp2);
		round_keys[6] = tmp1;

		assist_2(&tmp1, &tmp3);
		round_keys[7] = tmp3;

		tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
		assist_1(&tmp1, &tmp2);
		round_keys[8] = tmp1;

		assist_2(&tmp1, &tmp3);
		round_keys[9] = tmp3;

		tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
		assist_1(&tmp1, &tmp2);
		round_keys[10] = tmp1;

		assist_2(&tmp1, &tmp3);
		round_keys[11] = tmp3;

		tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
		assist_1(&tmp1, &tmp2);
		round_keys[12] = tmp1;

		assist_2(&tmp1, &tmp3);
		round_keys[13] = tmp3;

		tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
		assist_1(&tmp1, &tmp2);
		round_keys[14] = tmp1;
	}

	~aes256_t()
	{
		__m128i zero = _mm_setzero_si128();
		for (auto& rk : round_keys)
			_mm_store_si128(&rk, zero);
	}
};
