#pragma once
#ifndef _FUNCS_H_
#define _FUNCS_H_

#include "include.h"

class Funcs
{
public:
	void clear_all();
	void str_enc_dec(bool is_encrypt);
	void file_enc_dec(bool is_encrypt);
	void shuffle();
	void random_pass();
	void pick_dir(std::wstring& fp);
	void pick_file(std::wstring& fp);
	void merge_file();
	void split_file();
};

inline Funcs* g_funcs()
{
	static Funcs funcs;
	return &funcs;
}

#endif