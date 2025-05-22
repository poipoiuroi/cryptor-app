#pragma once
#ifndef _CORE_H_
#define _CORE_H_

#include "include.h"

class Core
{
public:
	void main_core();

	// render
	HWND g_hwnd{};
	ID3D11Device* g_pd3dDevice{};
	ID3D11DeviceContext* g_pd3dDeviceContext{};
	IDXGISwapChain* g_pSwapChain{};
	BOOL g_SwapChainOccluded = FALSE;
	UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
	ID3D11RenderTargetView* g_mainRenderTargetView{};

	// window
	POINTS position{};
	bool is_working = true;
	int w_width = 351;
	int w_high = 351;
	int w_min_width = 350;
	int w_min_high = 350;
	int w_resize_border_width = 5;
	int w_drag_border_width = 20;

	// imgui settings
	int current_tab = 1;

	bool is_key_hidden = true;
	bool all_in_one_line = true;
	char ed_key_buf[512] = "";
	char ed_in_buf[512] = "";
	char ed_out_buf[512] = "";
	int ed_current_item = 0;
	const char* ed_items[2] = { "aes-256", "base64" };

	int split_num = 2;
	std::wstring file_path;
	std::wstring dir_path;

	char ps_out_buf[1024] = "";
	char spec_buf[21] = "!@#$%^&*()_-+=:?*";
	bool spec_symbs = true;
	int pass_size = 25;

	char ll_in_buf[16384] = "";
	int ll_current_item = 0;
	const char* ll_items[3] = { "byLines", "byLength", "inRow" };
};

inline Core* g_core()
{
	static Core core;
	return &core;
}

#endif