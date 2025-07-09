#include "include.h"

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void ApplyTheme()
{
	ImGuiStyle& style = ImGui::GetStyle();
	style.GrabMinSize = 20;
	style.FramePadding.y += 2.0f;
	style.WindowTitleAlign = ImVec2(0.50f, 0.50f);
	style.WindowRounding = 5.0f;
	style.FrameRounding = 2.0f;
	style.FrameBorderSize = 1.0f;

	style.Colors[ImGuiCol_Border] = ImVec4(0.f, 255.f, 255.f, 255.f);
	style.Colors[ImGuiCol_Text] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
	style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.00f, 0.40f, 0.41f, 1.00f);
	style.Colors[ImGuiCol_Border] = ImVec4(0.00f, 1.00f, 1.00f, 0.65f);
	style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	style.Colors[ImGuiCol_FrameBg] = ImVec4(0.44f, 0.80f, 0.80f, 0.1f);
	style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.44f, 0.80f, 0.80f, 0.27f);
	style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.44f, 0.81f, 0.86f, 0.66f);
	style.Colors[ImGuiCol_TitleBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.89f);
	style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.89f);
	style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.03, 0.04, 0.05, 1);
	style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.20f);
	style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.22f, 0.29f, 0.30f, 0.71f);
	style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.00f, 1.00f, 1.00f, 0.44f);
	style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.00f, 1.00f, 1.00f, 0.74f);
	style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
	style.Colors[ImGuiCol_CheckMark] = ImVec4(0.00f, 1.00f, 1.00f, 0.68f);
	style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.00f, 1.00f, 1.00f, 0.36f);
	style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.00f, 1.00f, 1.00f, 0.76f);
	style.Colors[ImGuiCol_Button] = ImVec4(0.00f, 0.65f, 0.65f, 0.06f);
	style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.01f, 1.00f, 1.00f, 0.23f);
	style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.00f, 1.00f, 1.00f, 0.32f);
	style.Colors[ImGuiCol_Header] = ImVec4(0.00f, 1.00f, 1.00f, 0.33f);
	style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.00f, 1.00f, 1.00f, 0.42f);
	style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.00f, 1.00f, 1.00f, 0.54f);
	style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 1.00f, 1.00f, 0.54f);
	style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.00f, 1.00f, 1.00f, 0.74f);
	style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
	style.Colors[ImGuiCol_PlotLines] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
	style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
	style.Colors[ImGuiCol_PlotHistogram] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
	style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
	style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.00f, 1.00f, 1.00f, 0.22f);
	style.Colors[ImGuiCol_WindowBg] = ImVec4(0.03, 0.04, 0.05, 1);
}

void RenderLoop()
{
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.IniFilename = NULL;

	ApplyTheme();
	ImGui_ImplWin32_Init(g_core()->g_hwnd);
	ImGui_ImplDX11_Init(g_core()->g_pd3dDevice, g_core()->g_pd3dDeviceContext);

	ImVec4 cc = ImVec4(0.00f, 0.75f, 0.52f, 1.00f);
	const float ccwa[4] = { cc.x * cc.w, cc.y * cc.w, cc.z * cc.w, cc.w };

	while (g_core()->is_working)
	{
		if (g_core()->g_SwapChainOccluded && g_core()->g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
		{
			WaitMessage();
			continue;
		}

		g_core()->g_SwapChainOccluded = false;

		if (g_core()->g_ResizeWidth != 0 && g_core()->g_ResizeHeight != 0)
		{
			CleanupRenderTarget();
			g_core()->g_pSwapChain->ResizeBuffers(0, g_core()->g_ResizeWidth, g_core()->g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
			g_core()->g_ResizeWidth = g_core()->g_ResizeHeight = 0;
			CreateRenderTarget();
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		g_core()->main_core();

		ImGui::Render();

		g_core()->g_pd3dDeviceContext->OMSetRenderTargets(1, &g_core()->g_mainRenderTargetView, 0);
		g_core()->g_pd3dDeviceContext->ClearRenderTargetView(g_core()->g_mainRenderTargetView, ccwa);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		HRESULT hr = g_core()->g_pSwapChain->Present(2, 0);
		g_core()->g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
	}

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
}

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	WNDCLASSW wc{ 0 };
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = L"pdfsghdfhgskdf";

	RegisterClassW(&wc);

	g_core()->g_hwnd = CreateWindowExW(
		NULL,
		wc.lpszClassName,
		L"Qaxulorer",
		WS_POPUP,
		100, 100, g_core()->w_width, g_core()->w_high,
		NULL, NULL,
		wc.hInstance, NULL);

	if (!CreateDeviceD3D(g_core()->g_hwnd))
	{
		CleanupDeviceD3D();
		UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}

	ShowWindow(g_core()->g_hwnd, SW_SHOWDEFAULT);
	UpdateWindow(g_core()->g_hwnd);

	std::thread th(RenderLoop);

	MSG msg;
	while (GetMessageW(&msg, 0, 0U, 0U))
	{
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
		if (!g_core()->is_working)
		{
			th.join();
			break;
		}
	}

	CleanupDeviceD3D();
	DestroyWindow(g_core()->g_hwnd);
	UnregisterClassW(wc.lpszClassName, wc.hInstance);

	return 0;
}

bool CreateDeviceD3D(HWND hWnd)
{
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hWnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	HRESULT res = D3D11CreateDeviceAndSwapChain(0, D3D_DRIVER_TYPE_HARDWARE, 0, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_core()->g_pSwapChain, &g_core()->g_pd3dDevice, &featureLevel, &g_core()->g_pd3dDeviceContext);
	if (res == DXGI_ERROR_UNSUPPORTED)
		res = D3D11CreateDeviceAndSwapChain(0, D3D_DRIVER_TYPE_WARP, 0, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_core()->g_pSwapChain, &g_core()->g_pd3dDevice, &featureLevel, &g_core()->g_pd3dDeviceContext);
	if (res != S_OK)
		return false;

	CreateRenderTarget();
	return true;
}

void CleanupDeviceD3D()
{
	CleanupRenderTarget();
	if (g_core()->g_pSwapChain) { g_core()->g_pSwapChain->Release(); g_core()->g_pSwapChain = 0; }
	if (g_core()->g_pd3dDeviceContext) { g_core()->g_pd3dDeviceContext->Release(); g_core()->g_pd3dDeviceContext = 0; }
	if (g_core()->g_pd3dDevice) { g_core()->g_pd3dDevice->Release(); g_core()->g_pd3dDevice = 0; }
}

void CreateRenderTarget()
{
	ID3D11Texture2D* pBackBuffer;
	HRESULT hr = g_core()->g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	if (FAILED(hr)) return;
	g_core()->g_pd3dDevice->CreateRenderTargetView(pBackBuffer, 0, &g_core()->g_mainRenderTargetView);
	pBackBuffer->Release();
}

void CleanupRenderTarget()
{
	if (g_core()->g_mainRenderTargetView) { g_core()->g_mainRenderTargetView->Release(); g_core()->g_mainRenderTargetView = 0; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	switch (msg)
	{
	case WM_SIZING:
	{
		RECT* pRect = (RECT*)lParam;

		switch (wParam)
		{
		case WMSZ_LEFT:
		case WMSZ_RIGHT:
			if (pRect->right - pRect->left < g_core()->w_min_width)
			{
				if (wParam == WMSZ_LEFT)
				{
					pRect->left = pRect->right - g_core()->w_min_width;
				}
				else
				{
					pRect->right = pRect->left + g_core()->w_min_width;
				}
			}
			break;

		case WMSZ_TOP:
		case WMSZ_BOTTOM:
			if (pRect->bottom - pRect->top < g_core()->w_min_high)
			{
				if (wParam == WMSZ_TOP)
				{
					pRect->top = pRect->bottom - g_core()->w_min_high;
				}
				else
				{
					pRect->bottom = pRect->top + g_core()->w_min_high;
				}
			}
			break;

		case WMSZ_TOPLEFT:
		case WMSZ_BOTTOMLEFT:
		case WMSZ_TOPRIGHT:
		case WMSZ_BOTTOMRIGHT:
			if (pRect->right - pRect->left < g_core()->w_min_width)
			{
				if (wParam == WMSZ_TOPLEFT || wParam == WMSZ_BOTTOMLEFT)
				{
					pRect->left = pRect->right - g_core()->w_min_width;
				}
				else
				{
					pRect->right = pRect->left + g_core()->w_min_width;
				}
			}

			if (pRect->bottom - pRect->top < g_core()->w_min_high)
			{
				if (wParam == WMSZ_TOPLEFT || wParam == WMSZ_TOPRIGHT)
				{
					pRect->top = pRect->bottom - g_core()->w_min_high;
				}
				else
				{
					pRect->bottom = pRect->top + g_core()->w_min_high;
				}
			}
			break;
		}

		return 0;
	}
	case WM_NCHITTEST:
	{
		POINT pt{ LOWORD(lParam), HIWORD(lParam) };
		ScreenToClient(hWnd, &pt);

		RECT rc;
		GetClientRect(hWnd, &rc);

		if (pt.x < g_core()->w_resize_border_width && pt.y < g_core()->w_resize_border_width) return HTTOPLEFT;
		if (pt.x > rc.right - g_core()->w_resize_border_width && pt.y < g_core()->w_resize_border_width) return HTTOPRIGHT;
		if (pt.x < g_core()->w_resize_border_width && pt.y > rc.bottom - g_core()->w_resize_border_width) return HTBOTTOMLEFT;
		if (pt.x > rc.right - g_core()->w_resize_border_width && pt.y > rc.bottom - g_core()->w_resize_border_width) return HTBOTTOMRIGHT;
		if (pt.x < g_core()->w_resize_border_width) return HTLEFT;
		if (pt.x > rc.right - g_core()->w_resize_border_width) return HTRIGHT;
		if (pt.y < g_core()->w_resize_border_width) return HTTOP;
		if (pt.y > rc.bottom - g_core()->w_resize_border_width) return HTBOTTOM;

		return HTCLIENT;
	}
	case WM_MOUSEMOVE:
	{
		if (wParam == MK_LBUTTON)
		{
			const auto points = MAKEPOINTS(lParam);
			auto rect = RECT{ };

			GetWindowRect(hWnd, &rect);
			rect.left += points.x - g_core()->position.x;
			rect.top += points.y - g_core()->position.y;

			if (g_core()->position.x >= NULL && g_core()->position.x <= g_core()->w_width && g_core()->position.y >= NULL && g_core()->position.y <= g_core()->w_drag_border_width)
			{
				SetWindowPos(hWnd, HWND_TOPMOST, rect.left, rect.top, NULL, NULL, SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOZORDER);
			}
		}
		return NULL;
	}
	case WM_SIZE:
	{
		if (wParam == SIZE_MINIMIZED)
			return 0;

		POINTS pt{ (UINT)LOWORD(lParam), (UINT)HIWORD(lParam) };

		if (pt.x < g_core()->w_min_width)
			pt.x = g_core()->w_min_width;
		if (pt.y < g_core()->w_min_high)
			pt.y = g_core()->w_min_high;

		g_core()->g_ResizeWidth = pt.x;
		g_core()->g_ResizeHeight = pt.y;
		g_core()->w_width = pt.x;
		g_core()->w_high = pt.y;

		return 0;
	}
	case WM_LBUTTONDOWN:
	{
		g_core()->position = MAKEPOINTS(lParam);
		return NULL;
	}
	case WM_SYSCOMMAND:
	{
		if ((wParam & 0xfff0) == SC_KEYMENU)
			return 0;

		break;
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		return 0;
	}
	}
	return DefWindowProcW(hWnd, msg, wParam, lParam);
}
