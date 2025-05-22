#include "include.h"

static void HelpMarker(const char* desc)
{
	ImGui::TextDisabled("(?)");
	if (ImGui::BeginItemTooltip())
	{
		ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
		ImGui::TextUnformatted(desc);
		ImGui::PopTextWrapPos();
		ImGui::EndTooltip();
	}
}

void Interface1()
{
	ImGui::PushItemWidth(g_core()->w_width - 160);
	ImGui::SetCursorPos(ImVec2(10, 30));
	ImGui::InputText("##keyg33", g_core()->ed_key_buf, IM_ARRAYSIZE(g_core()->ed_key_buf), g_core()->is_key_hidden ?
		ImGuiInputTextFlags_Password + ImGuiInputTextFlags_CharsNoBlank : ImGuiInputTextFlags_CharsNoBlank,
		[](ImGuiInputTextCallbackData* data) -> int { if (data->EventChar == ' ') return 1; return 0; });
	ImGui::PopItemWidth();

	ImGui::PushItemWidth((g_core()->w_width + 130) - g_core()->w_width);
	ImGui::SetCursorPos(ImVec2(g_core()->w_width - 140, 30));
	ImGui::Combo("##qhq34ds", &g_core()->ed_current_item, g_core()->ed_items, 2);
	ImGui::PopItemWidth();

	float height1 = g_core()->w_high - (g_core()->w_high / 2) - 55;
	float height2 = g_core()->w_high - (g_core()->w_high - height1);

	ImGui::SetCursorPos(ImVec2(10, 60));
	ImGui::InputTextMultiline("##ing2", g_core()->ed_in_buf, IM_ARRAYSIZE(g_core()->ed_in_buf), ImVec2(g_core()->w_width - 20, height1));

	ImGui::SetCursorPos(ImVec2(10, height1 + 70));
	ImGui::InputTextMultiline("##outk6", g_core()->ed_out_buf, IM_ARRAYSIZE(g_core()->ed_out_buf), ImVec2(g_core()->w_width - 20, height2), ImGuiInputTextFlags_ReadOnly);

	ImGui::SetCursorPos(ImVec2(10, g_core()->w_high - 30));
	if (ImGui::Button("encrypt", { 60, 20 })) g_funcs()->str_enc_dec(1);

	ImGui::SetCursorPos(ImVec2(80, g_core()->w_high - 30));
	if (ImGui::Button("decrypt", { 60, 20 })) g_funcs()->str_enc_dec(0);

	ImGui::SetCursorPos(ImVec2(150, g_core()->w_high - 30 - 1));
	ImGui::Checkbox("inline", &g_core()->all_in_one_line);

	ImGui::SetCursorPos(ImVec2(g_core()->w_width - 90, g_core()->w_high - 30));
	if (ImGui::Button("$", ImVec2{ 20,20 })) g_core()->is_key_hidden = !g_core()->is_key_hidden;
}

void Interface2()
{
	ImVec2 button_size(70, 20);
	const int buttons_per_row = 2;
	float button_width = button_size.x * buttons_per_row + 10 * (buttons_per_row - 1);
	float start_x = (g_core()->w_width - button_width) / 2;
	float start_y = 30.0f;

	ImGui::SetCursorPos(ImVec2(start_x, start_y));
	if (ImGui::Button("encrypt", button_size)) g_funcs()->file_enc_dec(1);

	ImGui::SetCursorPos(ImVec2(start_x + button_size.x + 10, start_y));
	if (ImGui::Button("decrypt", button_size)) g_funcs()->file_enc_dec(0); ImGui::SameLine(); HelpMarker("To enc/dec - select file");

	start_y += button_size.y + 10;

	ImGui::SetCursorPos(ImVec2(start_x, start_y));
	if (ImGui::Button("pick-file", button_size)) g_funcs()->pick_file(g_core()->file_path);

	ImGui::SetCursorPos(ImVec2(start_x + button_size.x + 10, start_y));
	if (ImGui::Button("pick-dir", button_size)) g_funcs()->pick_dir(g_core()->dir_path);

	start_y += button_size.y + 10;

	ImGui::SetCursorPos(ImVec2(start_x, start_y));
	if (ImGui::Button("split", button_size)) g_funcs()->split_file();

	ImGui::SetCursorPos(ImVec2(start_x + button_size.x + 10, start_y));
	if (ImGui::Button("merge", button_size)) g_funcs()->merge_file(); ImGui::SameLine(); HelpMarker("To split - select file\nTo merge - select dir");

	start_y += button_size.y + 10;

	ImGui::PushItemWidth(150);
	ImGui::SetCursorPos({ (float)((g_core()->w_width - 150) / 2), start_y });
	ImGui::SliderInt("##k45fwdd", &g_core()->split_num, 2, 255); ImGui::SameLine(); HelpMarker("Amount of parts to split");
	ImGui::PopItemWidth();
}

void Interface3()
{
	ImVec2 pos(10, 30);
	ImVec2 itm_size((float)(g_core()->w_width - 20), (float)(g_core()->w_high - 130));

	ImGui::SetCursorPos(pos);
	ImGui::InputTextMultiline("##34fgd", g_core()->ps_out_buf, IM_ARRAYSIZE(g_core()->ps_out_buf), itm_size, ImGuiInputTextFlags_ReadOnly);

	pos.y = (float)(g_core()->w_high - 60);
	ImGui::SetCursorPos(pos);
	ImGui::PushItemWidth(150);
	ImGui::InputText("##65fd2ee", g_core()->spec_buf, IM_ARRAYSIZE(g_core()->spec_buf));

	ImGui::SetCursorPos(ImVec2(170, (float)(g_core()->w_high - 60)));
	ImGui::Checkbox("symbs", &g_core()->spec_symbs);

	pos.y = (float)(g_core()->w_high - 90);
	ImGui::SetCursorPos(pos);
	ImGui::SliderInt("##k45fwdd", &g_core()->pass_size, 10, 64);
	ImGui::PopItemWidth();

	ImGui::SetCursorPos(ImVec2(170, (float)(g_core()->w_high - 90)));
	if (ImGui::Button("generate", { 70, 20 })) g_funcs()->random_pass();
}

void Interface4()
{
	ImVec2 item_size((float)(g_core()->w_width - 20), (float)(g_core()->w_high - 100));
	ImVec2 pos(10, 30);

	ImGui::SetCursorPos(pos);
	ImGui::InputTextMultiline("##ing2", g_core()->ll_in_buf, IM_ARRAYSIZE(g_core()->ll_in_buf), item_size);

	pos.y = (float)(g_core()->w_high - 60);
	ImGui::PushItemWidth(140);
	ImGui::SetCursorPos(pos);
	ImGui::Combo("##qhq34ds", &g_core()->ll_current_item, g_core()->ll_items, IM_ARRAYSIZE(g_core()->ll_items));

	pos.x = 160;
	pos.y = (float)(g_core()->w_high - 58);
	ImGui::SetCursorPos(pos);
	if (ImGui::Button("shuffle", { 60, 20 })) g_funcs()->shuffle();
}

void Core::main_core()
{
	ImGui::SetNextWindowPos({ 0, 0 }, ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize({ (float)g_core()->w_width, (float)g_core()->w_high});

	ImGuiStyle& style = ImGui::GetStyle();
	style.FrameBorderSize = 0.f;
	ImGui::Begin("qaxulorer", &g_core()->is_working, 256 | 32 | 4 | 2);
	style.FrameBorderSize = 1.f;

	ImGui::SetCursorPos(ImVec2(g_core()->w_width - 30, g_core()->w_high - 30));
	if (ImGui::Button("?", { 20,20 })) { g_core()->current_tab = (g_core()->current_tab % 4) + 1; }

	ImGui::SetCursorPos(ImVec2(g_core()->w_width - 60, g_core()->w_high - 30));
	if (ImGui::Button("&", ImVec2{ 20,20 }))  g_funcs()->clear_all();

	switch (g_core()->current_tab) 
	{
	case 1: { Interface1(); break; }
	case 2: { Interface2(); break; }
	case 3: { Interface3(); break; }
	case 4: { Interface4(); break; }
	}

	ImGui::End();
}