#include "include.h"
#include <Shobjidl.h>
#include <comdef.h>
#include <filesystem>

std::string w2s(const std::wstring& wstr)
{
	if (wstr.empty()) return std::string();
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), 0, 0, 0, 0);
	std::string str(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, 0, 0);
	return str;
}

std::wstring s2w(const std::string& str)
{
	if (str.empty()) return std::wstring();
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), 0, 0);
	std::wstring wstr(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
	return wstr;
}

void shuffle_utf8(std::string& str, std::mt19937& rng)
{
	std::wstring wstr = s2w(str);
	std::vector<std::wstring::value_type> utf8_chars(wstr.begin(), wstr.end());
	std::shuffle(utf8_chars.begin(), utf8_chars.end(), rng);
	wstr.assign(utf8_chars.begin(), utf8_chars.end());
	str = w2s(wstr);
}

std::wstring rstr_w(size_t length)
{
	const std::wstring charset = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::wstring result;

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dist(0, charset.size() - 1);

	for (size_t i = 0; i < length; ++i)
	{
		result += charset[dist(gen)];
	}

	return result;
}

std::vector<uint8_t> process_multiline_data(const std::vector<uint8_t>& data, int mod, bool is_encrypt, const std::array<uint8_t, 32>& key = {})
{
	std::string data_str(data.begin(), data.end());

	std::vector<std::string> input_lines;
	std::string current_line;
	for (char c : data_str)
	{
		if (c == '\n')
		{
			if (!current_line.empty())
			{
				input_lines.push_back(current_line);
				current_line.clear();
			}
		}
		else
		{
			current_line.push_back(c);
		}
	}
	if (!current_line.empty()) {
		input_lines.push_back(current_line);
	}

	std::vector<std::string> processed_lines;

	auto process_line = [&](const std::string& line)
		{
			std::vector<uint8_t> line_bytes(line.begin(), line.end());
			std::vector<uint8_t> processed;

			if (mod == 0)
			{
				if (is_encrypt)
				{
					if (g_cryptor()->encrypt_bin(line_bytes, key, processed))
					{
						processed = g_cryptor()->b64_enc(processed);
					}
				}
				else
				{
					processed = g_cryptor()->b64_dec(line_bytes);
					g_cryptor()->decrypt_bin(processed, key, processed);
				}
			}
			else
			{
				processed = is_encrypt
					? g_cryptor()->b64_enc(line_bytes)
					: g_cryptor()->b64_dec(line_bytes);
			}

			std::string processed_str(processed.begin(), processed.end());

			if (!is_encrypt && processed_str.find('\n') != std::string::npos)
			{
				processed_lines.push_back("/*" + processed_str + "*/\n");
			}
			else
			{
				processed_lines.push_back(processed_str + "\n");
			}
		};

	for (const auto& line : input_lines)
	{
		process_line(line);
	}

	std::vector<uint8_t> result;
	for (const auto& line : processed_lines)
	{
		result.insert(result.end(), line.begin(), line.end());
	}

	if (!result.empty()) result.pop_back();

	return result;
}

void Funcs::clear_all()
{
	memset(g_core()->ed_in_buf, 0, sizeof(g_core()->ed_in_buf));
	memset(g_core()->ed_out_buf, 0, sizeof(g_core()->ed_out_buf));
	memset(g_core()->ps_out_buf, 0, sizeof(g_core()->ps_out_buf));
	memset(g_core()->ll_in_buf, 0, sizeof(g_core()->ll_in_buf));

	g_core()->file_path.clear();
	g_core()->dir_path.clear();
}

void Funcs::str_enc_dec(bool is_encrypt)
{
	try
	{
		std::string key(g_core()->ed_key_buf);
		std::string input_str(g_core()->ed_in_buf);
		std::vector<uint8_t> input_data(input_str.begin(), input_str.end());
		if (input_data.empty()) return;

		std::vector<uint8_t> output_data;
		std::array<uint8_t, 32>  key_hash = (g_core()->ed_current_item == 0 && !key.empty())
			? g_cryptor()->sha256(key)
			: std::array<uint8_t, 32>();

		int mode = g_core()->ed_current_item;
		bool single_line = g_core()->all_in_one_line;

		if (mode == 0)
		{
			if (single_line)
			{
				if (is_encrypt)
				{
					if (g_cryptor()->encrypt_bin(input_data, key_hash, output_data))
					{
						output_data = g_cryptor()->b64_enc(output_data);
					}
				}
				else
				{
					output_data = g_cryptor()->b64_dec(input_data);
					g_cryptor()->decrypt_bin(output_data, key_hash, output_data);
				}
			}
			else
			{
				output_data = process_multiline_data(input_data, 0, is_encrypt, key_hash);
			}
		}
		else if (mode == 1)
		{
			if (single_line)
			{
				output_data = is_encrypt
					? g_cryptor()->b64_enc(input_data)
					: g_cryptor()->b64_dec(input_data);
			}
			else
			{
				output_data = process_multiline_data(input_data, 1, is_encrypt);
			}
		}

		memset(g_core()->ed_out_buf, 0, sizeof(g_core()->ed_out_buf));
		if (!output_data.empty() && output_data.size() <= sizeof(g_core()->ed_out_buf))
		{
			memcpy(g_core()->ed_out_buf, output_data.data(), output_data.size());
		}
	}
	catch (...) {}
}

void Funcs::file_enc_dec(bool is_encrypt)
{
	try
	{
		std::string key(g_core()->ed_key_buf);
		if (key.empty() || !std::filesystem::exists(g_core()->file_path)) return;

		std::array<uint8_t, 32>  key_hash = g_cryptor()->sha256(key);
		std::filesystem::path original_path = g_core()->file_path;
		std::filesystem::path output_path = original_path.parent_path() / (is_encrypt ? L"enc_" : L"dec_");
		output_path += rstr_w(5);

		if (is_encrypt)
			g_cryptor()->encrypt_file(original_path, output_path.wstring(), key_hash);
		else
			g_cryptor()->decrypt_file(original_path, output_path.wstring(), key_hash);
	}
	catch (...) {}
}

void Funcs::shuffle()
{
	try
	{
		std::vector<std::string> words;
		std::istringstream iss(g_core()->ll_in_buf);
		std::string word;

		while (std::getline(iss, word, '\n'))
		{
			if (!word.empty())
				words.push_back(word);
		}

		if (words.empty()) return;

		std::random_device rd;
		std::mt19937 rng(rd());

		switch (g_core()->ll_current_item)
		{
		case 0:
			for (int i = 0; i < 30; ++i)
				std::shuffle(words.begin(), words.end(), rng);
			break;

		case 1:
			std::sort(words.begin(), words.end(),
				[](const std::string& a, const std::string& b) {
					return a.length() < b.length();
				});
			break;

		case 2:
			for (auto& w : words) shuffle_utf8(w, rng);
			break;
		}

		std::ostringstream oss;
		for (const auto& w : words)
			oss << w << '\n';

		std::string output = oss.str();
		if (!output.empty())
			output.pop_back();

		memset(g_core()->ll_in_buf, 0, sizeof(g_core()->ll_in_buf));
		if (output.size() <= sizeof(g_core()->ll_in_buf))
			memcpy(g_core()->ll_in_buf, output.data(), output.size());
	}
	catch (...) {}
}

void Funcs::random_pass()
{
	static constexpr char char_set_base[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

	std::string char_set(char_set_base);

	if (g_core()->spec_symbs)
	{
		char_set.append(g_core()->spec_buf);
	}

	const size_t pass_len = g_core()->pass_size;
	const size_t lines = 10;
	const size_t total_size = (pass_len + 1) * lines;

	std::string rnd_pass;
	rnd_pass.reserve(total_size);

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dist(0, static_cast<int>(char_set.size()) - 1);

	for (size_t line = 0; line < lines; ++line)
	{
		for (size_t i = 0; i < pass_len; ++i)
			rnd_pass += char_set[dist(gen)];
		rnd_pass += '\n';
	}

	if (!rnd_pass.empty())
	{
		rnd_pass.pop_back();
	}

	if (rnd_pass.size() <= sizeof(g_core()->ps_out_buf)) {
		memcpy(g_core()->ps_out_buf, rnd_pass.data(), rnd_pass.size());
	}
}

void Funcs::pick_dir(std::wstring& fp)
{
	if (SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)))
	{
		IFileOpenDialog* pFolderDlg = nullptr;
		if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL,
			IID_IFileOpenDialog, reinterpret_cast<void**>(&pFolderDlg))))
		{
			FILEOPENDIALOGOPTIONS options = {};
			if (SUCCEEDED(pFolderDlg->GetOptions(&options)))
			{
				pFolderDlg->SetOptions(options | FOS_PICKFOLDERS | FOS_PATHMUSTEXIST | FOS_FORCEFILESYSTEM);

				if (SUCCEEDED(pFolderDlg->Show(NULL)))
				{
					IShellItem* pItem = nullptr;
					if (SUCCEEDED(pFolderDlg->GetResult(&pItem)))
					{
						LPWSTR pszFilePath = nullptr;
						if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath)) && pszFilePath)
						{
							fp = pszFilePath;
							CoTaskMemFree(pszFilePath);
						}
						pItem->Release();
					}
				}
			}
			pFolderDlg->Release();
		}
		CoUninitialize();
	}
}

void Funcs::pick_file(std::wstring& fp)
{
	WCHAR pszFilePath[512]{ 0 };
	OPENFILENAMEW ofn{ 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = pszFilePath;
	ofn.nMaxFile = 512;
	ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
	GetOpenFileNameW(&ofn);
	fp = pszFilePath;
}

void Funcs::merge_file()
{
	struct FileData
	{
		unsigned char index;
		std::filesystem::path path;
		bool operator<(const FileData& other) const noexcept
		{
			return index < other.index;
		}
	};

	const auto& core_path = g_core()->dir_path;
	if (!std::filesystem::exists(core_path)) return;

	const auto parent_path = std::filesystem::path(core_path).parent_path();
	const std::wstring outfile = parent_path.wstring() + L"\\" + rstr_w(3) + L"_merged";

	constexpr size_t header_size = 4;
	char header[header_size];

	std::vector<FileData> files;
	files.reserve(64);

	for (const auto& entry : std::filesystem::directory_iterator(core_path))
	{
		if (!entry.is_regular_file()) continue;

		std::ifstream ifile(entry.path(), std::ios::binary);
		if (!ifile.read(header, header_size)) continue;

		if (header[0] == 'G' && header[1] == 'F' && header[2] == 'M')
		{
			files.push_back({ static_cast<unsigned char>(header[3]), entry.path() });
		}
	}

	if (files.size() < 2) return;
	std::sort(files.begin(), files.end());

	std::ofstream ofile(outfile, std::ios::binary);
	if (!ofile) return;

	std::vector<char> buffer;
	buffer.reserve(1024 * 1024 * 4);

	for (const auto& file_data : files)
	{
		std::ifstream ifile(file_data.path, std::ios::binary);
		if (!ifile) continue;

		const auto file_size = std::filesystem::file_size(file_data.path);
		const auto data_size = static_cast<std::streamsize>(file_size - header_size);

		ifile.seekg(header_size, std::ios::beg);
		buffer.resize(static_cast<size_t>(data_size));

		if (!ifile.read(buffer.data(), data_size)) continue;
		ofile.write(buffer.data(), data_size);
	}
}

void Funcs::split_file()
{
	const auto& file_path = g_core()->file_path;
	if (!std::filesystem::exists(file_path)) return;

	const auto base_path = file_path.substr(0, file_path.find_last_of(L'\\'));
	const std::wstring split_dir = base_path + L"\\" + rstr_w(5);

	std::ifstream ifile(file_path, std::ios::binary | std::ios::ate);
	if (!ifile) return;

	const size_t file_size = static_cast<size_t>(ifile.tellg());
	ifile.seekg(0, std::ios::beg);

	if (std::filesystem::exists(split_dir)) {
		std::filesystem::remove_all(split_dir);
	}
	std::filesystem::create_directory(split_dir);

	constexpr size_t chunk_size = 4 * 1024 * 1024;
	const size_t num_parts = g_core()->split_num;
	const size_t part_size_base = file_size / num_parts;

	char header[4] = { 'G', 'F', 'M', 0 };

	std::vector<char> buffer;
	buffer.reserve(chunk_size);

	for (size_t i = 0; i < num_parts; ++i)
	{
		const size_t part_size = (i == num_parts - 1)
			? part_size_base + file_size % num_parts
			: part_size_base;

		const std::wstring part_path = split_dir + L"\\" + rstr_w(5);
		std::ofstream ofile(part_path, std::ios::binary);
		if (!ofile) return;

		header[3] = static_cast<char>(i);
		ofile.write(header, sizeof(header));

		size_t remaining = part_size;
		while (remaining > 0)
		{
			const size_t read_size = std::min(chunk_size, remaining);
			buffer.resize(read_size);
			if (!ifile.read(buffer.data(), read_size)) break;
			ofile.write(buffer.data(), read_size);
			remaining -= read_size;
		}
	}

	ifile.close();
}
