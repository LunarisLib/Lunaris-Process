#include <Lunaris/Process/platform.h>
#include <Lunaris/Process/exception.h>

#include <thread>

namespace Lunaris {
namespace Process {
namespace platform{

    process_data open(const std::string& call, const e_modes mode, const std::vector<std::string>& args) {
        process_data pd;
        
		pd.m_saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		pd.m_saAttr.bInheritHandle = true;
		pd.m_saAttr.lpSecurityDescriptor = nullptr;

		HANDLE hChildStd_IN_Rd = nullptr;  // this is deletable after startup apparently
		HANDLE hChildStd_OUT_Wr = nullptr; // this is deletable after startup apparently

		const auto easy_cleanup = [&] {
			if (hChildStd_IN_Rd != nullptr) {
				CloseHandle(hChildStd_IN_Rd);
				hChildStd_IN_Rd = nullptr;
			}
			if (pd.m_hChildStd_IN_Wr != nullptr) {
				CloseHandle(pd.m_hChildStd_IN_Wr);
				pd.m_hChildStd_IN_Wr = nullptr;
			}
			if (pd.m_hChildStd_OUT_Rd != nullptr) {
				CloseHandle(pd.m_hChildStd_OUT_Rd);
				pd.m_hChildStd_OUT_Rd = nullptr;
			}
			if (hChildStd_OUT_Wr != nullptr) {
				CloseHandle(hChildStd_OUT_Wr);
				hChildStd_OUT_Wr = nullptr;
			}
		};

        if (mode & e_modes::READ) {
			if (!CreatePipe(&pd.m_hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &pd.m_saAttr, 0)) {
				easy_cleanup();
				throw ProcessException("Could not create pipe for STDOUT of child process!");
			}
			if (!SetHandleInformation(pd.m_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
				easy_cleanup();
				throw ProcessException("Could not set up pipe for STDOUT of child process!");
			}
		}

        if (mode & e_modes::WRITE) {
			if (!CreatePipe(&hChildStd_IN_Rd, &pd.m_hChildStd_IN_Wr, &pd.m_saAttr, 0)) {
				easy_cleanup();
				throw ProcessException("Could not create pipe for STDIN of child process!");
			}
			if (!SetHandleInformation(pd.m_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
				easy_cleanup();
				throw ProcessException("Could not set up pipe for STDIN of child process!");
			}
		}

		ZeroMemory(&pd.m_piProcInfo, sizeof(PROCESS_INFORMATION));
#ifdef UNICODE
		ZeroMemory(&pd.m_siStartInfo, sizeof(STARTUPINFOA));
#else
		ZeroMemory(&pd.m_siStartInfo, sizeof(STARTUPINFO));
#endif

		pd.m_siStartInfo.cb = sizeof(pd.m_siStartInfo);

        if (mode & e_modes::READ) {
			pd.m_siStartInfo.hStdError = hChildStd_OUT_Wr;
			pd.m_siStartInfo.hStdOutput = hChildStd_OUT_Wr;
		}
        if (mode & e_modes::WRITE) {
			pd.m_siStartInfo.hStdInput = hChildStd_IN_Rd;
		}
		pd.m_siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

		std::string gen_tags = call;
		for (const auto& it : args) {
			if (it.length() >= 2 && it.front() == '\"' && it.back() == '\"') {
				gen_tags += (" " + it);
			}
			else gen_tags += (" \"" + it + "\"");
		}

		if (!CreateProcessA(nullptr,
			const_cast<char*>(gen_tags.c_str()),	// command line 
			nullptr,								// process security attributes 
			nullptr,								// primary thread security attributes 
			true,									// handles are inherited 
			0,										// creation flags 
			nullptr,								// use parent's environment 
			nullptr,								// use parent's current directory 
			&pd.m_siStartInfo,						// STARTUPINFO pointer 
			&pd.m_piProcInfo)			    		// receives PROCESS_INFORMATION
			) {
			easy_cleanup();
			throw ProcessException("Could not launch process!");
		}

		CloseHandle(pd.m_piProcInfo.hThread);
		pd.m_piProcInfo.hThread = nullptr;

		CloseHandle(hChildStd_OUT_Wr);
		CloseHandle(hChildStd_IN_Rd);

		return pd;
    }
    
    void close(process_data& data) {
		if (data.m_piProcInfo.hProcess != nullptr) {
			TerminateProcess(data.m_piProcInfo.hProcess, 0);
			CloseHandle(data.m_piProcInfo.hProcess);
			data.m_piProcInfo.hProcess = nullptr;
		}
		if (data.m_hChildStd_IN_Wr != nullptr) {
			CloseHandle(data.m_hChildStd_IN_Wr);
			data.m_hChildStd_IN_Wr = nullptr;
		}
		if (data.m_hChildStd_OUT_Rd != nullptr) {
			CloseHandle(data.m_hChildStd_OUT_Rd);
			data.m_hChildStd_OUT_Rd = nullptr;
		}
    }
    
    bool write(const process_data& data, const std::string& str) {
		if (!data.m_hChildStd_IN_Wr || str.empty()) return false;

		DWORD dwWrite{};
		return WriteFile(data.m_hChildStd_IN_Wr, str.c_str(), static_cast<DWORD>(str.size()), &dwWrite, nullptr);
    }
    
    std::string read(const process_data& data) {
		if (!data.m_hChildStd_OUT_Rd) return {};

		std::string buf;
        char ch{};

		for (unsigned t = 0; t < 10;) {
			if (!has_read(data)) {
				++t;
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
				continue;
			}

			DWORD got = 0;

			if (!ReadFile(data.m_hChildStd_OUT_Rd, &ch, sizeof(char), &got, nullptr) || got == 0) {
				if (get_state(data) != e_process_status::P_ACTIVE) return buf;
                
				++t;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
				continue;
			}

			t = 0;
			
			switch (ch) {
			case '\r':
			case '\n':
				if (buf.size() > 0) return buf;
				break;
			default:
				buf += ch;
			}
        }

		return buf;
    }
    
    bool has_read(const process_data& data) {
		DWORD dwAvail = 0;
		return ::PeekNamedPipe(data.m_hChildStd_OUT_Rd, nullptr, 0, nullptr, &dwAvail, nullptr) && dwAvail != 0;
    }
    
    e_process_status get_state(const process_data& data) {
		DWORD code{};
		if (!GetExitCodeProcess(data.m_piProcInfo.hProcess, &code)) return e_process_status::P_ERROR;
		switch(code) {
        case STILL_ACTIVE: return e_process_status::P_ACTIVE;
        default: return code < 0xC0000000 ? e_process_status::P_EXITED : e_process_status::P_ERROR;
        }
    }
    

} // namespace platform
} // namespace Lunaris
} // namespace Process