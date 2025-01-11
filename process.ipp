#pragma once
#include "process.h"

namespace Lunaris {

	inline bool process_sync::read_flag() const
	{
		return m_mode != mode::WRITE; // READ || READWRITE
	}

	inline bool process_sync::write_flag() const
	{
		return m_mode != mode::READ; // WRITE || READWRITE
	}

	inline void process_sync::_i_open(const std::string& call, const std::vector<std::string>& args)
	{
#ifdef _WIN32
		m_saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		m_saAttr.bInheritHandle = true;
		m_saAttr.lpSecurityDescriptor = nullptr;

		HANDLE hChildStd_IN_Rd = nullptr;  // this is deletable after startup apparently
		HANDLE hChildStd_OUT_Wr = nullptr; // this is deletable after startup apparently

		const auto easy_cleanup = [&] {
			if (hChildStd_IN_Rd != nullptr) {
				CloseHandle(hChildStd_IN_Rd);
				hChildStd_IN_Rd = nullptr;
			}
			if (m_hChildStd_IN_Wr != nullptr) {
				CloseHandle(m_hChildStd_IN_Wr);
				m_hChildStd_IN_Wr = nullptr;
			}
			if (m_hChildStd_OUT_Rd != nullptr) {
				CloseHandle(m_hChildStd_OUT_Rd);
				m_hChildStd_OUT_Rd = nullptr;
			}
			if (hChildStd_OUT_Wr != nullptr) {
				CloseHandle(hChildStd_OUT_Wr);
				hChildStd_OUT_Wr = nullptr;
			}
		};

		if (read_flag()) { // only start read pipes if read_flag()

			if (!CreatePipe(&m_hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &m_saAttr, 0)) {
				easy_cleanup();
				throw std::runtime_error("Could not create pipe for STDOUT of child process!");
			}
			if (!SetHandleInformation(m_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
				easy_cleanup();
				throw std::runtime_error("Could not set up pipe for STDOUT of child process!");
			}
		}

		if (write_flag()) { // only start write pipes if write_flag()
			if (!CreatePipe(&hChildStd_IN_Rd, &m_hChildStd_IN_Wr, &m_saAttr, 0)) {
				easy_cleanup();
				throw std::runtime_error("Could not create pipe for STDIN of child process!");
			}
			if (!SetHandleInformation(m_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
				easy_cleanup();
				throw std::runtime_error("Could not set up pipe for STDIN of child process!");
			}
		}

		ZeroMemory(&m_piProcInfo, sizeof(PROCESS_INFORMATION));
#ifdef UNICODE
		ZeroMemory(&m_siStartInfo, sizeof(STARTUPINFOA));
#else
		ZeroMemory(&m_siStartInfo, sizeof(STARTUPINFO));
#endif

		m_siStartInfo.cb = sizeof(m_siStartInfo);
		if (read_flag()) {
			m_siStartInfo.hStdError = hChildStd_OUT_Wr;
			m_siStartInfo.hStdOutput = hChildStd_OUT_Wr;
		}
		if (write_flag()) {
			m_siStartInfo.hStdInput = hChildStd_IN_Rd;
		}
		m_siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

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
			&m_siStartInfo,							// STARTUPINFO pointer 
			&m_piProcInfo)							// receives PROCESS_INFORMATION
			) {
			easy_cleanup();
			throw std::runtime_error("Could not launch process!");
		}

		CloseHandle(m_piProcInfo.hThread);
		m_piProcInfo.hThread = nullptr;

		CloseHandle(hChildStd_OUT_Wr);
		CloseHandle(hChildStd_IN_Rd);
#else // assume linux

		if (read_flag()) {
			if (pipe(aStdinPipe) < 0) {
				throw std::runtime_error("Could not create stdin pipe of child process!");
			}
		}
		if (write_flag()) {
			if (pipe(aStdoutPipe) < 0) {
				close(aStdinPipe[PIPE_READ]);
				close(aStdinPipe[PIPE_WRITE]);
				throw std::runtime_error("Could not create stdout pipe of child process!");
			}
		}

		pid_t forkid = fork();
		if (forkid == 0) { // child

			if (aStdinPipe[PIPE_READ] != 0 && dup2(aStdinPipe[PIPE_READ], STDIN_FILENO) == -1) {
				exit(errno);
			}

			if (aStdoutPipe[PIPE_WRITE] != 0 && dup2(aStdoutPipe[PIPE_WRITE], STDOUT_FILENO) == -1) {
				exit(errno);
			}

			if (aStdoutPipe[PIPE_WRITE] != 0 && dup2(aStdoutPipe[PIPE_WRITE], STDERR_FILENO) == -1) {
				exit(errno);
			}

			// all these are for use by parent only
			if (aStdinPipe[PIPE_READ] != 0) close(aStdinPipe[PIPE_READ]);
			if (aStdinPipe[PIPE_WRITE] != 0) close(aStdinPipe[PIPE_WRITE]);
			if (aStdoutPipe[PIPE_READ] != 0) close(aStdoutPipe[PIPE_READ]);
			if (aStdoutPipe[PIPE_WRITE] != 0) close(aStdoutPipe[PIPE_WRITE]);
			aStdinPipe[PIPE_READ] = 0;
			aStdinPipe[PIPE_WRITE] = 0;
			aStdoutPipe[PIPE_READ] = 0;
			aStdoutPipe[PIPE_WRITE] = 0;

			std::vector<char*> adptargs;
			//adptargs.push_back((char*)call.c_str());
			for (const auto& it : args) adptargs.push_back((char*)it.c_str());
			adptargs.push_back((char*)nullptr);

			int nResult = execvp(call.c_str(), adptargs.data());

			exit(nResult);
		}
		else {
			if (forkid <= 0) { // failed
				if (aStdinPipe[PIPE_READ] != 0) close(aStdinPipe[PIPE_READ]);
				if (aStdinPipe[PIPE_WRITE] != 0) close(aStdinPipe[PIPE_WRITE]);
				if (aStdoutPipe[PIPE_READ] != 0) close(aStdoutPipe[PIPE_READ]);
				if (aStdoutPipe[PIPE_WRITE] != 0) close(aStdoutPipe[PIPE_WRITE]);
				aStdinPipe[PIPE_READ] = 0;
				aStdinPipe[PIPE_WRITE] = 0;
				aStdoutPipe[PIPE_READ] = 0;
				aStdoutPipe[PIPE_WRITE] = 0;
				throw std::runtime_error("Could not start child process!");
			}
			m_nChildID = forkid;

			if (aStdinPipe[PIPE_READ] != 0) close(aStdinPipe[PIPE_READ]);
			if (aStdoutPipe[PIPE_WRITE] != 0) close(aStdoutPipe[PIPE_WRITE]);
			aStdinPipe[PIPE_READ] = 0;
			aStdoutPipe[PIPE_WRITE] = 0;
		}
#endif // WIN32
	}
	
	inline process_sync::process_sync(const std::string& call, const mode m)
		: m_mode(m)
	{
		_i_open(call, {});
	}

	inline process_sync::process_sync(const std::string& call, const std::initializer_list<std::string>& aas, const mode m)
		: m_mode(m)
	{
		_i_open(call, aas);
	}

	inline process_sync::process_sync(const std::string& call, const std::vector<std::string>& aas, const mode m)
		: m_mode(m)
	{
		_i_open(call, aas);
	}

	inline process_sync::~process_sync()
	{
		stop();
	}

	inline void process_sync::stop()
	{
#ifdef _WIN32
		if (m_piProcInfo.hProcess != nullptr) {
			TerminateProcess(m_piProcInfo.hProcess, 0);
			CloseHandle(m_piProcInfo.hProcess);
			m_piProcInfo.hProcess = nullptr;
		}
		if (m_hChildStd_IN_Wr != nullptr) {
			CloseHandle(m_hChildStd_IN_Wr);
			m_hChildStd_IN_Wr = nullptr;
		}
		if (m_hChildStd_OUT_Rd != nullptr) {
			CloseHandle(m_hChildStd_OUT_Rd);
			m_hChildStd_OUT_Rd = nullptr;
		}
#else // assuming linux
		if (m_nChildID != 0) {
			kill(m_nChildID, SIGTERM);
			m_nChildID = 0;
		}
		if (aStdinPipe[PIPE_READ] != 0) {
			close(aStdinPipe[PIPE_READ]);
			aStdinPipe[PIPE_READ] = 0;
		}
		if (aStdinPipe[PIPE_WRITE] != 0) {
			close(aStdinPipe[PIPE_WRITE]);
			aStdinPipe[PIPE_WRITE] = 0;
		}
		if (aStdoutPipe[PIPE_READ] != 0) {
			close(aStdoutPipe[PIPE_READ]);
			aStdoutPipe[PIPE_READ] = 0;
		}
		if (aStdoutPipe[PIPE_WRITE] != 0) {
			close(aStdoutPipe[PIPE_WRITE]);
			aStdoutPipe[PIPE_WRITE] = 0;
		}
#endif
	}

	inline bool process_sync::write(std::string s, const bool addline)
	{
		if (addline) s += '\n';
#ifdef _WIN32
		if (!m_hChildStd_IN_Wr || !write_flag() || s.empty()) return false;

		DWORD dwWrite{};
		return WriteFile(m_hChildStd_IN_Wr, s.c_str(), static_cast<DWORD>(s.size()), &dwWrite, nullptr);
#else // assume Linux
		if (aStdinPipe[PIPE_WRITE] == 0 || !write_flag() || s.empty()) return false;

		return ::write(aStdinPipe[PIPE_WRITE], s.data(), s.size()) > 0;
#endif
	}

	inline std::string process_sync::read()
	{
#ifdef _WIN32
		if (!m_hChildStd_OUT_Rd || !read_flag()) return "";
#else // assume Linux
		if (aStdoutPipe[PIPE_READ] == 0 || !read_flag()) return "";
#endif
		std::string buf;

		while (1) {

			char ch{};
#ifdef _WIN32
			DWORD got = 0;

			if (!ReadFile(m_hChildStd_OUT_Rd, &ch, sizeof(char), &got, nullptr) || got == 0) {
				if (!is_running()) {
					std::this_thread::sleep_for(std::chrono::milliseconds(20));
					return buf;
				}
				continue;
			}
#else // assume Linux
			if (::read(aStdoutPipe[PIPE_READ], &ch, sizeof(char)) == 0) {
				if (!is_running()) {
					std::this_thread::sleep_for(std::chrono::milliseconds(20));
					return buf;
				}
				continue;
			}
#endif

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

	inline bool process_sync::has_read() const
	{
#ifdef _WIN32
		DWORD dwAvail = 0;
		return ((m_mode != mode::WRITE) && ::PeekNamedPipe(m_hChildStd_OUT_Rd, nullptr, 0, nullptr, &dwAvail, nullptr) && dwAvail);
#else // Linux
		pollfd fd;
		fd.fd = aStdoutPipe[PIPE_READ];
		fd.events = POLLIN;
		fd.revents = 0;
		int retpoll = poll(&fd, 1, 10);
		if (retpoll <= 0) return false;

		switch (fd.revents) {
		case POLLERR:
		case POLLHUP:
		case POLLNVAL:
			return false;
		default:
			return fd.revents != 0;
		}
#endif
	}

	inline bool process_sync::can_read() const
	{
		return read_flag();
	}

	inline bool process_sync::can_write() const
	{
		return write_flag(); // WRITE || READWRITE
	}

	inline bool process_sync::is_running() const
	{
#ifdef _WIN32
		DWORD code{};
		GetExitCodeProcess(m_piProcInfo.hProcess, &code);
		return code == STILL_ACTIVE;
#else // assume Linux
		if (m_nChildID == 0) return false; // no child
		int status{};
		pid_t res = waitpid(m_nChildID, &status, WNOHANG); // 0 = active, -1 = error, else exited // (W NO HANG)
		return res == 0 || res == m_nChildID;
#endif
	}

	inline bool process_sync::valid() const
	{
#ifdef _WIN32
		return is_running() && m_hChildStd_IN_Wr != 0 && m_hChildStd_OUT_Rd != 0;
#else // Linux
		return is_running() && aStdoutPipe[PIPE_READ] != 0 && aStdinPipe[PIPE_WRITE] != 0;
#endif
	}

	inline bool process_sync::empty() const
	{
		return !valid();
	}

	inline void process_async::run_async()
	{
		while (m_keep_running) {
			if (!m_proc) {
				m_keep_running = false;
				return;
			}
			if (!m_proc->is_running() && !m_proc->has_read()) {
				m_keep_running = false;
				return;
			}

			if (!m_proc->has_read()) {
				std::this_thread::sleep_for(std::chrono::milliseconds(20));
				continue;
			}

			std::string str = m_proc->read();

			if (!str.empty()) {
				std::lock_guard<std::mutex> luck(m_saf);
				m_autohandle(*m_proc, str);
			}
		}
	}

	inline process_async::process_async(const std::string& call, std::function<void(process_sync&, const std::string&)> f)
		: m_autohandle(f)
	{
		if (!f) throw std::invalid_argument("Invalid function!");

		m_proc = std::unique_ptr<process_sync>(new process_sync(call, process_sync::mode::READWRITE));
		m_keep_running = true;
		m_autoout = std::thread([this] { run_async(); });
	}

	inline process_async::process_async(const std::string& call, const std::initializer_list<std::string>& lst, std::function<void(process_sync&, const std::string&)> f)
		: m_autohandle(f)
	{
		if (!f) throw std::invalid_argument("Invalid function!");

		m_proc = std::unique_ptr<process_sync>(new process_sync(call, lst, process_sync::mode::READWRITE));
		m_keep_running = true;
		m_autoout = std::thread([this] { run_async(); });
	}

	inline process_async::process_async(const std::string& call, const std::vector<std::string>& lst, std::function<void(process_sync&, const std::string&)> f)
		: m_autohandle(f)
	{
		if (!f) throw std::invalid_argument("Invalid function!");

		m_proc = std::unique_ptr<process_sync>(new process_sync(call, lst, process_sync::mode::READWRITE));
		m_keep_running = true;
		m_autoout = std::thread([this] { run_async(); });
	}

	inline process_async::~process_async()
	{
		stop();
	}

	inline bool process_async::reset(const std::string& call, std::function<void(process_sync&, const std::string&)> f)
	{
		if (!f) return false;

		stop();

		m_proc = std::unique_ptr<process_sync>(new process_sync(call, process_sync::mode::READWRITE));
		m_keep_running = true;
		m_autohandle = f;
		m_autoout = std::thread([this] { run_async(); });

		return true;
	}

	inline bool process_async::reset(const std::string& call, const std::initializer_list<std::string>& lst, std::function<void(process_sync&, const std::string&)> f)
	{
		if (!f) return false;

		stop();

		m_proc = std::unique_ptr<process_sync>(new process_sync(call, lst, process_sync::mode::READWRITE));
		m_keep_running = true;
		m_autohandle = f;
		m_autoout = std::thread([this] { run_async(); });

		return true;
	}

	inline bool process_async::reset(const std::string& call, const std::vector<std::string>& lst, std::function<void(process_sync&, const std::string&)> f)
	{
		if (!f) return false;

		stop();

		m_proc = std::unique_ptr<process_sync>(new process_sync(call, lst, process_sync::mode::READWRITE));
		m_keep_running = true;
		m_autohandle = f;
		m_autoout = std::thread([this] { run_async(); });

		return true;
	}

	inline bool process_async::reset_hook(std::function<void(process_sync&, const std::string&)> f)
	{
		if (!f) return false;
		std::lock_guard<std::mutex> luck(m_saf);
		m_autohandle = f;
		return true;
	}

	inline bool process_async::write(std::string s, const bool b)
	{
		std::lock_guard<std::mutex> luck(m_saf); // safe writing
		if (!m_proc || !m_proc->can_write()) return false;
		return m_proc->write(std::move(s), b);
	}

	inline void process_async::stop()
	{
		m_keep_running = false;
		if (m_proc) m_proc->stop();
		if (m_autoout.joinable()) m_autoout.join();
        m_proc.reset();
	}

	inline bool process_async::is_running() const
	{
		return m_keep_running || (m_proc && m_proc->is_running());
	}

	inline bool process_async::valid() const
	{
		return m_proc && m_proc->valid() && m_autohandle;
	}

	inline bool process_async::empty() const
	{
		return !m_proc || (m_proc && m_proc->empty()) || !m_autohandle;
	}

}