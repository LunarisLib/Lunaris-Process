#pragma once

#ifdef _WIN32

#include <Windows.h>

#else // assuming linux

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#define PIPE_READ 0
#define PIPE_WRITE 1

#endif

#include <thread>
#include <mutex>
#include <string>
#include <functional>
#include <initializer_list>

namespace Lunaris {

	/// <summary>
	/// <para>This is a syncronous (read/write) process task manager.</para>
	/// <para>Run apps with arguments on Windows and Linux easily. Same format, same power.</para>
	/// </summary>
	class process_sync {
	public:
		enum class mode { READ, WRITE, READWRITE };
	private:
		const mode m_mode = mode::READWRITE;

		/* - - - - - - - - - - WIN32 - - - - - - - - - - */
#ifdef _WIN32
		HANDLE m_hChildStd_IN_Wr = nullptr;
		HANDLE m_hChildStd_OUT_Rd = nullptr;

		SECURITY_ATTRIBUTES m_saAttr{};
		PROCESS_INFORMATION m_piProcInfo{};

#ifdef UNICODE
		STARTUPINFOA m_siStartInfo{};
#else
		STARTUPINFO m_siStartInfo{};
#endif
		/* - - - - - - - - - - ENDOF WIN32 - - - - - - - - - - */
#else
	/* - - - - - - - - - - LINUX - - - - - - - - - - */
		int aStdinPipe[2]{};
		int aStdoutPipe[2]{};
		pid_t m_nChildID = 0;
		/* - - - - - - - - - - ENDOF LINUX - - - - - - - - - - */
#endif
		bool read_flag() const;
		bool write_flag() const;
		void _i_open(const std::string&, const std::initializer_list<std::string>&);
	public:
		/// <summary>
		/// <para>Start process by name.</para>
		/// </summary>
		/// <param name="{std::string}">App path or relative path.</param>
		/// <param name="{mode}">IO mode.</param>
		process_sync(const std::string&, const mode);

		/// <summary>
		/// <para>Start process by name with arguments.</para>
		/// </summary>
		/// <param name="{std::string}">App path or relative path.</param>
		/// <param name="{std::initializer_list}">List of arguments.</param>
		/// <param name="{mode}">IO mode.</param>
		process_sync(const std::string&, const std::initializer_list<std::string>&, const mode);
        
        process_sync(const process_sync&) = delete;
        process_sync(process_sync&&) = delete;
        void operator=(const process_sync&) = delete;
        void operator=(process_sync&&) = delete;

		// dies
		~process_sync();

		/// <summary>
		/// <para>Stop and close handles.</para>
		/// </summary>
		void stop();

		/// <summary>
		/// <para>If writable, attempt to push command to stdin of process.</para>
		/// </summary>
		/// <param name="{std::string}">Command or text to send.</param>
		/// <param name="{bool}">Automatically add breakline after the string? (this is just a useful thing, but if you don't like that, you can disable it).</param>
		/// <returns>{bool} False if any error, else true.</returns>
		bool write(std::string, const bool = true);

		/// <summary>
		/// <para>Attempt to read process stdout (one line).</para>
		/// </summary>
		/// <returns>{std::string} Empty string if error, else string.</returns>
		std::string read();

		/// <summary>
		/// <para>Check if there's buffer to read on process stdout.</para>
		/// </summary>
		/// <returns>{bool} True if there's something to read.</returns>
		bool has_read() const;

		/// <summary>
		/// <para>Check if you started with read flag.</para>
		/// </summary>
		/// <returns>{bool} True if read flag is enabled.</returns>
		bool can_read() const;

		/// <summary>
		/// <para>Check if you started with write flag.</para>
		/// </summary>
		/// <returns>{bool} True if write flag is enabled.</returns>
		bool can_write() const;

		/// <summary>
		/// <para>Is the process running?</para>
		/// <para>NOTE: stdout buffer may still have something to read if the process quit before you read(). Check can_read() for that.</para>
		/// </summary>
		/// <returns>{bool} True if running.</returns>
		bool is_running() const;

		/// <summary>
		/// <para>It is considered valid if:</para>
		/// <para>1. Process is running;</para>
		/// <para>2. Pipes are set and good.</para>
		/// </summary>
		/// <returns>{bool} True if valid.</returns>
		bool valid() const;

		/// <summary>
		/// <para>It is considered empty if it's not valid.</para>
		/// </summary>
		/// <returns>{bool} Is it NOT valid?</returns>
		bool empty() const;
	};

}

#include "process.ipp"