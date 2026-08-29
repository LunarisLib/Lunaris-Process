#pragma once

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#endif

#include <cstdint>
#include <string>
#include <vector>

namespace Lunaris {
namespace Process {

#ifdef _WIN32
    struct process_data {
		HANDLE m_hChildStd_IN_Wr = nullptr;
		HANDLE m_hChildStd_OUT_Rd = nullptr;

		SECURITY_ATTRIBUTES m_saAttr{};
		PROCESS_INFORMATION m_piProcInfo{};

#ifdef UNICODE
		STARTUPINFOA m_siStartInfo{};
#else
		STARTUPINFO m_siStartInfo{};
#endif
    };
#else
    struct process_data {
        enum class e_pipe { READ = 0, WRITE = 1, _NUM_OPTS };

		int aStdinPipe [static_cast<size_t>(e_pipe::_NUM_OPTS)]{};
		int aStdoutPipe[static_cast<size_t>(e_pipe::_NUM_OPTS)]{};
		pid_t m_nChildID = 0;
    };
#endif

    enum class e_modes : uint8_t { 
        INVALID     = 0,
        READ        = 1 << 0,
        WRITE       = 1 << 1,
    };

    enum e_process_status {
        ACTIVE = 0,
        ERROR = -1,
        EXITED = 1
    };

    constexpr e_modes operator|(const e_modes& lhs, const e_modes& rhs) {
        using T = std::underlying_type_t<e_modes>;
        return static_cast<e_modes>(static_cast<T>(lhs) | static_cast<T>(rhs));
    }

    constexpr bool operator&(const e_modes& lhs, const e_modes& rhs) {
        using T = std::underlying_type_t<e_modes>;
        return (static_cast<T>(lhs) & static_cast<T>(rhs)) != 0;
    }

    namespace platform {
        process_data open(const std::string& call, const e_modes mode, const std::vector<std::string>& args);
        void close(process_data& data);

        bool write(const process_data& data, const std::string& str);
        std::string read(const process_data& data);

        bool has_read(const process_data& data);

        e_process_status get_state(const process_data& data);
    }

} // namespace Process
} // namespace Lunaris