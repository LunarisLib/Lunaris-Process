#include <Lunaris/Process/platform.h>
#include <Lunaris/Process/exception.h>

#include <thread>

namespace Lunaris {
namespace Process {
namespace platform{

    static constexpr size_t c_read = static_cast<size_t>(process_data::e_pipe::READ);
    static constexpr size_t c_write = static_cast<size_t>(process_data::e_pipe::WRITE);

    process_data open(const std::string& call, const e_modes mode, const std::vector<std::string>& args) {
        process_data pd;

        if (mode & e_modes::READ) {
            if (pipe(pd.aStdinPipe) < 0) {
                throw process_exception("Could not create stdin pipe of child process!");
            }
        }
        if (mode & e_modes::WRITE) {
			if (pipe(pd.aStdoutPipe) < 0) {
				::close(pd.aStdinPipe[c_read]);
				::close(pd.aStdinPipe[c_write]);
				throw process_exception("Could not create stdout pipe of child process!");
			}
        }

		pid_t forkid = fork();
		if (forkid == 0) { // child

			if (pd.aStdinPipe[c_read] != 0 && dup2(pd.aStdinPipe[c_read], STDIN_FILENO) == -1) {
				exit(errno);
			}

			if (pd.aStdoutPipe[c_write] != 0 && dup2(pd.aStdoutPipe[c_write], STDOUT_FILENO) == -1) {
				exit(errno);
			}

			if (pd.aStdoutPipe[c_write] != 0 && dup2(pd.aStdoutPipe[c_write], STDERR_FILENO) == -1) {
				exit(errno);
			}

			// all these are for use by parent only
			if (pd.aStdinPipe[c_read] != 0) ::close(pd.aStdinPipe[c_read]);
			if (pd.aStdinPipe[c_write] != 0) ::close(pd.aStdinPipe[c_write]);
			if (pd.aStdoutPipe[c_read] != 0) ::close(pd.aStdoutPipe[c_read]);
			if (pd.aStdoutPipe[c_write] != 0) ::close(pd.aStdoutPipe[c_write]);
			pd.aStdinPipe[c_read] = 0;
			pd.aStdinPipe[c_write] = 0;
			pd.aStdoutPipe[c_read] = 0;
			pd.aStdoutPipe[c_write] = 0;

            
			std::vector<char*> adptargs;
			adptargs.push_back((char*)call.c_str());
			for (const auto& it : args) adptargs.push_back((char*)it.c_str());
			adptargs.push_back((char*)nullptr);

			int nResult = execvp(call.c_str(), adptargs.data());

			exit(nResult);
		}
		else {
			if (forkid <= 0) { // failed
				if (pd.aStdinPipe[c_read] != 0) ::close(pd.aStdinPipe[c_read]);
				if (pd.aStdinPipe[c_write] != 0) ::close(pd.aStdinPipe[c_write]);
				if (pd.aStdoutPipe[c_read] != 0) ::close(pd.aStdoutPipe[c_read]);
				if (pd.aStdoutPipe[c_write] != 0) ::close(pd.aStdoutPipe[c_write]);
				pd.aStdinPipe[c_read] = 0;
				pd.aStdinPipe[c_write] = 0;
				pd.aStdoutPipe[c_read] = 0;
				pd.aStdoutPipe[c_write] = 0;
				throw process_exception("Could not start child process!");
			}
			pd.m_nChildID = forkid;

			if (pd.aStdinPipe[c_read] != 0) ::close(pd.aStdinPipe[c_read]);
			if (pd.aStdoutPipe[c_write] != 0) ::close(pd.aStdoutPipe[c_write]);
			pd.aStdinPipe[c_read] = 0;
			pd.aStdoutPipe[c_write] = 0;
		}

		return pd;
    }

    void close(process_data& data) {
		if (data.m_nChildID != 0) {
			kill(data.m_nChildID, SIGTERM);
			data.m_nChildID = 0;
		}
		if (data.aStdinPipe[c_read] != 0) {
			::close(data.aStdinPipe[c_read]);
			data.aStdinPipe[c_read] = 0;
		}
		if (data.aStdinPipe[c_write] != 0) {
			::close(data.aStdinPipe[c_write]);
			data.aStdinPipe[c_write] = 0;
		}
		if (data.aStdoutPipe[c_read] != 0) {
			::close(data.aStdoutPipe[c_read]);
			data.aStdoutPipe[c_read] = 0;
		}
		if (data.aStdoutPipe[c_write] != 0) {
			::close(data.aStdoutPipe[c_write]);
			data.aStdoutPipe[c_write] = 0;
		}
    }

    bool write(const process_data& data, const std::string& str) {
        if (data.aStdinPipe[c_write] == 0 || str.empty()) return false;
        
		return ::write(data.aStdinPipe[c_write], str.data(), str.size()) > 0;
    }

    std::string read(const process_data& data) {
        if (data.aStdoutPipe[c_read] == 0) return {};

		std::string buf;
        char ch{};

		while (1) {
			if (::read(data.aStdoutPipe[c_read], &ch, sizeof(char)) == 0) {
				if (get_state(data) != e_process_status::P_ACTIVE) return buf;
                
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
				continue;
			}

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
		pollfd fd;
		fd.fd = data.aStdoutPipe[c_read];
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
    }

    e_process_status get_state(const process_data& data) {
        if (data.m_nChildID == 0) return e_process_status::P_EXITED; // no child
		int status{};
		pid_t res = waitpid(data.m_nChildID, &status, WNOHANG);
        
        switch(res) {
        case 0: return e_process_status::P_ACTIVE;
        default: return res < 0 ? e_process_status::P_ERROR : e_process_status::P_EXITED;
        }
    }


} // namespace platform
} // namespace Lunaris
} // namespace Process