#include <Lunaris/Process/process.h>


namespace Lunaris {
namespace Process {

    Process::Process(const std::string& command, const e_modes& modes) 
        : m_data(platform::open(command, modes, {}))
    {}

    Process::Process(const std::string& command, const std::initializer_list<std::string>& args, const e_modes& modes) 
        : m_data(platform::open(command, modes, args))
    {}

    Process::~Process() {
        stop();
    }

    void Process::stop() {
        platform::close(m_data);
    }

    bool Process::write(const std::string& str) {
        return platform::write(m_data, str);
    }

    std::string Process::read() {
        return platform::read(m_data);
    }

    bool Process::has_read() const {
        return platform::has_read(m_data);
    }

    bool Process::running() const {
        return platform::get_state(m_data) == e_process_status::ACTIVE;
    }

    bool Process::valid() const {
        return platform::get_state(m_data) != e_process_status::ERROR;
    }

    Process::operator bool() const {
        return platform::get_state(m_data) != e_process_status::ERROR;
    }

} // namespace Process
} // namespace Lunaris