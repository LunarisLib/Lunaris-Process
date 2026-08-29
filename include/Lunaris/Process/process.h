#pragma once

#include <Lunaris/Process/platform.h>

#include <memory>

namespace Lunaris {
namespace Process {

    class Process {
    public:
        Process(const std::string& command, const e_modes& modes = e_modes::READ | e_modes::WRITE);
        Process(const std::string& command, const std::initializer_list<std::string>& args, const e_modes& modes = e_modes::READ | e_modes::WRITE);

        ~Process();

        void stop();

        bool write(const std::string&);
        std::string read();

        bool has_read() const;

        bool running() const;

        bool valid() const;
        operator bool() const;

        Process(const Process&) = delete;
        Process(Process&&) = delete;
        void operator=(const Process&) = delete;
        void operator=(Process&&) = delete;
    private:
        process_data m_data;
    };

} // namespace Process
} // namespace Lunaris