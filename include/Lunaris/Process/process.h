#pragma once

#include <Lunaris/Process/platform.h>

#include <memory>

namespace Lunaris {
namespace Process {

    /**
     * @brief Process is a wrapper of a call like in a terminal. You can use it to call apps that uses stdio like in terminal
     */
    class Process {
    public:
        /**
         * @brief Construct a new Process object
         * 
         * @param command Executable name or path
         * @param modes Flags of enum e_modes
         */
        Process(const std::string& command, const e_modes& modes = e_modes::READ | e_modes::WRITE);

        /**
         * @brief Construct a new Process object
         * 
         * @param command Executable name or path
         * @param args 
         * @param modes Flags of enum e_modes
         */
        Process(const std::string& command, const std::vector<std::string>& args, const e_modes& modes = e_modes::READ | e_modes::WRITE);

        ~Process();

        /**
         * @brief Does a SIGTERM on the process
         */
        void stop();

        /**
         * @brief Write data to stdout 
         * 
         * @return `bool` returns true if wrote something
         */
        bool write(const std::string&);

        /**
         * @brief Attempts to read from stdin.
         * 
         * @return `std::string` A line read, or the most it could read before timeout
         */
        std::string read();

        /**
         * @brief Check if there's something to read in stdin
         * 
         * @return `bool` returns true if you have data to read
         */
        bool has_read() const;

        /**
         * @brief Check if the process is still up and running
         * 
         * @return `bool` returns true if ACTIVE
         */
        bool running() const;

        /**
         * @brief Check if state is different than error (it may have stopped already)
         * 
         * @return `bool` returns true if no error
         */
        bool valid() const;

        /**
         * @brief Check if state is different than error (it may have stopped already)
         * 
         * @return `bool` returns true if no error
         */
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