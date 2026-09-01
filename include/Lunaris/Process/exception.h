#pragma once

#include <stdexcept>

namespace Lunaris {
namespace Process {

    class process_exception : public std::runtime_error {
    public:
        explicit process_exception(const std::string&) noexcept;
        explicit process_exception(const char*) noexcept;

        const char* what() const noexcept;
    };

} // namespace Process
} // namespace Lunaris