#pragma once

#include <stdexcept>

namespace Lunaris {
namespace Process {

    class ProcessException : public std::runtime_error {
    public:
        explicit ProcessException(const std::string&) noexcept;
        explicit ProcessException(const char*) noexcept;

        const char* what() const noexcept;
    };

} // namespace Process
} // namespace Lunaris