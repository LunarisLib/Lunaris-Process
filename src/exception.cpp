#include <Lunaris/Process/exception.h>


namespace Lunaris {
namespace Process {

    process_exception::process_exception(const std::string& msg) noexcept
        : std::runtime_error(msg)
    {
    }

    process_exception::process_exception(const char* msg) noexcept
        : std::runtime_error(msg)
    {
    }

    const char* process_exception::what() const noexcept {
        return std::runtime_error::what();
    }

} // namespace Process
} // namespace Lunaris