#include <Lunaris/Process/exception.h>


namespace Lunaris {
namespace Process {

    ProcessException::ProcessException(const std::string& msg) noexcept
        : std::runtime_error(msg)
    {
    }

    ProcessException::ProcessException(const char* msg) noexcept
        : std::runtime_error(msg)
    {
    }

    const char* ProcessException::what() const noexcept {
        return std::runtime_error::what();
    }

} // namespace Process
} // namespace Lunaris