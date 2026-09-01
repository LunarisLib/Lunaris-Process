#include <Lunaris/process.h>

#include <iostream>
#include <thread>

using namespace Lunaris::Process;

int main() {
    std::printf("Testing cat echoing...\n");

    const std::string c_msg{"hello world echo"};
#ifdef _WIN32
    constexpr char cmd[] = "more.com";
#else
    constexpr char cmd[] = "cat";
#endif
    Process proc{cmd};

    std::printf("Writing message...\n");
    if (!proc.write(c_msg + "\r\n")) {
        std::printf("Failed to write message.\n");
        return 1;
    }

    std::printf("Reading back...\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const auto back = proc.read();

    if (back != c_msg) {
        std::printf("Message mismatch. '%s' != '%s'\n", back.c_str(), c_msg.c_str());
        return 2;
    }

    proc.stop();

    std::printf("Sounds good!\n");

    return 0;
}