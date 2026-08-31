#include <Lunaris/process.h>

#include <iostream>
#include <thread>

using namespace Lunaris::Process;

int main() {
    std::printf("Testing cat echoing...\n");

    const std::string c_msg{"hello world echo"};
    Process proc("cat");

    std::printf("Writing message...\n");
    if (!proc.write(c_msg)) {
        std::printf("Failed to write message.\n");
        return 1;
    }

    std::printf("Reading back...\n");
    const auto back = proc.read();

    if (back != c_msg) {
        std::printf("Message mismatch.\n");
        return 2;
    }

    proc.stop();

    std::printf("Sounds good!\n");

    return 0;
}