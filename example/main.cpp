#include <iostream>
#include <thread>

#include <Lunaris/process.h>

using namespace Lunaris::Process;

int main() {
    Process proc("cat");

    while(proc.running()) {
        std::printf("ON WAIT\n");
        std::string str;
        std::getline(std::cin, str);

        std::printf("SENDING: %s\n", str.c_str());
        proc.write(str);
        std::printf("SENT: %s\n", str.c_str());

        if (str.find("exit") == 0)
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (proc.has_read()) 
            std::printf("ECHOED: %s\n", proc.read().c_str());
    }

    proc.stop();

    return 0;
}

/*int main() {
    Process proc("ls");

    while(!proc.has_read()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    while(proc.has_read()) 
        std::printf("-> %s\n", proc.read().c_str());

    std::cout << "WIP.\n";

    return 0;
}
*/