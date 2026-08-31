#include <iostream>
#include <thread>

#include <Lunaris/process.h>

using namespace Lunaris::Process;

int main() {
    Process proc("ls");

    while(!proc.has_read()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    while(proc.has_read()) 
        std::printf("-> %s\n", proc.read().c_str());

    std::cout << "WIP.\n";

    return 0;
}
