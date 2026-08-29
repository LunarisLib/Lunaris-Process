#include <iostream>
#include <thread>
#include <print>

#include <Lunaris/process.h>

using namespace Lunaris::Process;

int main() {
    Process proc("ls");

    while(!proc.has_read()) std::this_thread::sleep_for(std::chrono::milliseconds(100));

    
    while(proc.has_read()) 
        std::print("-> {}\n", proc.read());

    std::cout << "WIP.\n";

    return 0;
}
