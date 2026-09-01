#include <Lunaris/process.h>

#include <iostream>

using namespace Lunaris::Process;

struct command {
    std::string base;
    std::vector<std::string> arguments;
    const uint32_t expected_min_responses_len;

    command(std::initializer_list<std::string> opts, const uint32_t erl)
        : base(*opts.begin()), arguments(opts.begin() + 1, opts.end()), expected_min_responses_len(erl)
    {}
};

int main() {
#ifdef _WIN32
    const command commands[] = {
        {{"whoami"}, 1},
        {{"hostname"}, 1},
        {{"cmd", "/c", "echo", "\"is apple a fruit\""}, 1},
        {{"ping", "-n", "5", "127.0.0.1"}, 6},
        {{"timeout", "/t", "5", "/nobreak"}, 0},
        //{{"cmd", "/c", "dir"}, 3},
        {{"tasklist"}, 5}
    };
#else
    const command commands[] = {
        {{"whoami"}, 1},
        {{"hostname"}, 1},
        {{"echo", "\"is apple a fruit\""}, 1},
        {{"ping", "-c", "5", "127.0.0.1"}, 6},
        {{"sleep", "5"}, 0},
        {{"ls"}, 3},
        {{"ps", "aux"}, 5}
    };
#endif

    for(const command& cmd : commands) {
        std::printf("Testing command: '%s'\n", cmd.base.c_str());

        Process proc{cmd.base, cmd.arguments};
        std::vector<std::string> lines;
        
        while(proc.running()) {
            if (proc.has_read()) {
                lines.push_back(proc.read());
            }
        }

        std::printf("- Got %zu lines:\n", lines.size());
        for(const auto& line : lines)
            std::printf("  - %s\n", line.c_str());

        if (lines.size() < cmd.expected_min_responses_len) {
            std::printf("Mismatch of expected number of lines: %zu < %u (min expected)!\n", lines.size(), cmd.expected_min_responses_len);
            return 1;
        }
    }

    return 0;
}