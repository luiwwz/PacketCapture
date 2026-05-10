#ifndef PROCESS_MANAGER_H
#define PROCESS_MANAGER_H

#include <vector>
#include <sys/types.h>
#include <unistd.h>
#include <csignal>

class ProcessManager {
private:
    static ProcessManager* instance;
    std::vector<pid_t> analyzer_processes;
    int num_analyzers;
    volatile static bool should_exit;

    ProcessManager();
    ~ProcessManager();

public:
    static ProcessManager* getInstance();
    void setupSignalHandlers();
    void spawnAnalyzers(int count);
    void terminateAnalyzers();
    void waitForAnalyzers();
    static void signalHandler(int signal);
    bool shouldContinue() const;
};

#endif
