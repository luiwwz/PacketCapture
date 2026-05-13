#ifndef THREAD_MANAGER_H
#define THREAD_MANAGER_H

#include <thread>
#include <vector>
#include <atomic>
#include <csignal>

class ThreadManager {
private:
    static ThreadManager* instance;
    std::vector<std::thread> analyzer_threads;
    static std::atomic<bool> should_exit;

    ThreadManager();

public:
    static ThreadManager* getInstance();

    void setupSignalHandlers();
    void spawnAnalyzers(int count);
    void terminateAnalyzers();
    void waitForAnalyzers();
    bool shouldContinue() const;

    static void signalHandler(int signal);
};

#endif
