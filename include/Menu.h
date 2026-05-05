#ifndef MENU_H
#define MENU_H

#include <string>

class Menu {
private:
    std::string currentInterface;
    bool loggingEnabled;
    int packetCount;

    void startPacketCapture();

public:
    Menu();
    void showMainMenu();
    void showInterfaceMenu();
    void showSettingsMenu();
    void showPacketCountMenu();
    
    std::string getCurrentInterface() const;
    bool isLoggingEnabled() const;
    int getPacketCount() const;
};

#endif
