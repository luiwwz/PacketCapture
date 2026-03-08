#include  "PacketCapturer.h"

int main() {
    PacketCapturer capturer("eth0");
    capturer.startCapture();
    return 0;
}
