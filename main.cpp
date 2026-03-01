#include  "PacketCapturer.h"

int main() {
    PacketCapturer capturer("enp0s3");
    capturer.startCapture();
    return 0;
}
