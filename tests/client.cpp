#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include "Lines/Lines.hpp"

using namespace Ksee;

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int port = 9876;
    if (argc > 1) port = atoi(argv[1]);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    printf("[Lines Client] Target UDP server at 127.0.0.1:%d\n", port);

    Lines client;
    client.enable([&](String bundle) {
        sendto(sockfd, bundle.data(), bundle.size(), 0, (sockaddr*)&serverAddr, sizeof(serverAddr));
    }, /* band = */ 0, /* initialWeight = */ 50, /* mtu = */ 1024);

    bool isReady = false;
    int repliesReceived = 0;
    int totalToSend = (argc > 2) ? atoi(argv[2]) : 3;

    client.onAnnounce = [&]() -> bool {
        printf("[Lines Client] Server announced itself, sending Upgrade...\n");
        return true;
    };

    client.onReady = [&]() {
        printf("[Lines Client] Handshake complete! Post-upgrade channel is LIVE.\n");
        isReady = true;

        for (int i = 1; i <= totalToSend; ++i) {
            u32 channel = (i % 2 == 0) ? 2 : 1;
            String msg = "Ping #" + String(i) + " over Lines UDP";
            printf("[Lines Client] Sending Packet on Channel %u: '%s'\n", channel, msg.c_str());
            client.push(Packet(channel, msg, true, true));
        }
    };

    client.onPacket = [&](Packet packet) {
        printf("[Lines Client] Received Reply on Channel %u: '%s'\n", packet.channel, packet.payload.c_str());
        repliesReceived++;
    };

    // Start handshake: probe
    Lines::Tree selector;
    parseJSON(R"({
        "name": "device.alpha",
        "version": 101,
        "protocol": "LinesUDP"
    })", selector);
    printf("[Lines Client] Sending Probe to server with bitpacked selector Tree:\n%s\n", toJSON(selector).c_str());
    client.probe(selector);

    u8 buffer[4096];
    u64 startTime = millis();
    bool completed = false;

    while (millis() - startTime < 5000) { // 5-second max timeout
        pollfd pfd{};
        pfd.fd = sockfd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 50);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            sockaddr_in fromAddr{};
            socklen_t fromLen = sizeof(fromAddr);
            ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&fromAddr, &fromLen);
            if (n > 0) {
                String bundle(buffer, (usz)n);
                client.parse(bundle, 0);
            }
        }

        client.update();

        if (isReady && repliesReceived >= totalToSend) {
            completed = true;
            printf("[Lines Client] All %d echo replies successfully received!\n", repliesReceived);

            // Send graceful disconnect with a rich bitpacked reason tree (parsed from JSON)
            Lines::Tree reason;
            parseJSON(R"({
                "status": "completed",
                "code": 200,
                "message": "all_packets_exchanged",
                "stats": {
                    "sent": 3,
                    "received": 3
                }
            })", reason);
            printf("[Lines Client] Disconnecting cleanly with bitpacked reason Tree:\n%s\n", toJSON(reason).c_str());
            client.disconnect(reason);
            usleep(20000); // 20ms to allow delivery
            break;
        }
    }

    close(sockfd);

    if (completed) {
        printf("[Lines Client] UDP Communication test PASSED successfully!\n");
        return 0;
    } else {
        printf("[Lines Client] ERROR: UDP Communication test timed out (replies: %d/%d).\n",
               repliesReceived, totalToSend);
        return 1;
    }
}
