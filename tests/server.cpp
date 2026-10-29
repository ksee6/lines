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

struct ClientSession {
    Lines lines;
    sockaddr_in addr;
    bool active = false;
};

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int port = 9876;
    if (argc > 1) port = atoi(argv[1]);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serverAddr.sin_port = htons(port);

    if (bind(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    printf("[Lines Server] Listening on 127.0.0.1:%d\n", port);

    ClientSession session;
    session.lines.enable([&](String bundle) {
        if (session.active) {
            sendto(sockfd, bundle.data(), bundle.size(), 0, (sockaddr*)&session.addr, sizeof(session.addr));
        }
    });

    session.lines.onProbe = [&](Lines::Tree selector) -> bool {
        String json = toJSON(selector);
        printf("[Lines Server] Received Probe from client! Selector Tree:\n%s\n", json.c_str());
        return true; // Announce
    };

    session.lines.onUpgrade = [&]() -> bool {
        printf("[Lines Server] Received Upgrade! Connection live.\n");
        return true;
    };

    int packetsReceived = 0;
    session.lines.onPacket = [&](Packet packet) {
        printf("[Lines Server] Received Packet on Channel %u: '%s'\n",
               packet.channel, packet.payload.c_str());
        packetsReceived++;

        // Echo back with Pong
        String reply = "Pong from Lines UDP Server (" + String(packetsReceived) + ")";
        session.lines.push(Packet(packet.channel, reply, true, true));
    };

    bool disconnected = false;
    session.lines.onDisconnect = [&](Lines::Tree reason) {
        String json = toJSON(reason);
        printf("[Lines Server] Client disconnected. Bitpacked Reason Tree as JSON:\n%s\n", json.c_str());
        disconnected = true;
    };

    u8 buffer[4096];
    bool run = true;
    int maxPackets = (argc > 2) ? atoi(argv[2]) : 3;

    while (run && !disconnected) {
        pollfd pfd{};
        pfd.fd = sockfd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 50);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            sockaddr_in clientAddr{};
            socklen_t addrLen = sizeof(clientAddr);
            ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&clientAddr, &addrLen);
            if (n > 0) {
                session.addr = clientAddr;
                session.active = true;

                String bundle(buffer, (usz)n);
                session.lines.parse(bundle, 0);

                if (disconnected) {
                    usleep(10000);
                    break;
                }
            }
        }

        session.lines.update();
    }

    printf("[Lines Server] Completed cleanly. Total packets processed: %d\n", packetsReceived);
    close(sockfd);
    return 0;
}
