#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include "Lines/Lines.hpp"
#include <Ksee/Crypto/SHA.hpp>

using namespace Ksee;
using Lines = Ksee::Lines;
using PhysicalBand = Ksee::PhysicalBand;
using BandSlot = Ksee::BandSlot;
using Packet = Ksee::Packet;
using SentBundle = Ksee::SentBundle;
using RecvBundle = Ksee::RecvBundle;

static String toHex(const String &bin) {
    static const char hexChars[] = "0123456789abcdef";
    String res;
    for (usz i = 0; i < bin.size(); ++i) {
        u8 b = (u8)bin[i];
        res.push(hexChars[(b >> 4) & 0x0F]);
        res.push(hexChars[b & 0x0F]);
    }
    return res;
}

struct ClientSession {
    Lines lines;
    sockaddr_in addr;
    bool active = false;
};

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int port = 9876;
    if (argc > 1) port = atoi(argv[1]);

    int totalMB = (argc > 2) ? atoi(argv[2]) : 50;
    if (totalMB <= 0) totalMB = 50;
    const usz totalBytes = (usz)totalMB * 1024 * 1024;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    int bufSize = 16 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serverAddr.sin_port = htons(port);

    if (bind(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    printf("[Lines Server] Listening on 127.0.0.1:%d (Expecting %d MB of data)\n", port, totalMB);

    ClientSession session;
    session.lines.enable([&](String bundle) {
        if (session.active) {
            sendto(sockfd, bundle.data(), bundle.size(), 0, (sockaddr*)&session.addr, sizeof(session.addr));
        }
    }, /* band = */ 1, /* initialWeight = */ 100, /* maxBundleSize = */ 36000);

    session.lines.onProbe = [&](Lines::Tree selector) -> bool {
        String json = stringifyJSON(selector, 2);
        printf("[Lines Server] Received Probe from client! Hydrated Selector Tree (%zu bytes wire):\n%s\n",
               petrify(selector).size(), json.c_str());
        return true;
    };

    session.lines.onUpgrade = [&]() -> bool {
        printf("[Lines Server] Received Upgrade! Connection live. Ready to receive bulk data.\n");
        return true;
    };

    String serverReceivedData;
    serverReceivedData.allocate(totalBytes);
    usz serverBytesReceived = 0;
    bool hashVerified = false;

    session.lines.onPacket = [&](Packet packet) {
        if (packet.channel == 1) {
            if (packet.payload.size() == 69 && packet.payload.startsWith("HASH:")) {
                String clientHashHex = packet.payload.substring(5);
                printf("[Lines Server] Received Client SHA256 Hash: %s\n", clientHashHex.c_str());
                printf("[Lines Server] Total payload bytes received:  %zu / %zu\n", serverBytesReceived, totalBytes);

                if (serverBytesReceived == totalBytes) {
                    String serverHashHex = toHex(SHA256::hash(serverReceivedData.data(), totalBytes));
                    printf("[Lines Server] Server computed SHA256 Hash: %s\n", serverHashHex.c_str());

                    if (serverHashHex == clientHashHex) {
                        hashVerified = true;
                        printf("[Lines Server] SUCCESS: 50MB HASH MATCH CONFIRMED!\n");
                        session.lines.push(Packet(1, "HASH_OK", true, true));
                    } else {
                        printf("[Lines Server] ERROR: HASH MISMATCH!\n");
                        session.lines.push(Packet(1, "HASH_ERR", true, true));
                    }
                } else {
                    printf("[Lines Server] ERROR: Incomplete transfer (%zu / %zu bytes)\n",
                           serverBytesReceived, totalBytes);
                    session.lines.push(Packet(1, "HASH_INCOMPLETE", true, true));
                }
            } else {
                if (serverBytesReceived + packet.payload.size() <= totalBytes) {
                    memcpy((void*)(serverReceivedData.data() + serverBytesReceived),
                           packet.payload.data(), packet.payload.size());
                    serverBytesReceived += packet.payload.size();
                }
            }
        }
    };

    bool disconnected = false;
    session.lines.onDisconnect = [&](Lines::Tree reason) {
        String json = stringifyJSON(reason, 2);
        printf("[Lines Server] Client disconnected. Hydrated Petrified Reason Tree (%zu bytes wire):\n%s\n",
               petrify(reason).size(), json.c_str());
        disconnected = true;
    };

    u8 buffer[65536];
    int sackCounter = 0;
    u64 lastServerSack = millis();
    u64 lastProgressPrint = millis();

    while (!disconnected) {
        pollfd pfd{};
        pfd.fd = sockfd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 10);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            while (true) {
                sockaddr_in clientAddr{};
                socklen_t addrLen = sizeof(clientAddr);
                ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (sockaddr*)&clientAddr, &addrLen);
                if (n <= 0) break;

                session.addr = clientAddr;
                session.active = true;

                String bundle((const u8*)buffer, (usz)n);
                session.lines.parse(bundle, 1);

                if (++sackCounter >= 8) {
                    session.lines.sendSackHeartbeat(1);
                    sackCounter = 0;
                    lastServerSack = millis();
                }
            }
            if (sackCounter > 0) {
                session.lines.sendSackHeartbeat(1);
                sackCounter = 0;
                lastServerSack = millis();
            }
        }

        u64 now = millis();
        if (now - lastProgressPrint >= 1000) {
            printf("[Lines Server Progress] received: %zu / %zu (%.1f%%), base: %llu\n",
                   serverBytesReceived, totalBytes, (double)serverBytesReceived * 100.0 / totalBytes,
                   (unsigned long long)session.lines.base);
            lastProgressPrint = now;
        }

        if (session.active && now - lastServerSack >= 25) {
            session.lines.sendSackHeartbeat(1);
            lastServerSack = now;
        }

        session.lines.update();
    }

    printf("[Lines Server] Completed cleanly. Total bytes received: %zu. Hash verified: %s\n",
           serverBytesReceived, hashVerified ? "YES" : "NO");
    close(sockfd);
    return hashVerified ? 0 : 1;
}
