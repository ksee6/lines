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
using Band = Ksee::Band;
using LinesBandSlot = Ksee::LinesBandSlot;
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

    int bufSize = 16 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    printf("[Lines Client] Target UDP server at 127.0.0.1:%d (Preparing %d MB transfer)\n", port, totalMB);

    Lines client;
    Band pb;
    pb.sendCallback = [&](String bundle) {
        sendto(sockfd, bundle.data(), bundle.size(), 0, (sockaddr*)&serverAddr, sizeof(serverAddr));
    };
    pb.maxBundleSize = 36000;
    client.enable(pb);

    bool isReady = false;
    bool serverConfirmed = false;

    client.onAnnounce = [&]() -> bool {
        printf("[Lines Client] Server announced itself, sending Upgrade...\n");
        return true;
    };

    client.onUpgrade = [&](Lines::Tree) {
        printf("[Lines Client] Handshake complete! Post-upgrade session is LIVE.\n");
        isReady = true;
    };

    client.onPacket = [&](Packet packet) {
        printf("[Lines Client] Received packet on handle %llu: '%.*s'\n",
               (unsigned long long)packet.handle, (int)packet.payload.size(), packet.payload.c_str());
        if (packet.handle == 1 && packet.payload == "HASH_OK") {
            serverConfirmed = true;
            printf("[Lines Client] Server confirmed 50MB hash match successfully!\n");
        } else if (packet.handle == 1 && packet.payload == "HASH_ERR") {
            printf("[Lines Client] ERROR: Server reported hash mismatch!\n");
        }
    };

    // Start handshake: probe
    Lines::Tree selector;
    parseTree(R"({
        "name": "device.alpha",
        "version": 101,
        "protocol": "LinesUDP"
    })", selector);
    String petrifiedSel = petrify(selector);
    printf("[Lines Client] Sending Probe to server with Petrified Tree (%zu bytes):\n%s\n",
           petrifiedSel.size(), stringifyJSON(selector, 2).c_str());
    client.probe(selector);

    u8 buffer[65536];
    u64 tStart = millis();

    // 1. Wait for handshake
    while (!isReady && millis() - tStart < 5000) {
        pollfd pfd{};
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 10);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (n > 0) client.parse(String((const u8*)buffer, (usz)n));
        }
    }

    if (!isReady) {
        printf("[Lines Client] Handshake timed out!\n");
        close(sockfd);
        return 1;
    }

    // 2. Prepare 50MB payload and compute SHA-256
    printf("[Lines Client] Generating %d MB of test data...\n", totalMB);
    String dataToSend;
    dataToSend.allocate(totalBytes);
    for (usz i = 0; i < totalBytes; ++i) {
        dataToSend[i] = (char)((i * 31 + 7) & 0xFF);
    }

    String clientHashHex = toHex(SHA256::hash(dataToSend.data(), totalBytes));
    printf("[Lines Client] Computed SHA-256 over %zu bytes:\n    %s\n", totalBytes, clientHashHex.c_str());

    // 3. Stream 50MB and push hash
    usz sentBytes = 0;
    const usz chunkSize = 32768;
    bool hashPushed = false;
    u64 tTransferStart = millis();
    u64 lastClientUpdate = millis();

    printf("[Lines Client] Streaming %d MB of data over Lines encrypted transport...\n", totalMB);

    u64 lastProgressPrint = millis();
    while (!serverConfirmed && millis() - tTransferStart < 30000) {
        int pushedThisBatch = 0;
        while (sentBytes < totalBytes && client.couldPush() && pushedThisBatch < 8) {
            usz chunkSz = (totalBytes - sentBytes > chunkSize) ? chunkSize : (totalBytes - sentBytes);
            client.push(Packet(String((const u8*)dataToSend.data() + sentBytes, chunkSz), 1, 1, true, true));
            sentBytes += chunkSz;
            pushedThisBatch++;
        }

        if (sentBytes == totalBytes && !hashPushed && client.couldPush()) {
            client.push(Packet("HASH:" + clientHashHex, 1, 1, true, true));
            hashPushed = true;
            printf("[Lines Client] All %zu bytes pushed. Dispatched SHA-256 hash packet on Channel 1.\n", totalBytes);
        }

        pollfd pfd{};
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        int pollTimeout = (client.couldPush() && sentBytes < totalBytes) ? 0 : 2;
        poll(&pfd, 1, pollTimeout);

        if (pfd.revents & POLLIN) {
            while (true) {
                ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, nullptr, nullptr);
                if (n <= 0) break;
                client.parse(String((const u8*)buffer, (usz)n));
            }
        }

        u64 now = millis();
        if (now - lastProgressPrint >= 1000) {
            printf("[Lines Client Progress] sentBytes: %zu / %zu (%.1f%%), couldPush: %d\n",
                   sentBytes, totalBytes, (double)sentBytes * 100.0 / totalBytes,
                   (int)client.couldPush());
            lastProgressPrint = now;
        }

        if (now - lastClientUpdate >= 20) {
            if (!client.couldPush()) {
                client.retransmitFrom = 0;
            }
            client.update();
            lastClientUpdate = now;
        }
    }

    u64 tTransferEnd = millis();
    u64 elapsed = tTransferEnd - tTransferStart;
    if (elapsed == 0) elapsed = 1;
    f64 speedMBs = (f64)totalMB / ((f64)elapsed / 1000.0);

    if (serverConfirmed) {
        printf("[Lines Client] Transfer and verification completed in %llu ms (Throughput: %.2f MB/s)!\n",
               (unsigned long long)elapsed, speedMBs);

        // Graceful disconnect
        Lines::Tree reason;
        parseTree(R"({
            "status": "completed",
            "code": 200,
            "message": "50mb_hash_verified",
            "transferred_bytes": 52428800
        })", reason);
        String petrifiedReason = petrify(reason);
        printf("[Lines Client] Disconnecting cleanly with Petrified Tree (%zu bytes):\n%s\n",
               petrifiedReason.size(), stringifyJSON(reason, 2).c_str());
        client.disconnect(reason);
        usleep(20000);
    } else {
        printf("[Lines Client] ERROR: 50MB transfer and hash verification timed out!\n");
    }

    close(sockfd);
    return serverConfirmed ? 0 : 1;
}
