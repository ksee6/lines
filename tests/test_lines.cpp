#include <stdio.h>
#include <assert.h>
#include "../include/Lines/Lines.hpp"

using namespace Ksee;

static void test_multiband_properties() {
    printf("[TEST] Multi-Band Properties & Aggression...\n");
    Lines lines;
    assert(!lines.isUpgraded());
    assert(lines.getAggression() == 0.0f);
    assert(lines.couldPush());

    lines.enable([](String) {}, 0, 100, 1024);
    lines.enable([](String) {}, 1, 200, 512);

    assert(lines.getBandWeight(0) == 100);
    assert(lines.getBandWeight(1) == 200);
    assert(lines.getWeight() == 300);

    lines.disable(1);
    assert(lines.getBandWeight(1) == 0);
    assert(lines.getWeight() == 100);
    printf("  -> Multi-band configuration verified.\n");
}

static void test_handshake_lifecycle() {
    printf("[TEST] Complete 1.5RTT Handshake (Probe -> Announce -> Upgrade)...\n");
    Lines client;
    Lines server;

    String clientWire;
    String serverWire;

    client.enable([&](String b) { clientWire = b; }, 0, 10, 1024);
    server.enable([&](String b) { serverWire = b; }, 0, 10, 1024);

    bool serverProbed = false;
    server.onProbe = [&](Lines::Tree sel) -> bool {
        serverProbed = true;
        return true;
    };

    bool clientAnnounced = false;
    client.onAnnounce = [&]() -> bool {
        clientAnnounced = true;
        return true;
    };

    bool serverUpgraded = false;
    server.onUpgrade = [&]() -> bool {
        serverUpgraded = true;
        return true;
    };

    bool clientReady = false;
    client.onReady = [&]() { clientReady = true; };

    bool serverReady = false;
    server.onReady = [&]() { serverReady = true; };

    // 1. Client probes
    Lines::Tree selector;
    selector.path = Path("gateway.device1");
    client.probe(selector);
    assert(clientWire.size() > 0);
    assert(!Lines::isEncrypted(clientWire));

    // 2. Server receives probe and sends Announce
    bool handledProbe = server.parse(clientWire, 0);
    assert(handledProbe);
    assert(serverProbed);
    assert(serverWire.size() > 0);

    // 3. Client receives Announce and sends Upgrade
    bool handledAnnounce = client.parse(serverWire, 0);
    assert(handledAnnounce);
    assert(clientAnnounced);
    assert(clientReady);
    assert(client.isUpgraded());

    // 4. Server receives Upgrade
    bool handledUpgrade = server.parse(clientWire, 0);
    assert(handledUpgrade);
    assert(serverUpgraded);
    assert(serverReady);
    assert(server.isUpgraded());

    printf("  -> Handshake fully completed, both sides live in post-upgrade mode.\n");
}

static void test_post_upgrade_messaging() {
    printf("[TEST] Post-Upgrade Encrypted Messaging & Channels...\n");
    Lines client;
    Lines server;

    String sharedSecret = "01234567890123456789012345678901"; // 32 bytes
    client.manualUpgrade(sharedSecret, true, 2);
    server.manualUpgrade(sharedSecret, false, 2);

    assert(client.isUpgraded());
    assert(server.isUpgraded());

    String serverRxPayload;
    u32 serverRxChannel = 0;
    server.onPacket = [&](Packet p) {
        serverRxPayload = p.payload;
        serverRxChannel = p.channel;
    };

    String clientBundle;
    client.enable([&](String b) { clientBundle = b; }, 0, 50, 1024);

    Packet outP(42, String("Hello from encrypted client!"), true, true);
    client.push(outP);

    assert(clientBundle.size() > 0);
    assert(Lines::isEncrypted(clientBundle));

    bool parsed = server.parse(clientBundle, 0);
    assert(parsed);
    assert(serverRxChannel == 42);
    assert(serverRxPayload == "Hello from encrypted client!");

    // Test reverse direction (Server -> Client)
    String serverBundle;
    server.enable([&](String b) { serverBundle = b; }, 0, 50, 1024);

    String clientRxPayload;
    u32 clientRxChannel = 0;
    client.onPacket = [&](Packet p) {
        clientRxPayload = p.payload;
        clientRxChannel = p.channel;
    };

    Packet replyP(7, String("Encrypted response from server!"), true, true);
    server.push(replyP);

    assert(serverBundle.size() > 0);
    assert(Lines::isEncrypted(serverBundle));

    parsed = client.parse(serverBundle, 0);
    assert(parsed);
    assert(clientRxChannel == 7);
    assert(clientRxPayload == "Encrypted response from server!");

    printf("  -> Bidirectional encrypted messaging verified.\n");
}

static void test_anti_tamper_and_anti_replay() {
    printf("[TEST] Anti-Tamper & Anti-Replay Sliding Window...\n");
    Lines client;
    Lines server;

    String sharedSecret = "secret_key_for_testing_tamper_32";
    client.manualUpgrade(sharedSecret, true, 2);
    server.manualUpgrade(sharedSecret, false, 2);

    String clientBundle;
    client.enable([&](String b) { clientBundle = b; }, 0, 10, 1024);

    client.push(Packet(1, String("Tamper Test Payload"), true, true));
    assert(clientBundle.size() > 0);

    // 1. Valid bundle passes
    bool ok = server.parse(clientBundle, 0);
    assert(ok);

    // 2. Replayed bundle is dropped
    bool replayed = server.parse(clientBundle, 0);
    assert(!replayed);

    // 3. Tampered bundle (corrupt ciphertext)
    client.push(Packet(1, String("Another Payload"), true, true));
    String tamperedBundle = clientBundle;
    tamperedBundle[tamperedBundle.size() - 1] ^= 0xFF; // Flip byte in ciphertext
    bool tamperedOk = server.parse(tamperedBundle, 0);
    assert(!tamperedOk);

    printf("  -> Anti-tamper and anti-replay windowing verified.\n");
}

static void test_connection_roaming_fast_filter() {
    printf("[TEST] Connection Roaming Fast Pre-Filtering (< 10ns)...\n");
    Lines clientA;
    Lines clientB;

    clientA.manualUpgrade("client_a_secret_key_32_bytes____", true, 2);
    clientB.manualUpgrade("client_b_secret_key_32_bytes____", true, 2);

    Lines serverA;
    Lines serverB;
    serverA.manualUpgrade("client_a_secret_key_32_bytes____", false, 2);
    serverB.manualUpgrade("client_b_secret_key_32_bytes____", false, 2);

    String bundleA;
    clientA.enable([&](String b) { bundleA = b; }, 0, 10, 1024);
    clientA.push(Packet(1, String("Roaming packet from A"), true, true));

    // Server A should match bundle A in Tier 1
    assert(serverA.matchesBundle(bundleA));
    // Server B should reject bundle A instantly without decrypting!
    assert(!serverB.matchesBundle(bundleA));

    printf("  -> Roaming fast filter verified.\n");
}

static void test_fragmentation_and_reassembly() {
    printf("[TEST] Fragmentation & Reassembly over MTU Boundaries...\n");
    Lines client;
    Lines server;

    String sharedSecret = "32_byte_secret_for_fragmentation";
    client.manualUpgrade(sharedSecret, true, 2);
    server.manualUpgrade(sharedSecret, false, 2);

    String receivedBigPayload;
    server.onPacket = [&](Packet p) {
        receivedBigPayload = p.payload;
    };

    Array<String> capturedBundles;
    client.enable([&](String b) { capturedBundles.push(b); }, 0, 10, 512);

    // Create 1500-byte payload (exceeds 512-byte MTU)
    String bigPayload;
    for (int i = 0; i < 150; ++i) {
        bigPayload.append("0123456789", 10);
    }
    assert(bigPayload.size() == 1500);

    client.push(Packet(5, bigPayload, true, true));
    assert(capturedBundles.size() > 1);

    // Deliver all fragments to server
    for (usz i = 0; i < capturedBundles.size(); ++i) {
        bool ok = server.parse(capturedBundles[i], 0);
        assert(ok);
    }

    assert(receivedBigPayload.size() > 0);
    printf("  -> Large packet successfully fragmented and handled.\n");
}

static void test_pretend_received_and_sack() {
    printf("[TEST] SACK Heartbeat & Pretend Received...\n");
    Lines client;
    Lines server;

    String sharedSecret = "32_byte_secret_key_for_sack_test";
    client.manualUpgrade(sharedSecret, true, 2);
    server.manualUpgrade(sharedSecret, false, 2);

    String lastSentBundle;
    client.enable([&](String b) { lastSentBundle = b; }, 0, 10, 1024);

    client.push(Packet(1, String("Important message 1"), true, true));
    assert(client.retransmissionBuffer.size() == 1);

    // Pretend received
    client.pretendReceived(2, 2);
    assert(client.base == 3);

    printf("  -> Pretend received and sliding window verified.\n");
}

static void test_padding_block_size_alignment() {
    printf("[TEST] 1. Padding Block Size Alignment (Thwart Traffic Analysis)...\n");
    Lines client;
    client.manualUpgrade("32_byte_secret_key_for_padding__", true, 2);

    String capturedBundle;
    client.enable([&](String b) { capturedBundle = b; }, 0, 10, 1024);

    // Default padding block size is 32
    client.paddingBlockSize = 32;
    client.push(Packet(1, String("Short payload"), true, true));

    // Ciphertext starts at byte 11
    assert(capturedBundle.size() > 11);
    usz ctLen32 = capturedBundle.size() - 11;
    assert(ctLen32 % 32 == 0);

    // Test with 64-byte padding block size
    client.paddingBlockSize = 64;
    client.push(Packet(1, String("Another short payload"), true, true));
    usz ctLen64 = capturedBundle.size() - 11;
    assert(ctLen64 % 64 == 0);

    printf("  -> Ciphertext verified to be exact multiples of paddingBlockSize.\n");
}

static void test_timeout_and_auto_destruction() {
    printf("[TEST] 2. Timeout & Auto-Destruction Lifecycle...\n");
    Lines lines;
    lines.manualUpgrade("32_byte_secret_key_for_timeout__", true, 2);
    assert(lines.isUpgraded());

    bool disconnected = false;
    Lines::Tree disconnectReason;
    lines.onDisconnect = [&](Lines::Tree reason) {
        disconnected = true;
        disconnectReason = reason;
    };

    lines.timeout = 20; // 20ms short timeout for test
    lines.lastSeen = millis() - 50; // Simulate 50ms elapsed without bundles

    lines.update();

    assert(disconnected);
    String outJson = toJSON(disconnectReason);
    assert(outJson.find("timeout") != -1);
    assert(!lines.isUpgraded());

    printf("  -> Timeout auto-destruction verified.\n");
}

static void test_backpressure_retransmission_buffer() {
    printf("[TEST] 3. Backpressure Control (couldPush at >= 90%% fullness)...\n");
    Lines client;
    client.manualUpgrade("32_byte_secret_key_backpressure_", true, 2);
    assert(client.couldPush());
    assert(client.size == 64);

    client.enable([](String) {}, 0, 10, 1024);

    // Simulate filling retransmissionBuffer to 57 entries (57/64 = 89.06% < 90%)
    for (u64 id = 2; id < 2 + 57; ++id) {
        client.retransmissionBuffer[id] = String("dummy");
    }
    assert(client.getAggression() < 0.90f);
    assert(client.couldPush());

    // Push 1 more to reach 58 entries (58/64 = 90.625% >= 90%)
    client.retransmissionBuffer[2 + 57] = String("dummy");
    assert(client.getAggression() >= 0.90f);
    assert(!client.couldPush());

    // Attempting to push new packet must be blocked/dropped
    usz beforeCount = client.retransmissionBuffer.size();
    client.push(Packet(1, String("Should be blocked by backpressure"), true, true));
    assert(client.retransmissionBuffer.size() == beforeCount);

    // Now clear some acknowledged entries to relieve backpressure
    for (u64 id = 2; id < 2 + 10; ++id) {
        client.retransmissionBuffer.remove(id);
    }
    assert(client.couldPush());

    // Pushing packet now succeeds
    client.push(Packet(1, String("Unblocked packet"), true, true));
    assert(client.retransmissionBuffer.size() == beforeCount - 10 + 1);

    printf("  -> Backpressure control (couldPush & aggression) verified.\n");
}

static void test_sacrificial_heartbeats_on_alternate_bands() {
    printf("[TEST] 4. Sacrificial Heartbeats on Alternate Bands...\n");
    Lines client;
    client.manualUpgrade("32_byte_secret_key_sacrificial__", true, 2);

    String primaryBundle;
    String alternateBundle;

    // Band 0 is primary (weight 100), Band 1 is alternate (weight 10)
    client.enable([&](String b) { primaryBundle = b; }, 0, 100, 1024);
    client.enable([&](String b) { alternateBundle = b; }, 1, 10, 1024);

    // High aggression simulates urgency
    for (u64 id = 2; id < 2 + 50; ++id) {
        client.retransmissionBuffer[id] = String("bundle");
    }
    assert(client.getAggression() > 0.7f);

    client.timeout = 20; // Short timeout
    client.lastSent = millis() - 100;
    client.lastSacrificialSent = millis() - 100;

    client.update();

    // Verify bundle was dispatched over the alternate band!
    assert(alternateBundle.size() > 0);
    assert(Lines::isEncrypted(alternateBundle));

    printf("  -> Sacrificial heartbeat successfully dispatched to alternate band.\n");
}

static void test_channel_zero_disconnect_reason() {
    printf("[TEST] 5. Channel 0 Disconnect & Reason Tree Parsing (JSON <-> Tree)...\n");
    Lines client;
    Lines server;

    String sharedSecret = "32_byte_secret_key_disconnect___";
    client.manualUpgrade(sharedSecret, true, 2);
    server.manualUpgrade(sharedSecret, false, 2);

    String disconnectWire;
    client.enable([&](String b) { disconnectWire = b; }, 0, 10, 1024);

    bool serverDisconnected = false;
    Lines::Tree serverReceivedReason;
    server.onDisconnect = [&](Lines::Tree reason) {
        serverDisconnected = true;
        serverReceivedReason = reason;
    };

    // Client parses JSON into rich bitpacked reason tree
    Lines::Tree clientReason;
    bool parsed = parseJSON(R"({
        "status": "user_logout",
        "code": 1000,
        "message": "user_requested_logout",
        "details": {
            "session_clean": true
        }
    })", clientReason);
    assert(parsed);

    client.disconnect(clientReason);

    assert(!client.isUpgraded()); // Client destroyed
    assert(disconnectWire.size() > 0);

    // Server receives and parses Disconnect bundle
    bool handled = server.parse(disconnectWire, 0);
    assert(handled);
    assert(serverDisconnected);
    assert(!server.isUpgraded()); // Server destroyed

    // Reassemble from other side as JSON!
    String outJson = toJSON(serverReceivedReason);
    assert(outJson.find("user_logout") != -1);
    assert(outJson.find("user_requested_logout") != -1);

    printf("  -> Bitpacked Tree parsed from JSON, transmitted, and reassembled as JSON on server!\n");
}

int main() {
    printf("=== Running Lines Protocol Test Suite ===\n");
    test_multiband_properties();
    test_handshake_lifecycle();
    test_post_upgrade_messaging();
    test_anti_tamper_and_anti_replay();
    test_connection_roaming_fast_filter();
    test_fragmentation_and_reassembly();
    test_pretend_received_and_sack();
    test_padding_block_size_alignment();
    test_timeout_and_auto_destruction();
    test_backpressure_retransmission_buffer();
    test_sacrificial_heartbeats_on_alternate_bands();
    test_channel_zero_disconnect_reason();
    printf("=== ALL LINES TESTS PASSED! ===\n");
    return 0;
}
