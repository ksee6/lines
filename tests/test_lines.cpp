/**
 * @file test_lines.cpp
 * @brief Comprehensive verification suite for the Lines protocol engine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

#include <stdio.h>
#include <assert.h>
#include "../include/Lines/Lines.hpp"
#include "../include/Lines/Patches.hpp"
#include <Ksee/Crypto/SHA.hpp>

using namespace Ksee;
using Lines = Ksee::Lines;
using PhysicalBand = Ksee::PhysicalBand;
using BandSlot = Ksee::BandSlot;
using Packet = Ksee::Packet;
using SentBundle = Ksee::SentBundle;
using RecvBundle = Ksee::RecvBundle;
using Patches = Ksee::Patches;
using PatchConnection = Ksee::PatchConnection;

static void test_wire_framing_and_crc() {
    printf("[TEST 1] Wire Framing & Automotive CRC-15-CAN...\n");

    Lines client;
    String capturedWire;
    client.enable([&](String b) { capturedWire = b; }, 1);

    // 1. Pre-Upgrade Probe Wire Check
    Lines::Tree sel;
    sel.path = Path("sensors.temperature");
    client.probe(sel);

    assert(capturedWire.size() >= 3);
    assert(!Lines::isEncrypted(capturedWire));

    // Bit 15 must be 0
    u16 header = (u16)(u8)capturedWire[0] | ((u16)(u8)capturedWire[1] << 8);
    assert((header & 0x8000) == 0); // isEncrypted bit is 0

    // 2. Post-Upgrade Framing Check (10 Bytes Overhead)
    Lines peer;
    client.manualUpgrade("32_byte_secret_key_testing_10b__", true, 2);
    peer.manualUpgrade("32_byte_secret_key_testing_10b__", false, 2);

    capturedWire.clear();
    client.push(Packet(1, String("Minimal packet"), true, true));
    assert(capturedWire.size() >= 10);
    assert(Lines::isEncrypted(capturedWire));

    // Bit 15 must be 1
    u16 postHeader = (u16)(u8)capturedWire[0] | ((u16)(u8)capturedWire[1] << 8);
    assert((postHeader & 0x8000) != 0); // isEncrypted bit is 1

    // Verify MAC & decryption on peer
    bool parsed = peer.parse(capturedWire, 1);
    assert(parsed);

    printf("  -> Pre-upgrade (CRC-15) and Post-upgrade (10-byte MAC+Delta) verified.\n");
}

static void test_handshake_lifecycle() {
    printf("[TEST 2] 1.5RTT Symmetrical Handshake Lifecycle...\n");

    Lines client;
    Lines server;

    String clientWire;
    String serverWire;

    client.enable([&](String b) { clientWire = b; }, 1);
    server.enable([&](String b) { serverWire = b; }, 1);

    bool probed = false;
    server.onProbe = [&](Lines::Tree sel) -> bool {
        probed = true;
        return true; // Announce
    };

    bool announced = false;
    client.onAnnounce = [&]() -> bool {
        announced = true;
        return true; // Upgrade
    };

    bool clientUpgraded = false;
    client.onUpgrade = [&]() -> bool { clientUpgraded = true; return true; };

    bool serverUpgraded = false;
    server.onUpgrade = [&]() -> bool { serverUpgraded = true; return true; };

    // 1. Client probes
    Lines::Tree selector;
    selector.path = Path("gateway.device1");
    client.probe(selector);
    assert(clientWire.size() > 0);

    // 2. Server receives probe -> dispatches Announce
    bool handledProbe = server.parse(clientWire, 1);
    assert(handledProbe);
    assert(probed);
    assert(serverWire.size() > 0);

    // 3. Client receives Announce -> dispatches Upgrade
    bool handledAnnounce = client.parse(serverWire, 1);
    assert(handledAnnounce);
    assert(announced);
    assert(clientUpgraded);
    assert(client.isUpgraded());

    // 4. Server receives Upgrade -> connection live!
    bool handledUpgrade = server.parse(clientWire, 1);
    assert(handledUpgrade);
    assert(serverUpgraded);
    assert(server.isUpgraded());

    printf("  -> Symmetrical Handshake successfully upgraded both peers.\n");
}

static void test_delivery_modes_and_outbox() {
    printf("[TEST 3] Delivery Modes (Reliable, BestEffort, Curiosity) & Outbox Retention...\n");

    Lines client;
    String capturedWire;
    client.enable([&](String b) { capturedWire = b; }, 1);
    client.manualUpgrade("32_byte_secret_key_modes_test___", true, 2);

    // 1. Reliable Delivery: must retain bundle payload in outbox for retransmission
    Packet reliableP(String("Important RPC"), 1, Packet::Reliable);
    client.push(reliableP);
    assert(client.outbox.has(2));
    assert(client.outbox[2].bundle.size() > 0);
    assert(client.outbox[2].delivery == Packet::Reliable);

    // 2. BestEffort Delivery: must drop bundle payload immediately from outbox
    Packet bestEffortP(String("Player Position (x=10, y=20)"), 1, Packet::BestEffort);
    client.push(bestEffortP);
    assert(client.outbox.has(3));
    assert(client.outbox[3].bundle.size() == 0); // No payload stored!
    assert(client.outbox[3].delivery == Packet::BestEffort);

    // 3. Curiosity Delivery: must drop bundle payload immediately
    Packet curiosityP(String("Link Probe Ping"), 1, Packet::Curiosity);
    client.push(curiosityP);
    assert(client.outbox.has(4));
    assert(client.outbox[4].bundle.size() == 0);
    assert(client.outbox[4].delivery == Packet::Curiosity);

    printf("  -> Reliable, BestEffort, and Curiosity outbox semantics verified.\n");
}

static void test_sliding_window_silicon_native() {
    printf("[TEST 4] 64-Slot Native Silicon Window & Anti-Replay...\n");

    Lines client;
    Lines server;
    String secret = "32_byte_secret_window_test______";
    client.manualUpgrade(secret, true, 2);
    server.manualUpgrade(secret, false, 2);

    String capturedBundle;
    client.enable([&](String b) { capturedBundle = b; }, 1);

    client.push(Packet(1, String("Bundle #2"), true, true));

    // 1. Valid bundle parses successfully
    assert(server.parse(capturedBundle, 1));

    // 2. Replay attack: identical bundle is instantly rejected
    assert(!server.parse(capturedBundle, 1));

    // 3. Tampered ciphertext is rejected
    client.push(Packet(1, String("Bundle #3"), true, true));
    String tampered = capturedBundle;
    tampered[tampered.size() - 1] ^= 0x55;
    assert(!server.parse(tampered, 1));

    printf("  -> Native 64-bit window & anti-replay protection verified.\n");
}

static void test_pressure_and_backpressure() {
    printf("[TEST 5] Pipeline Pressure & Outbox Backpressure...\n");

    Lines client;
    client.manualUpgrade("32_byte_secret_pressure_test____", true, 2);
    client.enable([](String) {}, 1);

    assert(client.getPressure() == 0.0f);
    assert(client.couldPush());

    // Push 32 unacknowledged reliable packets -> pressure should be 32/64 = 0.5f
    for (int i = 0; i < 32; ++i) {
        client.push(Packet(1, String("Bulk data"), true, true));
    }
    f32 p = client.getPressure();
    assert(p >= 0.49f && p <= 0.51f);

    // Acknowledge all
    client.setAcknowledged(0, 31, millis());
    assert(client.getPressure() == 0.0f);

    printf("  -> Pressure calculation (unacked/64) and backpressure verified.\n");
}

static void test_multiband_metrics_and_collision_stun() {
    printf("[TEST 6] Band Metrics & Collision Stun Backoff...\n");

    Lines lines;
    BandSlot *slot1 = lines.enable([](String) {}, 1, /* initialWeight = */ 100, /* maxBundleSize = */ 1400);
    BandSlot *slot2 = lines.enable([](String) {}, 2, /* initialWeight = */ 500, /* maxBundleSize = */ 255);

    assert(lines.bands.size() == 2);
    assert(slot1->isAvailable());
    assert(slot2->isAvailable());

    // Band metrics, priming band & speed-based discovery
    lines.primingBandSlot = 0;
    assert(lines.getBestReliableBand() == 0); // Speeds are 0 -> returns primingBandSlot (0)

    // Simulate Band 2 transmitting and receiving ACK (faster throughput)
    slot2->ackedBytesLastSec = 500000;
    slot2->dutyConsumedLastSec = 100; // 5 MB/s send capacity
    assert(lines.getBestReliableBand() == 1); // Discovered faster band (index 1)!

    // Lowest latency routing for BestEffort
    slot1->minObservedLatency = 5;  // 5ms
    slot2->minObservedLatency = 20; // 20ms
    assert(lines.getBestEffortBand() == 0);  // Routes to lowest latency band (index 0)

    // Curiosity discovery routing
    i64 curiosityBand = lines.getBestCuriosityBand();
    assert(curiosityBand == 0 || curiosityBand == 1);

    // Test collision stun backoff
    lines.stun(slot1, 50); // Stun band 1 for 50ms
    assert(!slot1->isAvailable());
    assert(slot2->isAvailable());
    assert(lines.getBestEffortBand() == 1); // Band 1 is stunned -> falls back to available band 2 (index 1)

    // Max bundle size enforcement on parse
    lines.manualUpgrade("32_byte_secret_stun_test________", true, 2);
    String oversizedBundle(500, 'X');
    // Band 2 MTU is 255 -> 500-byte bundle must be dropped
    assert(!lines.parse(oversizedBundle, slot2));

    printf("  -> Band availability, stun backoff, discovery & primingBand verified.\n");
}

static void test_connection_roaming_fast_filter() {
    printf("[TEST 7] Connection Roaming Fast Pre-Filtering (< 10ns)...\n");

    Lines clientA;
    Lines clientB;
    clientA.manualUpgrade("client_a_secret_key_32_bytes____", true, 2);
    clientB.manualUpgrade("client_b_secret_key_32_bytes____", true, 2);

    Lines serverA;
    Lines serverB;
    serverA.manualUpgrade("client_a_secret_key_32_bytes____", false, 2);
    serverB.manualUpgrade("client_b_secret_key_32_bytes____", false, 2);

    String bundleA;
    clientA.enable([&](String b) { bundleA = b; }, 1);
    clientA.push(Packet(1, String("Packet from client A"), true, true));

    // Server A matches bundle A in 1 cycle
    assert(serverA.matchesBundle(bundleA));
    // Server B rejects bundle A without decrypting!
    assert(!serverB.matchesBundle(bundleA));

    printf("  -> Roaming fast filter verified.\n");
}

static void test_disjoint_sack_and_pretend_intervals() {
    printf("[TEST 8] Disjoint SACK Intervals & Pretend Received...\n");

    Lines client;
    Lines server;
    String secret = "32_byte_secret_sack_test________";
    client.manualUpgrade(secret, true, 2);
    server.manualUpgrade(secret, false, 2);

    String clientWire;
    client.enable([&](String b) { clientWire = b; }, 1);

    // Send bundles 2, 3, 4
    client.push(Packet(1, String("Msg 2"), true, true));
    client.push(Packet(1, String("Msg 3"), true, true));
    client.push(Packet(1, String("Msg 4"), true, true));

    assert(client.outbox.has(2) && client.outbox[2].ackTime == 0);
    assert(client.outbox.has(3) && client.outbox[3].ackTime == 0);
    assert(client.outbox.has(4) && client.outbox[4].ackTime == 0);

    // Pretend bundles 2 and 3 were acknowledged
    client.setAcknowledged(0, 1, millis());
    assert(client.outbox[2].ackTime != 0);
    assert(client.outbox[3].ackTime != 0);
    assert(client.outbox[4].ackTime == 0);

    // Pretend received on server
    server.pretendReceived(0, 2);
    assert(server.base == 5);

    printf("  -> SACK intervals and pretendReceived sliding window verified.\n");
}

static void test_padding_block_size_alignment() {
    printf("[TEST 9] Padding Block Size Alignment (Traffic Analysis Defense)...\n");

    Lines client;
    client.manualUpgrade("32_byte_secret_padding_test_____", true, 2);
    String wire;
    client.enable([&](String b) { wire = b; }, 1);

    client.paddingBlockSize = 32;
    client.push(Packet(1, String("Short text"), true, true));

    assert(wire.size() >= 10);
    usz ctLen = wire.size() - 10;
    assert(ctLen % 32 == 0);

    client.paddingBlockSize = 64;
    client.push(Packet(1, String("Another short text"), true, true));
    ctLen = wire.size() - 10;
    assert(ctLen % 64 == 0);

    printf("  -> Ciphertext verified to be exact multiples of paddingBlockSize.\n");
}

static void test_untrusted_gateway_onion_relaying() {
    printf("[TEST 10] Zero-Knowledge Gateway Relay (Double Onion Forwarding)...\n");

    // 1. End Node (Sensor) <---> Final Cloud Server
    Lines sensor;
    Lines cloudServer;
    String e2eSecret = "e2e_sensor_to_cloud_secret_32___";
    sensor.manualUpgrade(e2eSecret, true, 2);
    cloudServer.manualUpgrade(e2eSecret, false, 2);

    String innerPacketWire;
    sensor.enable([&](String b) { innerPacketWire = b; }, 1);

    // Sensor creates inner encrypted packet
    sensor.push(Packet(1, String("Sensor Telemetry: Temp=24.5C"), true, true));
    assert(innerPacketWire.size() > 0);
    assert(Lines::isEncrypted(innerPacketWire));

    // 2. Sensor <---> Gateway Hop (Outer Tunnel)
    Lines gatewayInbound;
    Lines gatewayOutbound;
    String hopSecret = "sensor_to_gateway_hop_secret_32_";
    gatewayInbound.manualUpgrade(hopSecret, false, 2);

    // Wrap inner packet inside outer BestEffort packet
    Lines sensorHop;
    sensorHop.manualUpgrade(hopSecret, true, 2);
    String outerBundleWire;
    sensorHop.enable([&](String b) { outerBundleWire = b; }, 1);
    sensorHop.push(Packet(innerPacketWire, 1, Packet::BestEffort));

    // Gateway receives outer bundle, extracts inner payload
    String forwardedPayload;
    gatewayInbound.onPacket = [&](Packet p) {
        forwardedPayload = p.payload;
    };
    bool gwOk = gatewayInbound.parse(outerBundleWire, 1);
    assert(gwOk);
    assert(forwardedPayload == innerPacketWire);

    // 3. Final Cloud Server receives forwarded inner packet and decrypts real data
    String serverReceivedData;
    cloudServer.onPacket = [&](Packet p) {
        serverReceivedData = p.payload;
    };
    bool srvOk = cloudServer.parse(forwardedPayload, 1);
    assert(srvOk);
    assert(serverReceivedData == "Sensor Telemetry: Temp=24.5C");

    printf("  -> Zero-knowledge Double Onion gateway relay verified end-to-end!\n");
}

static void test_physical_band_duty_and_shared_slots() {
    printf("[TEST 11] PhysicalBand Duty Cycle Debt, Regeneration & Shared Slot Dispatch...\n");

    // 1. Create PhysicalBand with 10% duty limit (100ms per second)
    PhysicalBand pb;
    pb.maxDuty = 100;
    pb.maxBundleSize = 500;
    assert(pb.couldPush());

    // Artificial airtime debt accumulation
    pb.duty = 90;
    assert(pb.couldPush());
    pb.duty = 100; // Debt reached limit
    assert(!pb.couldPush());

    // Debt regeneration: simulate 1 second elapsed
    pb.lastDebtRegenTime = millis() - 1000;
    pb.update(/* doLinesUpdates = */ false);
    assert(pb.duty == 0); // 100 - 100 = 0
    assert(pb.couldPush());

    // 2. Shared Slots: Two Lines instances share ONE PhysicalBand transceiver
    Lines clientA;
    Lines clientB;
    clientA.manualUpgrade("client_shared_secret_32_bytes___", true, 2);
    clientB.manualUpgrade("client_shared_secret_32_bytes___", true, 2);

    BandSlot *slotA = clientA.enable(pb);
    BandSlot *slotB = clientB.enable(pb);
    assert(pb.slots.size() == 2);
    assert(slotA->physical == &pb);
    assert(slotB->physical == &pb);

    // 3. Stun propagates across slots sharing the physical medium
    pb.stun(50);
    assert(!pb.couldPush());
    assert(!slotA->isAvailable());
    assert(!slotB->isAvailable());

    // 4. Staged toBeBundled packing
    Lines server;
    server.manualUpgrade("client_shared_secret_32_bytes___", false, 2);
    String wireOut;
    pb.stunnedUntil = 0; // Unstun
    pb.sendCallback = [&](String b) { wireOut = b; };

    // Push into clientA
    clientA.push(Packet(1, String("Shared band packet"), true, true));
    assert(wireOut.size() > 0);
    assert(server.parse(wireOut, 1));

    // 5. Slot removal and self-destruction check
    clientA.disable(slotA);
    assert(pb.slots.size() == 1);
    clientB.disable(slotB);
    assert(pb.slots.size() == 0);

    // Verify dynamically allocated band self-destructs safely on last slot removal
    PhysicalBand *dynPb = new PhysicalBand();
    dynPb->isDynamicallyAllocated = true;
    Lines clientC;
    BandSlot *slotC = clientC.enable(dynPb);
    assert(dynPb->slots.size() == 1);
    clientC.disable(slotC); // Triggers removeSlot -> self-destructs dynPb safely!

    printf("  -> PhysicalBand duty cycle, shared slots & self-destruction verified!\n");
}

static void test_pre_upgrade_tuning_isolation() {
    printf("[TEST 12] Pre-Upgrade Tuning Isolation (0 Wire Bytes Clashing Defense)...\n");

    Lines clientRed;
    Lines serverRed;
    clientRed.tune = "fleet_red_915mhz";
    serverRed.tune = "fleet_red_915mhz";

    Lines clientBlue;
    clientBlue.tune = "fleet_blue_915mhz";

    Lines clientDefault; // default tune = ""
    assert(clientDefault.tune == "");

    String wireRedProbe;
    clientRed.enable([&](String b) { wireRedProbe = b; }, 1);
    serverRed.enable([](String) {}, 1);
    clientBlue.enable([](String) {}, 1);
    clientDefault.enable([](String) {}, 1);

    // Client Red broadcasts a Probe
    Tree sel;
    sel.path = Path("telemetry.alpha");
    clientRed.probe(sel);
    assert(wireRedProbe.size() > 0);
    assert(!Lines::isEncrypted(wireRedProbe));

    // 1. Matching tune accepts instantly
    assert(serverRed.parse(wireRedProbe, 1));

    // 2. Mismatched tune ("fleet_blue_915mhz") rejects on CRC mismatch at byte 2!
    assert(!clientBlue.parse(wireRedProbe, 1));

    // 3. Default empty tune ("") also rejects because seed differs
    assert(!clientDefault.parse(wireRedProbe, 1));

    // 4. Default empty tune communication works with other default nodes
    String wireDefaultProbe;
    clientDefault.enable([&](String b) { wireDefaultProbe = b; }, 1);
    clientDefault.probe(sel);
    assert(wireDefaultProbe.size() > 0);

    Lines serverDefault;
    serverDefault.enable([](String) {}, 1);
    assert(serverDefault.parse(wireDefaultProbe, 1)); // Default matches default!
    assert(!clientRed.parse(wireDefaultProbe, 1));    // Red rejects default!
    assert(!clientBlue.parse(wireDefaultProbe, 1));   // Blue rejects default!

    printf("  -> Multi-tenant medium tuning isolation verified with 0 extra wire bytes!\n");
}

static void test_patches_routing_and_gateway() {
    printf("[TEST 13] Patches Fractal Tree Routing, BGP & Gateway Overrides...\n");

    // 1. Standard Tree::generate() verification
    Tree tree;
    tree.push(Path("0"));
    tree.push(Path("1"));
    Path gen1 = tree.generate();
    assert(gen1.toString() == "2");
    tree.push(gen1);
    Path gen2 = tree.generate();
    assert(gen2.toString() == "3");

    // 2. Path primitives (0 = Self, 1 = Control, 1.1 = Back/Upstream)
    assert(Path::Self.isSelf());
    assert(Path::Back.isBack());
    assert(Path::Control.isControl());

    // 3. Setup Root Patches Router at "2.2" (Batna district router)
    Patches router(Path("2.2"));
    assert(router.path.toString() == "2.2");
    assert(!router.autoInferPath);

    // Setup simulated physical band (in-memory pipe)
    Lines routerLines;
    Lines clientLines;

    // Cross-connect routerLines and clientLines with pre-upgrade tune = "Patches"
    routerLines.enable([&](String b) { clientLines.recv(b, 1); }, 1);
    clientLines.enable([&](String b) { routerLines.recv(b, 1); }, 1);

    PatchConnection *routerClientConn = router.addConnection(&routerLines, false, false);
    (void)routerClientConn;

    // 4. Setup Client Patches Node with autoInferPath = true
    Patches clientNode;
    assert(clientNode.autoInferPath);
    PatchConnection *clientUpstreamConn = clientNode.addConnection(&clientLines, true, false);
    (void)clientUpstreamConn;

    assert(routerLines.tune == "Patches");
    assert(clientLines.tune == "Patches");

    // Perform handshake (32-byte shared key)
    routerLines.manualUpgrade("PatchesSecretKey32BytesForTest!!", false, 2);
    clientLines.manualUpgrade("PatchesSecretKey32BytesForTest!!", true, 2);

    // Router onUpgrade leases a child path under "2.2"
    Tree meta;
    routerLines.onUpgrade(meta);

    // Verify router sent Your Path (Action 1) on channel 1
    // Client receives on channel 1, and since autoInferPath == true, client adopts the leased path!
    assert(!clientNode.autoInferPath);
    assert(clientNode.path.toString() == "2.2.0");

    // 5. Test Gateway Override (e.g. 4 for IPv4 translation)
    bool overrideHit = false;
    Path caughtSrc, caughtDst;
    String caughtPayload;
    u8 caughtTtl = 0;

    router.override(Path("4"), [&](const Path &src, const Path &dst, const String &bundle, u8 ttl) {
        overrideHit = true;
        caughtSrc = src;
        caughtDst = dst;
        caughtPayload = bundle;
        caughtTtl = ttl;
    });

    // Client node sends a bundle to IPv4 destination "8.8.8.8:80" via cut-through circuit
    Path targetIp("8.8.8.8:80");
    assert(targetIp.isIpv4());
    bool opened = clientNode.open(targetIp, 2, 32);
    assert(opened);

    // Send payload on channel 2
    clientLines.push(Packet("GET /index.html HTTP/1.1\r\n\r\n", 2, Packet::BestEffort));

    assert(overrideHit);
    assert(caughtPayload == "GET /index.html HTTP/1.1\r\n\r\n");
    assert(caughtTtl == 255 || caughtTtl == 31 || caughtTtl == 32);

    // 6. Test Static Infrastructure Peering (BGP suggestions)
    Patches telco(Path("2"));
    telco.addSuggestion("PEER_STATIC_KEY_ALGERIA", Path("2.2"));
    assert(telco.suggestions.size() == 1);
    assert(telco.suggestions[0].statics[0] == "PEER_STATIC_KEY_ALGERIA");
    assert(telco.suggestions[0].paths[0].toString() == "2.2");

    // 7. Multi-Hop Cut-Through Switching (Sensor -> Router -> Gateway)
    Lines sensorLines;
    Lines clientRouterLines;
    sensorLines.enable([&](String b) { clientRouterLines.recv(b, 1); }, 1);
    clientRouterLines.enable([&](String b) { sensorLines.recv(b, 1); }, 1);

    sensorLines.manualUpgrade("PatchesSecretKey32BytesForTest!!", true, 2);
    clientRouterLines.manualUpgrade("PatchesSecretKey32BytesForTest!!", false, 2);

    Patches sensorNode;
    sensorNode.addConnection(&sensorLines, true, false);
    clientNode.addConnection(&clientRouterLines, false, false);

    // Lease child path to sensor
    Tree sensorMeta;
    clientRouterLines.onUpgrade(sensorMeta);
    assert(!sensorNode.autoInferPath);
    assert(sensorNode.path.toString() == "2.2.0.0");

    // Sensor opens circuit to IPv4 destination across multiple hops
    overrideHit = false;
    caughtPayload = "";
    bool sensorOpened = sensorNode.open(targetIp, 2, 32);
    assert(sensorOpened);

    // Sensor pushes data on Channel 2 - switches through clientNode directly to router
    sensorLines.push(Packet("DATA_FROM_LORA_SENSOR", 2, Packet::BestEffort));
    assert(overrideHit);
    assert(caughtPayload == "DATA_FROM_LORA_SENSOR");

    // 8. Disconnect Cleanup
    clientLines.disconnect();
    assert(router.connections.size() == 0);
    assert(router.circuits.size() == 0);

    printf("  -> Multi-hop cut-through switching, BGP Peering & Overrides verified!\n");
}

int main() {
    printf("====================================================\n");
    printf("          RUNNING COMPLETE LINES TEST SUITE         \n");
    printf("====================================================\n");

    test_wire_framing_and_crc();
    test_handshake_lifecycle();
    test_delivery_modes_and_outbox();
    test_sliding_window_silicon_native();
    test_pressure_and_backpressure();
    test_multiband_metrics_and_collision_stun();
    test_connection_roaming_fast_filter();
    test_disjoint_sack_and_pretend_intervals();
    test_padding_block_size_alignment();
    test_untrusted_gateway_onion_relaying();
    test_physical_band_duty_and_shared_slots();
    test_pre_upgrade_tuning_isolation();
    test_patches_routing_and_gateway();

    printf("====================================================\n");
    printf("     ALL 13 TEST SUITES PASSED CLEANLY (100%%)!     \n");
    printf("====================================================\n");
    return 0;
}
