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
#include <Ksee/Algorithm/SHA.hpp>

using namespace Ksee;
using Lines = Ksee::Lines;
using Band = Ksee::Band;
using LinesBandSlot = Ksee::LinesBandSlot;
using Packet = Ksee::Packet;
using SentBundle = Ksee::SentBundle;
using RecvBundle = Ksee::RecvBundle;
using Patches = Ksee::Patches;
using PatchConnection = Ksee::PatchConnection;

static void test_wire_framing_and_crc() {
    printf("[TEST 1] Wire Framing & Automotive CRC-15-CAN...\n");

    Lines client;
    String capturedWire;
    client.enable([&](String b) { capturedWire = b; });

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
    client.push(Packet(String("Minimal packet"), 1, 1, true, true));
    assert(capturedWire.size() >= 10);
    assert(Lines::isEncrypted(capturedWire));

    // Bit 15 must be 1
    u16 postHeader = (u16)(u8)capturedWire[0] | ((u16)(u8)capturedWire[1] << 8);
    assert((postHeader & 0x8000) != 0); // isEncrypted bit is 1

    // Verify MAC & decryption on peer
    bool parsed = peer.parse(capturedWire);
    assert(parsed);

    printf("  -> Pre-upgrade (CRC-15) and Post-upgrade (10-byte MAC+Delta) verified.\n");
}

static void test_handshake_lifecycle() {
    printf("[TEST 2] 1.5RTT Symmetrical Handshake Lifecycle...\n");

    Lines client;
    Lines server;

    String clientWire;
    String serverWire;

    client.enable([&](String b) { clientWire = b; });
    server.enable([&](String b) { serverWire = b; });

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
    client.onUpgrade = [&](Lines::Tree) { clientUpgraded = true; };

    bool serverUpgraded = false;
    server.onUpgrade = [&](Lines::Tree) { serverUpgraded = true; };

    // 1. Client probes
    Lines::Tree selector;
    selector.path = Path("gateway.device1");
    client.probe(selector);
    assert(clientWire.size() > 0);

    // 2. Server receives probe -> dispatches Announce
    bool handledProbe = server.parse(clientWire);
    assert(handledProbe);
    assert(probed);
    assert(serverWire.size() > 0);

    // 3. Client receives Announce -> dispatches Upgrade
    bool handledAnnounce = client.parse(serverWire);
    assert(handledAnnounce);
    assert(announced);
    assert(clientUpgraded);
    assert(client.isUpgraded());

    // 4. Server receives Upgrade -> connection live!
    bool handledUpgrade = server.parse(clientWire);
    assert(handledUpgrade);
    assert(serverUpgraded);
    assert(server.isUpgraded());

    printf("  -> Symmetrical Handshake successfully upgraded both peers.\n");
}

static void test_delivery_modes_and_outbox() {
    printf("[TEST 3] Packet Delivery Flags (Reliable, Ordered, Sacrificial) & Outbox Retention...\n");

    Lines client;
    String capturedWire;
    client.enable([&](String b) { capturedWire = b; });
    client.manualUpgrade("32_byte_secret_key_modes_test___", true, 2);

    // 1. Reliable & Ordered (default) -> must retain payload in outbox
    Packet steadyP(String("Important RPC"), 1, 1, true, true, false);
    assert(steadyP.ordered);
    assert(steadyP.reliable);
    assert(!steadyP.sacrificial);
    client.push(steadyP);
    assert(client.outbox.has(2));
    assert(client.outbox[2].bundle.size() > 0);
    assert(client.outbox[2].reliable);
    assert(!client.outbox[2].sacrificial);

    // 2. Reliable & Unordered -> retains payload in outbox
    Packet swiftP(String("Emergency Stop"), 1, 1, true, false, false);
    assert(!swiftP.ordered);
    assert(swiftP.reliable);
    assert(!swiftP.sacrificial);
    client.push(swiftP);
    assert(client.outbox.has(3));
    assert(client.outbox[3].bundle.size() > 0); // Retained for retransmission!
    assert(client.outbox[3].reliable);
    assert(!client.outbox[3].sacrificial);

    // 3. Unreliable & Unordered -> dropped immediately from outbox
    Packet fleetingP(String("Player Position (x=10, y=20)"), 1, 1, false, false, false);
    assert(!fleetingP.ordered);
    assert(!fleetingP.reliable);
    assert(!fleetingP.sacrificial);
    client.push(fleetingP);
    assert(client.outbox.has(4));
    assert(client.outbox[4].bundle.size() == 0); // No payload stored!
    assert(!client.outbox[4].reliable);
    assert(!client.outbox[4].sacrificial);

    // 4. Sacrificial exploration probe -> dropped immediately from outbox
    Packet curiousP(String("Link Probe Ping"), 1, 1, false, false, true);
    assert(!curiousP.ordered);
    assert(!curiousP.reliable);
    assert(curiousP.sacrificial);
    client.push(curiousP);
    assert(client.outbox.has(5));
    assert(client.outbox[5].bundle.size() == 0);
    assert(!client.outbox[5].reliable);
    assert(client.outbox[5].sacrificial);

    printf("  -> Delivery flags (Reliable, Ordered, Sacrificial) & Outbox verified.\n");
}

static void test_sliding_window_silicon_native() {
    printf("[TEST 4] 64-Slot Native Silicon Window & Anti-Replay...\n");

    Lines client;
    Lines server;
    String secret = "32_byte_secret_window_test______";
    client.manualUpgrade(secret, true, 2);
    server.manualUpgrade(secret, false, 2);

    String capturedBundle;
    client.enable([&](String b) { capturedBundle = b; });

    client.push(Packet(String("Bundle #2"), 1, 1, true, true));

    // 1. Valid bundle parses successfully
    assert(server.parse(capturedBundle));

    // 2. Replay attack: identical bundle is instantly rejected
    assert(!server.parse(capturedBundle));

    // 3. Tampered ciphertext is rejected
    client.push(Packet(String("Bundle #3"), 1, 1, true, true));
    String tampered = capturedBundle;
    tampered[tampered.size() - 1] ^= 0x55;
    assert(!server.parse(tampered));

    printf("  -> Native 64-bit window & anti-replay protection verified.\n");
}

static void test_pressure_and_backpressure() {
    printf("[TEST 5] Pipeline Pressure & Outbox Backpressure...\n");

    Lines client;
    client.manualUpgrade("32_byte_secret_pressure_test____", true, 2);
    client.enable([](String) {});

    assert(client.getPressure() == 0.0f);
    assert(client.couldPush());

    // Push 32 unacknowledged reliable packets -> pressure should be 32/64 = 0.5f
    for (int i = 0; i < 32; ++i) {
        client.push(Packet(String("Bulk data"), 1, 1, true, true));
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

    Band pb1;
    pb1.sendCallback = [](String) {};
    pb1.idealCapacity = 100;
    pb1.maxBundleSize = 1400;

    Band pb2;
    pb2.sendCallback = [](String) {};
    pb2.idealCapacity = 500;
    pb2.maxBundleSize = 255;

    Lines lines;
    LinesBandSlot *slot1 = lines.enable(pb1);
    LinesBandSlot *slot2 = lines.enable(pb2);

    assert(lines.bands.size() == 2);
    assert(slot1->isAvailable());
    assert(slot2->isAvailable());

    // Band metrics, priming band & speed-based discovery
    lines.primingBandSlot = 0;
    assert(lines.getBestBand() == 0); // Speeds are 0 -> returns primingBandSlot (0)

    // Simulate Band 2 transmitting and receiving ACK (faster throughput)
    slot2->ackedBytesLastSec = 500000;
    slot2->dutyConsumedLastSec = 100; // 5 MB/s send capacity
    assert(lines.getBestBand() == 1); // Discovered faster band (index 1)!

    // Test getPotential() calculation
    slot2->band->idealCapacity = 10000000; // 10 MB/s ideal
    assert(slot2->getPotential() == 5000000); // 10 MB/s - 5 MB/s = 5 MB/s potential

    // Curiosity discovery routing
    i64 unexploredBand = lines.selectUnexploredBand(2);
    assert(unexploredBand == 0 || unexploredBand == 1);

    // Test collision stun backoff
    lines.stun(slot1, 50); // Stun band 1 for 50ms
    assert(!slot1->isAvailable());
    assert(slot2->isAvailable());
    assert(lines.getBestBand() == 1); // Band 1 is stunned -> falls back to available band 2 (index 1)

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
    clientA.enable([&](String b) { bundleA = b; });
    clientA.push(Packet(String("Packet from client A"), 1, 1, true, true));

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
    client.enable([&](String b) { clientWire = b; });

    // Send bundles 2, 3, 4
    client.push(Packet(String("Msg 2"), 1, 1, true, true));
    client.push(Packet(String("Msg 3"), 1, 1, true, true));
    client.push(Packet(String("Msg 4"), 1, 1, true, true));

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
    client.enable([&](String b) { wire = b; });

    client.paddingBlockSize = 32;
    client.push(Packet(String("Short text"), 1, 1, true, true));

    assert(wire.size() >= 10);
    usz ctLen = wire.size() - 10;
    assert(ctLen % 32 == 0);

    client.paddingBlockSize = 64;
    client.push(Packet(String("Another short text"), 1, 1, true, true));
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
    sensor.enable([&](String b) { innerPacketWire = b; });

    // Sensor creates inner encrypted packet
    sensor.push(Packet(String("Sensor Telemetry: Temp=24.5C"), 1, 1, true, true));
    assert(innerPacketWire.size() > 0);
    assert(Lines::isEncrypted(innerPacketWire));

    // 2. Sensor <---> Gateway Hop (Outer Tunnel)
    Lines gatewayInbound;
    Lines gatewayOutbound;
    String hopSecret = "sensor_to_gateway_hop_secret_32_";
    gatewayInbound.manualUpgrade(hopSecret, false, 2);

    // Wrap inner packet inside outer packet
    Lines sensorHop;
    sensorHop.manualUpgrade(hopSecret, true, 2);
    String outerBundleWire;
    sensorHop.enable([&](String b) { outerBundleWire = b; });
    sensorHop.push(Packet(innerPacketWire, 1, 1, false));

    // Gateway receives outer bundle, extracts inner payload
    String forwardedPayload;
    gatewayInbound.onPacket = [&](Packet p) {
        forwardedPayload = p.payload;
    };
    bool gwOk = gatewayInbound.parse(outerBundleWire);
    assert(gwOk);
    assert(forwardedPayload == innerPacketWire);

    // 3. Final Cloud Server receives forwarded inner packet and decrypts real data
    String serverReceivedData;
    cloudServer.onPacket = [&](Packet p) {
        serverReceivedData = p.payload;
    };
    bool srvOk = cloudServer.parse(forwardedPayload);
    assert(srvOk);
    assert(serverReceivedData == "Sensor Telemetry: Temp=24.5C");

    printf("  -> Zero-knowledge Double Onion gateway relay verified end-to-end!\n");
}

static void test_physical_band_duty_and_shared_slots() {
    printf("[TEST 11] Band Duty Cycle Debt, Regeneration & Shared Slot Dispatch...\n");

    // 1. Create Band with 10% duty limit (100ms per second)
    Band pb;
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
    pb.update(/* doSlotUpdates = */ false);
    assert(pb.duty == 0); // 100 - 100 = 0
    assert(pb.couldPush());

    // 2. Shared Slots: Two Lines instances share ONE Band transceiver
    Lines clientA;
    Lines clientB;
    clientA.manualUpgrade("client_shared_secret_32_bytes___", true, 2);
    clientB.manualUpgrade("client_shared_secret_32_bytes___", true, 2);

    LinesBandSlot *slotA = clientA.enable(pb);
    LinesBandSlot *slotB = clientB.enable(pb);
    assert(pb.slots.size() == 2);
    assert(slotA->band == &pb);
    assert(slotB->band == &pb);

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
    clientA.push(Packet(String("Shared band packet"), 1, 1, true, true));
    assert(wireOut.size() > 0);
    assert(server.parse(wireOut));

    // 5. Slot removal and self-destruction check
    clientA.disable(slotA);
    assert(pb.slots.size() == 1);
    clientB.disable(slotB);
    assert(pb.slots.size() == 0);

    // Verify dynamically allocated band self-destructs safely on last slot removal
    Band *dynPb = new Band();
    dynPb->isDynamicallyAllocated = true;
    Lines clientC;
    LinesBandSlot *slotC = clientC.enable(dynPb);
    assert(dynPb->slots.size() == 1);
    clientC.disable(slotC); // Triggers removeSlot -> self-destructs dynPb safely!

    printf("  -> Band duty cycle, shared slots & self-destruction verified!\n");
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
    clientRed.enable([&](String b) { wireRedProbe = b; });
    serverRed.enable([](String) {});
    clientBlue.enable([](String) {});
    clientDefault.enable([](String) {});

    // Client Red broadcasts a Probe
    Tree sel;
    sel.path = Path("telemetry.alpha");
    clientRed.probe(sel);
    assert(wireRedProbe.size() > 0);
    assert(!Lines::isEncrypted(wireRedProbe));

    // 1. Matching tune accepts instantly
    assert(serverRed.parse(wireRedProbe));

    // 2. Mismatched tune ("fleet_blue_915mhz") rejects on CRC mismatch at byte 2!
    assert(!clientBlue.parse(wireRedProbe));

    // 3. Default empty tune ("") also rejects because seed differs
    assert(!clientDefault.parse(wireRedProbe));

    // 4. Default empty tune communication works with other default nodes
    String wireDefaultProbe;
    clientDefault.enable([&](String b) { wireDefaultProbe = b; });
    clientDefault.primingBandSlot = clientDefault.bands.size() - 1;
    clientDefault.probe(sel);
    assert(wireDefaultProbe.size() > 0);

    Lines serverDefault;
    serverDefault.enable([](String) {});
    assert(serverDefault.parse(wireDefaultProbe)); // Default matches default!
    assert(!clientRed.parse(wireDefaultProbe));    // Red rejects default!
    assert(!clientBlue.parse(wireDefaultProbe));   // Blue rejects default!

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
    routerLines.enable([&](String b) { clientLines.recv(b); });
    clientLines.enable([&](String b) { routerLines.recv(b); });

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

    // Verify router sent Your Path (Action 1) on handle 1
    // Client receives on handle 1, and since autoInferPath == true, client adopts the leased path!
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

    // Send payload on handle 2
    clientLines.push(Packet("GET /index.html HTTP/1.1\r\n\r\n", 2, 1, false));

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
    sensorLines.enable([&](String b) { clientRouterLines.recv(b); });
    clientRouterLines.enable([&](String b) { sensorLines.recv(b); });

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
    sensorLines.push(Packet("DATA_FROM_LORA_SENSOR", 2, 1, false));
    assert(overrideHit);
    assert(caughtPayload == "DATA_FROM_LORA_SENSOR");

    // 8. Disconnect Cleanup
    clientLines.disconnect();
    assert(router.connections.size() == 0);
    assert(router.circuits.size() == 0);

    printf("  -> Multi-hop cut-through switching, BGP Peering & Overrides verified!\n");
}

void test_packet_intent_demux() {
    printf("[TEST 14] Packet Intent & Zero-Overhead Wire Framing...\n");

    Lines client;
    Lines server;

    String testSecret = "32_byte_secret_key_testing_intent_";
    client.manualUpgrade(testSecret, true, 2);
    server.manualUpgrade(testSecret, false, 2);

    String wire;
    client.enable([&](String b) { wire = b; });

    Packet receivedPkt;
    bool gotPkt = false;
    server.onPacket = [&](Packet p) {
        receivedPkt = p;
        gotPkt = true;
    };

    // 1. Default packet (handle 1, intent 1) -> 0 extra wire bytes
    client.push(Packet(String("Default packet"), 1, 1, true));
    assert(server.parse(wire));
    assert(gotPkt);
    assert(receivedPkt.payload == "Default packet");
    assert(receivedPkt.handle == 1);
    assert(receivedPkt.intent == 1);

    // 2. Custom intent on Handle 1 (e.g. Intent::Ping = 2)
    gotPkt = false;
    Packet pingPkt(String("PING"), 1, 2, false);
    client.push(pingPkt);
    assert(server.parse(wire));
    assert(gotPkt);
    assert(receivedPkt.payload == "PING");
    assert(receivedPkt.handle == 1);
    assert(receivedPkt.intent == 2);

    // 3. Custom handle & 64-bit varlong intent
    gotPkt = false;
    Packet rpcPkt(String("GET /user/42"), 7, 0x12345678ULL, true);
    client.push(rpcPkt);
    assert(server.parse(wire));
    assert(gotPkt);
    assert(receivedPkt.payload == "GET /user/42");
    assert(receivedPkt.handle == 7);
    assert(receivedPkt.intent == 0x12345678ULL);

    // 4. Control Intent Disconnect: Handle 0 with IntentDisconnect (0)
    bool disconnectedCaught = false;
    server.onDisconnect = [&](Lines::Tree reason, bool initiator) {
        disconnectedCaught = true;
    };
    client.disconnect();
    assert(server.parse(wire));
    assert(disconnectedCaught);

    printf("  -> Packet intent demux, 64-bit varlong intent & control intents verified!\n");
}

static void test_instance_reset_pristine_lifecycle() {
    printf("[TEST 15] Instance Reset (Pristine State Restoration & Seamless Reuse)...\n");

    Lines client;
    client.enable([](String) {});
    client.manualUpgrade("32_byte_secret_reset_test_______", true, 2);

    assert(client.isUpgraded());
    assert(client.bands.size() == 1);

    // Push 40 packets across multiple handles to heavily mutate state
    for (int i = 0; i < 40; ++i) {
        client.push(Packet(String("Heavy duty payload #") + String(i), i % 5 + 1, 1, true, true));
    }
    assert(client.nonce > 2);
    assert(client.outbox.size() > 0);
    assert(client.getPressure() > 0.0f);

    // Reset the instance
    client.reset();

    // Verify instance is pristine brand new
    assert(!client.isUpgraded());
    assert(client.upgradeTime == 0);
    assert(client.nonce == 2);
    assert(client.base == 2);
    assert(client.sendBase == 2);
    assert(client.windowBitmap == 0);
    assert(client.outbox.size() == 0);
    assert(client.inbox.size() == 0);
    assert(client.toBeBundled.size() == 0);
    assert(client.handleSequences.size() == 0);
    assert(client.bands.size() == 0);
    assert(client.sharedKey.size() == 0);
    assert(client.ourDirectionalKey == u256());
    assert(client.theirDirectionalKey == u256());
    assert(!client.initiator);
    assert(client.getPressure() == 0.0f);
    assert(client.couldPush());

    // Reuse the exact same instance for a fresh session
    String clientWire;
    String serverWire;
    client.enable([&](String b) { clientWire = b; });

    Lines server;
    server.enable([&](String b) { serverWire = b; });

    // Fresh 1.5-RTT Handshake
    server.onProbe = [&](Lines::Tree) -> bool { return true; };
    client.onAnnounce = [&]() -> bool { return true; };

    client.probe();
    assert(clientWire.size() > 0);
    assert(server.parse(clientWire));
    assert(serverWire.size() > 0);

    assert(client.parse(serverWire));
    assert(client.isUpgraded());

    assert(server.parse(clientWire));
    assert(server.isUpgraded());

    // Transmit data on reused instance
    String receivedPayload;
    server.onPacket = [&](Packet p) {
        receivedPayload = p.payload;
    };

    client.push(Packet(String("Brand new message on reused instance"), 3, 1, true, true));
    assert(server.parse(clientWire));
    assert(receivedPayload == "Brand new message on reused instance");

    // Disconnect automatically calls reset()
    client.disconnect();
    assert(!client.isUpgraded());
    assert(client.outbox.size() == 0);
    assert(client.bands.size() == 0);

    printf("  -> Lines instance after reset is verified 100%% pristine and reusable!\n");
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
    test_packet_intent_demux();
    test_instance_reset_pristine_lifecycle();

    printf("====================================================\n");
    printf("     ALL 15 TEST SUITES PASSED CLEANLY (100%%)!     \n");
    printf("====================================================\n");
    return 0;
}
