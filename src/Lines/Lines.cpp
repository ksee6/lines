/**
 * @file Lines.cpp
 * @brief High-performance, human-engineered implementation of the Lines protocol.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

#include "../../include/Lines/Lines.hpp"
#include <stdio.h>
#include <cmath>
#include <algorithm>
#include <Ksee/Crypto/AEAD.hpp>

namespace Ksee {

using Ksee::crypt;

// ---------------------------------------------------------------------------
// Low-Level Protocol Primitives & VarInt
// ---------------------------------------------------------------------------

static inline void encodeVarInt(u64 value, String &out) {
    while (value >= 0x80) {
        out.push((char)((value & 0x7F) | 0x80));
        value >>= 7;
    }
    out.push((char)(value & 0x7F));
}

static inline bool decodeVarInt(const u8 *data, usz len, usz &offset, u64 &out) {
    out = 0;
    u32 shift = 0;
    while (offset < len) {
        u8 byte = data[offset++];
        out |= (u64)(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) return true;
        shift += 7;
        if (shift >= 64) return false;
    }
    return false;
}

/**
 * @brief Computes standard automotive CRC-15-CAN (x^15 + x^14 + x^10 + x^8 + x^7 + x^4 + x^3 + 1).
 */
static u16 computeCrc15(const u8 *data, usz len, u16 initialCrc = 0x0000) {
    u16 crc = initialCrc & 0x7FFF;
    for (usz i = 0; i < len; ++i) {
        crc ^= (u16)data[i] << 7;
        for (int b = 0; b < 8; ++b) {
            crc <<= 1;
            if (crc & 0x8000) {
                crc ^= 0x4599;
            }
        }
    }
    return crc & 0x7FFF;
}

/**
 * @brief Generates an 8-byte Poly1305 MAC over bundleId + ciphertext.
 */
static void computeBundleMac(u8 out8[8], const u256 &key, u64 bundleId, const u8 *ciphertext, usz len) {
    u512 block0 = chacha(key, bundleId, 12, 0);

    // Stream bundleId (8 bytes little endian) followed by ciphertext
    u8 fullTag[16];
    String authPayload;
    authPayload.allocate(8 + len);
    for (int i = 0; i < 8; ++i) {
        authPayload[i] = (char)(u8)(bundleId >> (i * 8));
    }
    if (len > 0) {
        memcpy(authPayload.data() + 8, ciphertext, len);
    }

    poly1305_auth(fullTag, (const u8*)authPayload.data(), authPayload.size(), block0.data);
    for (int i = 0; i < 8; ++i) {
        out8[i] = fullTag[i];
    }
}

static bool verifyBundleMac(const u8 expected8[8], const u256 &key, u64 bundleId, const u8 *ciphertext, usz len) {
    u8 computed[8];
    computeBundleMac(computed, key, bundleId, ciphertext, len);
    u8 diff = 0;
    for (int i = 0; i < 8; ++i) {
        diff |= (expected8[i] ^ computed[i]);
    }
    return diff == 0;
}

static inline u16 computeDeltaMask(const u256 &directionalKey, const u8 *ciphertext, usz len) {
    u16 ctPrefix = 0;
    if (len >= 2) {
        ctPrefix = (u16)ciphertext[0] | ((u16)ciphertext[1] << 8);
    } else if (len == 1) {
        ctPrefix = (u16)ciphertext[0];
    }
    u32 keyHash = 0x811c9dc5;
    for (int i = 0; i < 32; ++i) {
        keyHash ^= (u32)directionalKey.data[i];
        keyHash *= 0x01000193;
    }
    return (u16)((ctPrefix ^ (u16)keyHash) & 0x7FFF);
}

// ---------------------------------------------------------------------------
// LinesBandSlot Implementation
// ---------------------------------------------------------------------------

LinesBandSlot::~LinesBandSlot() {
    if (band) {
        Band *b = band;
        band = nullptr;
        b->removeSlot(this);
    }
}

bool LinesBandSlot::isAvailable() const {
    if (!band) return false;
    return band->couldPush();
}

// ---------------------------------------------------------------------------
// Construction & Lifecycle
// ---------------------------------------------------------------------------

Lines::Lines() {
    reset();
}

Lines::~Lines() {
    reset();
}

void Lines::reset() {
    outbox.clear();
    inbox.clear();
    toBeBundled.clear();
    handleSequences.clear();

    // Zero / clear cryptographic identities & session keys
    sharedKey.clear();
    ourDirectionalKey = u256();
    theirDirectionalKey = u256();
    epheKeypair = XKeypair::generate();
    theirEphePublic = u256();
    theirMetadata.clear();
    theirStaticPublics.clear();
    theirStatics.clear();
    initiator = false;

    // Reset window registers, timing & heartbeat state
    upgradeTime = 0;
    base = 2;
    sendBase = 2;
    nonce = 2;
    windowBitmap = 0;
    baseMoveTime = millis();
    retransmitFrom = 0;
    lastSeen = millis();
    lastSent = millis();
    primingBandSlot = 0;
    nextBestEffortHeartbeat = 0;
    nextCuriosityHeartbeat = 0;

    // Clean up heap-allocated band slots
    for (usz i = 0; i < bands.size(); ++i) {
        LinesBandSlot *slot = bands[i];
        if (slot) {
            delete slot;
        }
    }
    bands.clear();
}

void Lines::setupDirectionalKeys() {
    if (sharedKey.size() < 32) return;
    u256 k = u256(sharedKey);
    u256 ourK = k;
    u256 theirK = k;

    if (initiator) {
        ourK.data[31] |= 1;
        theirK.data[31] &= 0xFE;
    } else {
        ourK.data[31] &= 0xFE;
        theirK.data[31] |= 1;
    }
    ourDirectionalKey = ourK;
    theirDirectionalKey = theirK;
}

void Lines::manualUpgrade(const String &key, bool isInitiator, u64 initialNonce) {
    sharedKey = key;
    initiator = isInitiator;
    setupDirectionalKeys();
    upgradeTime = millis();
    nonce = initialNonce;
    base = initialNonce;
    sendBase = initialNonce;
    windowBitmap = 0;
    baseMoveTime = millis();
    scheduleNextBestEffortHeartbeat();
    scheduleNextCuriosityHeartbeat();
}

// ---------------------------------------------------------------------------
// Multi-Band Management
// ---------------------------------------------------------------------------

LinesBandSlot* Lines::enable(Func<void(String)> sendCallback, Func<String()> recvCallback) {
    Band *b = new Band();
    b->isDynamicallyAllocated = true;
    b->sendCallback = sendCallback;
    b->recvCallback = recvCallback;
    return enable(b);
}

LinesBandSlot* Lines::enable(Band &band) {
    LinesBandSlot *slot = new LinesBandSlot();
    slot->lines = this;
    slot->id = bands.size() + 1;
    slot->windowResetTime = millis();
    slot->band = &band;
    band.onSlotDetached = [](void *s) {
        if (s) {
            LinesBandSlot *sl = (LinesBandSlot*)s;
            sl->band = nullptr;
        }
    };
    band.addSlot(slot);
    bands.push(slot);
    return slot;
}

LinesBandSlot* Lines::enable(Band *band) {
    if (!band) return nullptr;
    return enable(*band);
}

LinesBandSlot* Lines::enable(LinesBandSlot *bandSlot) {
    if (!bandSlot) return nullptr;
    bandSlot->lines = this;
    bands.push(bandSlot);
    if (bandSlot->band) {
        bandSlot->band->addSlot(bandSlot);
    }
    return bandSlot;
}

LinesBandSlot* Lines::enable() {
    Band *b = new Band();
    b->isDynamicallyAllocated = true;
    return enable(b);
}

void Lines::disable(LinesBandSlot *slot) {
    if (!slot) return;
    for (usz i = 0; i < bands.size(); ++i) {
        if (bands[i] == slot) {
            bands.remove(i);
            break;
        }
    }
    delete slot;
}

void Lines::disable(u64 bandSlotIdx) {
    if (bandSlotIdx < bands.size()) {
        disable(bands[bandSlotIdx]);
        return;
    }
    for (usz i = 0; i < bands.size(); ++i) {
        if (bands[i] && bands[i]->id == bandSlotIdx) {
            disable(bands[i]);
            return;
        }
    }
}

void Lines::stun(LinesBandSlot *slot, u64 duration) {
    if (slot && slot->band) {
        slot->band->stun(duration);
    }
}

void Lines::stun(u64 bandSlotIdx, u64 duration) {
    if (bandSlotIdx < bands.size() && bands[bandSlotIdx]) {
        stun(bands[bandSlotIdx], duration);
        return;
    }
    for (usz i = 0; i < bands.size(); ++i) {
        if (bands[i] && bands[i]->id == bandSlotIdx) {
            stun(bands[i], duration);
            return;
        }
    }
}

u64 Lines::getSendThroughput() const {
    u64 sum = 0;
    for (usz i = 0; i < bands.size(); ++i) {
        if (bands[i]) sum += bands[i]->getSendThroughput();
    }
    return sum;
}

u64 Lines::getRecvThroughput() const {
    u64 sum = 0;
    for (usz i = 0; i < bands.size(); ++i) {
        if (bands[i]) sum += bands[i]->getRecvThroughput();
    }
    return sum;
}

u64 Lines::getThroughput() const {
    return getSendThroughput() + getRecvThroughput();
}

u64 Lines::getLatency() const {
    u64 minLat = (u64)-1;
    for (usz i = 0; i < bands.size(); ++i) {
        if (bands[i] && bands[i]->isAvailable()) {
            u64 l = bands[i]->getLatency();
            if (l < minLat) minLat = l;
        }
    }
    return (minLat == (u64)-1) ? 1 : minLat;
}

f32 Lines::getPressure() const {
    u32 unacked = 0;
    for (const auto &pair : outbox) {
        if (pair.value.ackTime == 0 && pair.value.reliable) unacked++;
    }
    return (f32)unacked / (f32)size;
}

bool Lines::couldPush() const {
    if (maxThroughput > 0 && getThroughput() >= maxThroughput) return false;
    return getPressure() < 1.0f;
}

// ---------------------------------------------------------------------------
// Band Selection & Scheduling
// ---------------------------------------------------------------------------

i64 Lines::getBestBand() const {
    i64 bestIdx = -1;
    u64 maxCap = 0;

    for (usz i = 0; i < bands.size(); ++i) {
        LinesBandSlot *s = bands[i];
        if (!s || !s->isAvailable()) continue;
        u64 cap = s->getCapacity();
        if (cap > maxCap) {
            maxCap = cap;
            bestIdx = (i64)i;
        }
    }

    if (bestIdx == -1) {
        // Fall back to primingBandSlot
        if (primingBandSlot < bands.size() && bands[primingBandSlot]->isAvailable()) {
            return (i64)primingBandSlot;
        }
        for (usz i = 0; i < bands.size(); ++i) {
            if (bands[i] && bands[i]->isAvailable()) return (i64)i;
        }
    }
    return bestIdx;
}

i64 Lines::selectUnexploredBand(u32 jitter) const {
    Array<i64> candidateIndices;
    Array<u64> potentialScores;

    for (usz i = 0; i < bands.size(); ++i) {
        LinesBandSlot *s = bands[i];
        if (!s || !s->isAvailable()) continue;
        candidateIndices.push((i64)i);
        potentialScores.push(s->getPotential());
    }

    if (candidateIndices.size() == 0) return -1;
    if (candidateIndices.size() == 1) return candidateIndices[0];

    // Sort ranks by potential descending
    for (usz i = 0; i < candidateIndices.size(); ++i) {
        for (usz j = i + 1; j < candidateIndices.size(); ++j) {
            if (potentialScores[j] > potentialScores[i]) {
                std::swap(potentialScores[i], potentialScores[j]);
                std::swap(candidateIndices[i], candidateIndices[j]);
            }
        }
    }

    // Stochastic rank perturbation (+/- jitter positions)
    usz chosenIdx = 0;
    if (jitter > 0 && candidateIndices.size() > 1) {
        u32 range = 2 * jitter + 1;
        int delta = (int)(randomNumber<u32>() % range) - (int)jitter;
        int target = (int)chosenIdx + delta;
        if (target < 0) target = 0;
        if (target >= (int)candidateIndices.size()) target = (int)candidateIndices.size() - 1;
        chosenIdx = (usz)target;
    }

    return candidateIndices[chosenIdx];
}

void Lines::scheduleNextBestEffortHeartbeat() {
    u64 minWait = timeout / 6;
    u64 maxWait = timeout / 3;
    u64 span = (maxWait > minWait) ? (maxWait - minWait) : 1000;
    nextBestEffortHeartbeat = millis() + minWait + (randomNumber<u32>() % (u32)span);
}

void Lines::scheduleNextCuriosityHeartbeat() {
    if (bands.size() <= 1) {
        nextCuriosityHeartbeat = 0;
        return;
    }
    f32 p = getPressure();
    f32 factor = std::exp(-4.6f * p);
    u64 calculated = (u64)((f32)timeout * factor);
    u64 floorInterval = timeout / 100;
    u64 interval = (calculated > floorInterval) ? calculated : floorInterval;
    nextCuriosityHeartbeat = millis() + interval;
}

void Lines::sendSackHeartbeat(LinesBandSlot *targetSlot) {
    sendSack(false, targetSlot);
}

void Lines::sendSackHeartbeat(u64 targetBandSlotIdx) {
    LinesBandSlot *slot = (targetBandSlotIdx < bands.size()) ? bands[targetBandSlotIdx] : nullptr;
    sendSackHeartbeat(slot);
}

// ---------------------------------------------------------------------------
// Handshake Protocol Implementation
// ---------------------------------------------------------------------------

u16 Lines::getTuneSeed() const {
    if (tune.isEmpty()) return 0x0000;
    return computeCrc15((const u8*)tune.data(), tune.size(), 0x0000);
}

void Lines::probe(const Tree &sel) {
    initiator = true;
    String payload;
    payload.append((const char*)epheKeypair.publicKey().data, 32);

    String selBytes = petrify(sel);
    encodeVarInt(selBytes.size(), payload);
    payload.append(selBytes.data(), selBytes.size());

    // Single-packet Pre-Upgrade Bundle:
    // Header (2B): isEncrypted = 0 (bit 15), CRC-15-CAN (bits 14..0)
    // PacketHeader (1B): hasHandle = 0, respectsOrder = 0, isTheFinalPacketInThisBundle = 0, hasIntent = 0
    String bundle;
    bundle.allocate(3 + payload.size());
    bundle[0] = 0;
    bundle[1] = 0;
    bundle[2] = 0;
    for (usz i = 0; i < payload.size(); ++i) {
        bundle[3 + i] = payload[i];
    }

    // Compute CRC-15 over payload and packetHeader seeded by tune
    u16 crc = computeCrc15((const u8*)bundle.data() + 2, bundle.size() - 2, getTuneSeed());
    bundle[0] = (char)(u8)(crc & 0xFF);
    bundle[1] = (char)(u8)((crc >> 8) & 0x7F); // Bit 15 is 0

    i64 targetBandIdx = getBestBand();
    LinesBandSlot *slot = (targetBandIdx >= 0 && (usz)targetBandIdx < bands.size()) ? bands[(usz)targetBandIdx] : nullptr;
    if (!slot && bands.size() > 0) slot = bands[0];

    if (slot && slot->band) {
        slot->band->push(bundle);
        lastSent = millis();
    }
}

void Lines::upgrade(const Tree &clientMetadata) {
    if (sharedKey.size() < 32) return;
    initiator = true;
    setupDirectionalKeys();

    String payload;
    u8 mac[8];
    u256 ourK = ourDirectionalKey;

    // Ephemeral public
    payload.append((const char*)epheKeypair.publicKey().data, 32);

    // Static proofs and metadata
    String plaintext;
    encodeVarInt(staticKeypairs.size(), plaintext);
    for (usz i = 0; i < staticKeypairs.size(); ++i) {
        u256 proofKey = staticKeypairs[i].sharedKey(theirEphePublic);
        u8 proofMac[8];
        computeBundleMac(proofMac, proofKey, 1, nullptr, 0);
        plaintext.append((const char*)proofMac, 8);
        plaintext.append((const char*)staticKeypairs[i].publicKey().data, 32);
    }

    String metaBytes = petrify(clientMetadata);
    encodeVarInt(metaBytes.size(), plaintext);
    plaintext.append(metaBytes.data(), metaBytes.size());

    String ciphertext = crypt(plaintext, ourK, 1, 12);
    computeBundleMac(mac, ourK, 1, (const u8*)ciphertext.data(), ciphertext.size());

    payload.append((const char*)mac, 8);
    payload.append(ciphertext.data(), ciphertext.size());

    // Build pre-upgrade packet
    String bundle;
    bundle.allocate(3 + payload.size());
    bundle[0] = 0;
    bundle[1] = 0;
    bundle[2] = 0;
    for (usz i = 0; i < payload.size(); ++i) {
        bundle[3 + i] = payload[i];
    }

    u16 crc = computeCrc15((const u8*)bundle.data() + 2, bundle.size() - 2, getTuneSeed());
    bundle[0] = (char)(u8)(crc & 0xFF);
    bundle[1] = (char)(u8)((crc >> 8) & 0x7F);

    i64 targetBandIdx = getBestBand();
    LinesBandSlot *slot = (targetBandIdx >= 0 && (usz)targetBandIdx < bands.size()) ? bands[(usz)targetBandIdx] : nullptr;
    if (!slot && bands.size() > 0) slot = bands[0];

    if (slot && slot->band) {
        slot->band->push(bundle);
        lastSent = millis();
    }

    nonce = 2;
    base = 2;
    sendBase = 2;
    upgradeTime = millis();
    scheduleNextBestEffortHeartbeat();
    scheduleNextCuriosityHeartbeat();

    if (onUpgrade) onUpgrade(theirMetadata);
}

void Lines::disconnect(const Tree &reason) {
    if (!isUpgraded()) return;
    String reasonBytes = petrify(reason);

    Packet p(reasonBytes, 0, IntentDisconnect, true, true, false);
    Array<Packet> pkts;
    pkts.push(p);
    sendPostUpgradeBundle(pkts, true, false);

    if (onDisconnect) onDisconnect(reason, true);
    reset();
}

// ---------------------------------------------------------------------------
// Data Transmission & Outbox Management
// ---------------------------------------------------------------------------

void Lines::push(const Packet &packet) {
    if (!couldPush()) return; // Backpressure drop

    toBeBundled.push(packet);
    flushBundles();
}

void Lines::flushBundles() {
    if (!isUpgraded() || toBeBundled.isEmpty()) return;

    Array<Packet> standardReliable;
    Array<Packet> standardUnreliable;
    Array<Packet> sacrificialPkts;

    for (usz i = 0; i < toBeBundled.size(); ++i) {
        if (toBeBundled[i].sacrificial) {
            sacrificialPkts.push(toBeBundled[i]);
        } else if (toBeBundled[i].reliable) {
            standardReliable.push(toBeBundled[i]);
        } else {
            standardUnreliable.push(toBeBundled[i]);
        }
    }
    toBeBundled.clear();

    if (!standardReliable.isEmpty()) {
        sendPostUpgradeBundle(standardReliable, true, false);
    }
    if (!standardUnreliable.isEmpty()) {
        sendPostUpgradeBundle(standardUnreliable, false, false);
    }
    if (!sacrificialPkts.isEmpty()) {
        sendPostUpgradeBundle(sacrificialPkts, false, true);
    }
}

void Lines::sendPostUpgradeBundle(const Array<Packet> &packets, bool reliable, bool sacrificial, LinesBandSlot *preferredSlot) {
    if (packets.size() == 0) return;

    LinesBandSlot *targetSlot = preferredSlot;
    if (targetSlot == nullptr) {
        i64 idx = -1;
        if (sacrificial) {
            idx = selectUnexploredBand(2);
        } else {
            idx = getBestBand();
        }
        if (idx >= 0 && (usz)idx < bands.size()) {
            targetSlot = bands[(usz)idx];
        }
    }

    if (targetSlot == nullptr) {
        if (primingBandSlot < bands.size() && bands[primingBandSlot]->isAvailable()) {
            targetSlot = bands[primingBandSlot];
        } else if (bands.size() > 0 && bands[0]->isAvailable()) {
            targetSlot = bands[0];
        } else {
            return;
        }
    }

    // Assemble Plaintext Packets
    String plaintext;
    for (usz i = 0; i < packets.size(); ++i) {
        const Packet &p = packets[i];
        bool finalPacket = (i == packets.size() - 1);

        String pktData;
        u8 headerByte = 0;
        if (p.handle != 1)         headerByte |= 0x01; // hasHandle
        if (p.intent != 1)         headerByte |= 0x02; // hasIntent
        if (p.offset != 0)         headerByte |= 0x04; // hasOffset
        if (p.intendedLength != 0) headerByte |= 0x08; // hasIntendedLength
        if (finalPacket)           headerByte |= 0x10; // isTheFinalPacketInThisBundle
        if (p.ordered)             headerByte |= 0x20; // ordered

        pktData.push((char)headerByte);
        if (p.handle != 1) {
            encodeVarInt(p.handle, pktData);
        }
        if (p.intent != 1) {
            encodeVarInt(p.intent, pktData);
        }
        if (p.offset != 0) {
            encodeVarInt(p.offset, pktData);
        }
        if (p.intendedLength != 0) {
            encodeVarInt(p.intendedLength, pktData);
        }
        pktData.append(p.payload.data(), p.payload.size());

        encodeVarInt(pktData.size(), plaintext);
        plaintext.append(pktData.data(), pktData.size());
    }

    // Pad to paddingBlockSize (default 32)
    u32 padTarget = (paddingBlockSize > 0) ? paddingBlockSize : 32;
    usz remainder = plaintext.size() % padTarget;
    if (remainder != 0) {
        usz padCount = padTarget - remainder;
        for (usz p = 0; p < padCount; ++p) plaintext.push((char)0);
    }

    u64 bundleId = nonce++;
    String ciphertext = crypt(plaintext, ourDirectionalKey, bundleId, 12);

    // Compute MAC over [bundleId (8B) + ciphertext]
    u8 mac[8];
    computeBundleMac(mac, ourDirectionalKey, bundleId, (const u8*)ciphertext.data(), ciphertext.size());

    // 2-Byte Wire Header: [1 bit isEncrypted = 1 | 15 bits maskedDeltaId]
    u16 low15 = (u16)(bundleId & 0x7FFF);
    u16 mask = computeDeltaMask(ourDirectionalKey, (const u8*)ciphertext.data(), ciphertext.size());
    u16 maskedDelta = (low15 ^ mask) & 0x7FFF;
    u16 rawHeader = maskedDelta | 0x8000; // Bit 15 set for encrypted

    String wire;
    wire.allocate(10 + ciphertext.size());
    wire[0] = (char)(u8)(rawHeader & 0xFF);
    wire[1] = (char)(u8)((rawHeader >> 8) & 0xFF);
    for (int i = 0; i < 8; ++i) wire[2 + i] = (char)mac[i];
    if (ciphertext.size() > 0) {
        memcpy(wire.data() + 10, ciphertext.data(), ciphertext.size());
    }

    transmitBundle(bundleId, wire, targetSlot, reliable, sacrificial);
}

void Lines::transmitBundle(u64 bundleId, const String &rawBundle, LinesBandSlot *slot, bool reliable, bool sacrificial) {
    if (!slot || !slot->band) return;

    slot->band->push(rawBundle);
    lastSent = millis();

    // Outbox Accounting
    SentBundle sb;
    sb.sentTime = millis();
    sb.ackTime = 0;
    sb.size = rawBundle.size();
    sb.bandSlot = slot;
    sb.reliable = reliable;
    sb.sacrificial = sacrificial;

    u64 estSpeed = slot->getCapacity();
    sb.duty = (estSpeed > 0) ? ((sb.size * 1000) / estSpeed) : 1;
    if (sb.duty == 0) sb.duty = 1;

    if (reliable) {
        sb.bundle = rawBundle;
    } else {
        sb.bundle.clear();
        sb.ackTime = millis();
    }

    outbox[bundleId] = sb;
    advanceSendBase();

    // Rolling statistics update
    slot->bytesSentLastSec += rawBundle.size();
    slot->dutyConsumedLastSec += sb.duty;
}

void Lines::advanceSendBase() {
    while (sendBase < nonce) {
        const SentBundle *sb = outbox.get(sendBase);
        if (sb == nullptr || !sb->reliable || sb->ackTime != 0) {
            sendBase++;
        } else {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Sliding Window & SACK Intervals
// ---------------------------------------------------------------------------

void Lines::pretendReceived(u64 fromDelta, u64 toDelta) {
    for (u64 d = fromDelta; d <= toDelta; ++d) {
        if (d < size) {
            windowBitmap |= (1ULL << d);
        }
    }
    advanceWindow(base);
}

void Lines::setAcknowledged(u64 fromDelta, u64 toDelta, u64 ackTime) {
    u64 now = (ackTime == 0) ? millis() : ackTime;
    for (u64 d = fromDelta; d <= toDelta; ++d) {
        u64 bundleId = sendBase + d;
        if (outbox.has(bundleId)) {
            SentBundle &sb = outbox[bundleId];
            sb.ackTime = now;
            sb.bundle.clear(); // Free payload memory on ACK
            if (sb.bandSlot) {
                LinesBandSlot *s = sb.bandSlot;
                s->ackedBytesLastSec += sb.size;
                u64 rtt = (now > sb.sentTime) ? (now - sb.sentTime) : 1;
                u64 lat = rtt / 2;
                if (lat == 0) lat = 1;
                if (s->minObservedLatency == 0 || lat < s->minObservedLatency) {
                    s->minObservedLatency = lat;
                }
            }
        }
    }
    advanceSendBase();
}

void Lines::advanceWindow(u64 currentBase) {
    u64 shift = 0;
    while ((windowBitmap & 1ULL) != 0) {
        windowBitmap >>= 1;
        shift++;
    }
    if (shift > 0) {
        base = currentBase + shift;
        baseMoveTime = millis();

        // Deliver queued packets whose bundleId is now <= base
        for (auto &pair : handleSequences) {
            HandleSeq &hs = pair.value;
            Array<u64> readyIds;
            for (const auto &holPair : hs.holQueue) {
                if (holPair.key <= base) readyIds.push(holPair.key);
            }
            for (usz i = 0; i < readyIds.size(); ++i) {
                for (usz j = i + 1; j < readyIds.size(); ++j) {
                    if (readyIds[j] < readyIds[i]) {
                        u64 tmp = readyIds[i];
                        readyIds[i] = readyIds[j];
                        readyIds[j] = tmp;
                    }
                }
                Packet p = hs.holQueue[readyIds[i]];
                hs.holQueue.remove(readyIds[i]);
                if (onPacket) onPacket(p);
            }
        }

        // Prune old inbox entries outside window
        Array<u64> toPrune;
        for (const auto &pair : inbox) {
            if (pair.key < base) toPrune.push(pair.key);
        }
        for (usz i = 0; i < toPrune.size(); ++i) inbox.remove(toPrune[i]);
    }
}

Array<Interval<u64>> Lines::showReceived() const {
    Array<Interval<u64>> intervals;
    bool inInterval = false;
    u64 start = 0;

    for (u64 d = 0; d < size; ++d) {
        bool bit = (windowBitmap & (1ULL << d)) != 0;
        if (bit) {
            if (!inInterval) {
                inInterval = true;
                start = d;
            }
        } else {
            if (inInterval) {
                intervals.push(Interval<u64>(start, d - 1));
                inInterval = false;
            }
        }
    }
    if (inInterval) {
        intervals.push(Interval<u64>(start, size - 1));
    }
    return intervals;
}

Array<Interval<u64>> Lines::showUnavailableToRetransmit() const {
    Array<Interval<u64>> intervals;
    bool inInterval = false;
    u64 start = 0;

    u64 maxDelta = (nonce > sendBase) ? (nonce - sendBase) : 0;
    if (maxDelta > size) maxDelta = size;

    for (u64 d = 0; d < maxDelta; ++d) {
        u64 bundleId = sendBase + d;
        bool unavailable = false;
        const SentBundle *sb = outbox.get(bundleId);
        if (sb != nullptr) {
            if (!sb->reliable || sb->ackTime != 0 || sb->bundle.size() == 0) {
                unavailable = true;
            }
        }
        if (unavailable) {
            if (!inInterval) {
                inInterval = true;
                start = d;
            }
        } else {
            if (inInterval) {
                intervals.push(Interval<u64>(start, d - 1));
                inInterval = false;
            }
        }
    }
    if (inInterval && maxDelta > 0) {
        intervals.push(Interval<u64>(start, maxDelta - 1));
    }
    return intervals;
}

void Lines::sendSack(bool sacrificial, LinesBandSlot *targetSlot) {
    if (!isUpgraded()) return;
    Array<Interval<u64>> received = showReceived();
    Array<Interval<u64>> unavailable = showUnavailableToRetransmit();

    String sackData;
    encodeVarInt(base, sackData); // Cumulative Base ACK

    u16 timeSinceBaseMove = (u16)((millis() - baseMoveTime) & 0xFFFF);
    sackData.push((char)(u8)(timeSinceBaseMove & 0xFF));
    sackData.push((char)(u8)((timeSinceBaseMove >> 8) & 0xFF));

    sackData.push((char)(u8)received.size());
    for (usz i = 0; i < received.size(); ++i) {
        sackData.push((char)(u8)received[i].left);
        sackData.push((char)(u8)received[i].right);
    }

    sackData.push((char)(u8)unavailable.size());
    for (usz i = 0; i < unavailable.size(); ++i) {
        sackData.push((char)(u8)unavailable[i].left);
        sackData.push((char)(u8)unavailable[i].right);
    }

    Packet p(sackData, 0, IntentSack, false, false, sacrificial);
    Array<Packet> pkts;
    pkts.push(p);

    if (targetSlot == nullptr) {
        i64 idx = sacrificial ? selectUnexploredBand(2) : getBestBand();
        if (idx >= 0 && (usz)idx < bands.size()) {
            targetSlot = bands[(usz)idx];
        }
    }
    if (targetSlot == nullptr && bands.size() > 0) targetSlot = bands[0];
    if (targetSlot == nullptr) return;

    sendPostUpgradeBundle(pkts, false, sacrificial, targetSlot);
}

// ---------------------------------------------------------------------------
// Wire Parsing & Inbound Processing
// ---------------------------------------------------------------------------

bool Lines::parse(const String &bundle, LinesBandSlot *slot) {
    if (bundle.size() < 3) return false;

    if (!slot && bands.size() > 0) slot = bands[0];

    // Check throughput limits
    if (maxThroughput > 0 && getThroughput() >= maxThroughput) {
        return false;
    }

    if (slot && slot->band) {
        if (slot->band->maxBundleSize > 0 && bundle.size() > slot->band->maxBundleSize) {
            return false;
        }
        slot->bytesRecvLastSec += bundle.size();
    }

    // Pre-Upgrade Parse
    if (!isEncrypted(bundle)) {
        u16 receivedCrc = (u16)(u8)bundle[0] | ((u16)((u8)bundle[1] & 0x7F) << 8);
        u16 computedCrc = computeCrc15((const u8*)bundle.data() + 2, bundle.size() - 2, getTuneSeed());
        if (receivedCrc != computedCrc) {
            if (slot && slot->band) slot->band->stun(0);
            return false;
        }

        u8 packetHeader = (u8)bundle[2];
        bool hasHandle = (packetHeader & 0x01) != 0;
        bool hasIntent = (packetHeader & 0x02) != 0;
        bool hasOffset = (packetHeader & 0x04) != 0;
        bool hasIntendedLength = (packetHeader & 0x08) != 0;
        usz offset = 3;
        u64 handle = 1;
        if (hasHandle) {
            decodeVarInt((const u8*)bundle.data(), bundle.size(), offset, handle);
        }
        u64 intent = 1;
        if (hasIntent) {
            decodeVarInt((const u8*)bundle.data(), bundle.size(), offset, intent);
        }
        u64 off = 0;
        if (hasOffset) {
            decodeVarInt((const u8*)bundle.data(), bundle.size(), offset, off);
        }
        u64 intendedLen = 0;
        if (hasIntendedLength) {
            decodeVarInt((const u8*)bundle.data(), bundle.size(), offset, intendedLen);
        }

        String payload((const u8*)bundle.data() + offset, bundle.size() - offset);
        lastSeen = millis();

        // Pre-Upgrade Handshake Demux
        if (payload.size() >= 32) {
            if (!isUpgraded()) {
                if (initiator) {
                    handleAnnounce(payload, slot);
                } else {
                    bool upgraded = false;
                    if (payload.size() >= 40 && theirEphePublic != u256()) {
                        const u8 *macInBundle = (const u8*)payload.data() + 32;
                        const u8 *ct = (const u8*)payload.data() + 40;
                        usz ctLen = payload.size() - 40;
                        if (verifyBundleMac(macInBundle, theirDirectionalKey, 1, ct, ctLen)) {
                            handleUpgrade(payload, slot);
                            upgraded = true;
                        }
                    }
                    if (!upgraded) {
                        handleProbe(payload, slot);
                    }
                }
                return true;
            }
        }
        return false;
    }

    // Post-Upgrade Parse
    if (bundle.size() < 10) return false;
    if (sharedKey.size() < 32) return false;

    u16 rawHeader = (u16)(u8)bundle[0] | ((u16)(u8)bundle[1] << 8);
    u16 maskedDelta = rawHeader & 0x7FFF;

    const u8 *ct = (const u8*)bundle.data() + 10;
    usz ctLen = bundle.size() - 10;
    u16 mask = computeDeltaMask(theirDirectionalKey, ct, ctLen);
    u16 low15 = (maskedDelta ^ mask) & 0x7FFF;

    // Reconstruct full 64-bit bundleId relative to base
    u64 high = base & ~0x7FFFULL;
    u64 bundleId = high | (u64)low15;
    if (bundleId + 16384 < base) bundleId += 32768;
    else if (bundleId > base + 16384 && bundleId >= 32768) bundleId -= 32768;

    // Fast-drop if outside window
    if (bundleId < base) return false;
    u64 delta = bundleId - base;
    if (delta >= size) return false;

    // Anti-replay check
    if ((windowBitmap & (1ULL << delta)) != 0) {
        return false; // Already received
    }

    // Verify 8-byte Poly1305 MAC
    const u8 *macInBundle = (const u8*)bundle.data() + 2;
    if (!verifyBundleMac(macInBundle, theirDirectionalKey, bundleId, ct, ctLen)) {
        if (slot && slot->band) slot->band->stun(0);
        return false;
    }

    // Decrypt Payload
    String ciphertextStr((const u8*)ct, ctLen);
    String plaintext = crypt(ciphertextStr, theirDirectionalKey, bundleId, 12);

    // Mark window and inbox
    windowBitmap |= (1ULL << delta);
    RecvBundle rb;
    rb.recvTime = millis();
    rb.size = bundle.size();
    rb.bandSlot = slot;
    inbox[bundleId] = rb;

    lastSeen = millis();
    advanceWindow(base);

    // Demux Packets Inside Decrypted Payload
    usz offset = 0;
    while (offset < plaintext.size()) {
        u64 pktLen = 0;
        if (!decodeVarInt((const u8*)plaintext.data(), plaintext.size(), offset, pktLen)) break;
        if (pktLen == 0 || offset + pktLen > plaintext.size()) break;

        u8 pktHeader = (u8)plaintext[offset];
        bool hasHandle = (pktHeader & 0x01) != 0;
        bool hasIntent = (pktHeader & 0x02) != 0;
        bool hasOffset = (pktHeader & 0x04) != 0;
        bool hasIntendedLength = (pktHeader & 0x08) != 0;
        bool finalPkt = (pktHeader & 0x10) != 0;
        bool order = (pktHeader & 0x20) != 0;

        usz pktOffset = offset + 1;
        u64 handle = 1;
        if (hasHandle) {
            decodeVarInt((const u8*)plaintext.data(), offset + pktLen, pktOffset, handle);
        }

        u64 intent = 1;
        if (hasIntent) {
            decodeVarInt((const u8*)plaintext.data(), offset + pktLen, pktOffset, intent);
        }

        u64 off = 0;
        if (hasOffset) {
            decodeVarInt((const u8*)plaintext.data(), offset + pktLen, pktOffset, off);
        }

        u64 intendedLen = 0;
        if (hasIntendedLength) {
            decodeVarInt((const u8*)plaintext.data(), offset + pktLen, pktOffset, intendedLen);
        }

        usz payloadLen = (offset + pktLen > pktOffset) ? (offset + pktLen - pktOffset) : 0;
        String pktPayload((const u8*)plaintext.data() + pktOffset, payloadLen);

        Packet p(pktPayload, handle, intent, off, intendedLen, true, order, false);
        dispatchPacket(p, bundleId);

        offset += pktLen;
        if (finalPkt) break; // Trailing bytes are padding
    }

    return true;
}

void Lines::dispatchPacket(const Packet &packet, u64 bundleId) {
    if (packet.handle == 0) {
        // Control plane actions
        if (packet.intent == IntentDisconnect) {
            handleDisconnect(packet.payload);
        } else if (packet.intent == IntentSack) {
            handleSack(packet.payload);
        }
        return;
    }

    if (!packet.ordered || bundleId <= base) {
        if (onPacket) onPacket(packet);
        return;
    }

    // Out-of-order packet: queue it until base advances past bundleId
    HandleSeq &hs = handleSequences[packet.handle];
    hs.holQueue[bundleId] = packet;
}

// ---------------------------------------------------------------------------
// Control Plane Handlers
// ---------------------------------------------------------------------------

void Lines::handleProbe(const String &payload, LinesBandSlot *slot) {
    if (payload.size() < 32) return;
    for (int i = 0; i < 32; ++i) theirEphePublic.data[i] = (u8)payload[i];

    Tree sel;
    usz offset = 32;
    u64 selLen = 0;
    if (decodeVarInt((const u8*)payload.data(), payload.size(), offset, selLen)) {
        if (offset + selLen <= payload.size()) {
            hydrate(String((const u8*)payload.data() + offset, selLen), sel);
        }
    }

    Tree announceMetadata;
    bool allowAnnounce = true;
    if (onProbe) allowAnnounce = onProbe(sel, announceMetadata);
    if (!allowAnnounce) return;

    // Send Announce
    sharedKey = String((const u8*)epheKeypair.sharedKey(theirEphePublic).data, 32);
    initiator = false;
    setupDirectionalKeys();

    if (slot) {
        for (usz i = 0; i < bands.size(); ++i) {
            if (bands[i] == slot) {
                primingBandSlot = i;
                break;
            }
        }
    }

    String announcePayload;
    announcePayload.append((const char*)epheKeypair.publicKey().data, 32);

    String plaintext;
    encodeVarInt(staticKeypairs.size(), plaintext);
    for (usz i = 0; i < staticKeypairs.size(); ++i) {
        u256 proofKey = staticKeypairs[i].sharedKey(theirEphePublic);
        u8 proofMac[8];
        computeBundleMac(proofMac, proofKey, 0, nullptr, 0);
        plaintext.append((const char*)proofMac, 8);
        plaintext.append((const char*)staticKeypairs[i].publicKey().data, 32);
    }
    String metaBytes = petrify(announceMetadata);
    encodeVarInt(metaBytes.size(), plaintext);
    plaintext.append(metaBytes.data(), metaBytes.size());

    String ciphertext = crypt(plaintext, ourDirectionalKey, 0, 12);
    u8 mac[8];
    computeBundleMac(mac, ourDirectionalKey, 0, (const u8*)ciphertext.data(), ciphertext.size());

    announcePayload.append((const char*)mac, 8);
    announcePayload.append(ciphertext.data(), ciphertext.size());

    String bundle;
    bundle.allocate(3 + announcePayload.size());
    bundle[0] = 0;
    bundle[1] = 0;
    bundle[2] = 0;
    for (usz i = 0; i < announcePayload.size(); ++i) {
        bundle[3 + i] = announcePayload[i];
    }

    u16 crc = computeCrc15((const u8*)bundle.data() + 2, bundle.size() - 2, getTuneSeed());
    bundle[0] = (char)(u8)(crc & 0xFF);
    bundle[1] = (char)(u8)((crc >> 8) & 0x7F);

    if (slot && slot->band) {
        slot->band->push(bundle);
        lastSent = millis();
    }
}

void Lines::handleAnnounce(const String &payload, LinesBandSlot *slot) {
    if (payload.size() < 40) return;
    for (int i = 0; i < 32; ++i) theirEphePublic.data[i] = (u8)payload[i];

    sharedKey = String((const u8*)epheKeypair.sharedKey(theirEphePublic).data, 32);
    initiator = true;
    setupDirectionalKeys();

    if (slot) {
        for (usz i = 0; i < bands.size(); ++i) {
            if (bands[i] == slot) {
                primingBandSlot = i;
                break;
            }
        }
    }

    const u8 *macInBundle = (const u8*)payload.data() + 32;
    const u8 *ct = (const u8*)payload.data() + 40;
    usz ctLen = payload.size() - 40;

    if (!verifyBundleMac(macInBundle, theirDirectionalKey, 0, ct, ctLen)) {
        return;
    }

    String ciphertextStr((const u8*)ct, ctLen);
    String plaintext = crypt(ciphertextStr, theirDirectionalKey, 0, 12);
    usz offset = 0;
    u64 numProofs = 0;
    if (decodeVarInt((const u8*)plaintext.data(), plaintext.size(), offset, numProofs)) {
        for (u64 p = 0; p < numProofs && offset + 40 <= plaintext.size(); ++p) {
            String pubKey((const u8*)plaintext.data() + offset + 8, 32);
            theirStaticPublics.push(pubKey);
            theirStatics.push(pubKey);
            offset += 40;
        }
    }
    u64 metaLen = 0;
    if (decodeVarInt((const u8*)plaintext.data(), plaintext.size(), offset, metaLen)) {
        if (offset + metaLen <= plaintext.size()) {
            hydrate(String((const u8*)plaintext.data() + offset, metaLen), theirMetadata);
        }
    }

    bool shouldUpgrade = true;
    if (onAnnounce) shouldUpgrade = onAnnounce(theirMetadata);
    if (shouldUpgrade) upgrade();
}

void Lines::handleUpgrade(const String &payload, LinesBandSlot *slot) {
    if (payload.size() < 40) return;
    for (int i = 0; i < 32; ++i) theirEphePublic.data[i] = (u8)payload[i];

    sharedKey = String((const u8*)epheKeypair.sharedKey(theirEphePublic).data, 32);
    initiator = false;
    setupDirectionalKeys();

    if (slot) {
        for (usz i = 0; i < bands.size(); ++i) {
            if (bands[i] == slot) {
                primingBandSlot = i;
                break;
            }
        }
    }

    const u8 *macInBundle = (const u8*)payload.data() + 32;
    const u8 *ct = (const u8*)payload.data() + 40;
    usz ctLen = payload.size() - 40;

    if (!verifyBundleMac(macInBundle, theirDirectionalKey, 1, ct, ctLen)) {
        return;
    }

    String ciphertextStr((const u8*)ct, ctLen);
    String plaintext = crypt(ciphertextStr, theirDirectionalKey, 1, 12);
    usz offset = 0;
    u64 numProofs = 0;
    if (decodeVarInt((const u8*)plaintext.data(), plaintext.size(), offset, numProofs)) {
        for (u64 p = 0; p < numProofs && offset + 40 <= plaintext.size(); ++p) {
            String pubKey((const u8*)plaintext.data() + offset + 8, 32);
            theirStaticPublics.push(pubKey);
            theirStatics.push(pubKey);
            offset += 40;
        }
    }
    u64 metaLen = 0;
    if (decodeVarInt((const u8*)plaintext.data(), plaintext.size(), offset, metaLen)) {
        if (offset + metaLen <= plaintext.size()) {
            hydrate(String((const u8*)plaintext.data() + offset, metaLen), theirMetadata);
        }
    }

    nonce = 2;
    base = 2;
    sendBase = 2;
    upgradeTime = millis();
    scheduleNextBestEffortHeartbeat();
    scheduleNextCuriosityHeartbeat();

    if (onUpgrade) onUpgrade(theirMetadata);
}

void Lines::handleDisconnect(const String &payload) {
    Tree reason;
    hydrate(payload, reason);
    if (onDisconnect) onDisconnect(reason, false);
    reset();
}

void Lines::handleSack(const String &payload) {
    if (payload.size() < 4) return;
    usz offset = 0;
    u64 peerBase = 0;
    if (!decodeVarInt((const u8*)payload.data(), payload.size(), offset, peerBase)) return;

    u64 now = millis();
    if (peerBase > sendBase) {
        u64 ackCount = peerBase - sendBase;
        setAcknowledged(0, ackCount - 1, now);
        sendBase = peerBase;

        Array<u64> toPrune;
        for (const auto &pair : outbox) {
            if (pair.key < sendBase && pair.value.ackTime != 0) toPrune.push(pair.key);
        }
        for (usz i = 0; i < toPrune.size(); ++i) {
            outbox.remove(toPrune[i]);
        }
    }

    if (offset + 3 > payload.size()) return;
    u16 recvTimeDelta = (u16)(u8)payload[offset] | ((u16)(u8)payload[offset + 1] << 8);
    offset += 2;
    u64 ackTime = baseMoveTime + recvTimeDelta;
    if (recvTimeDelta == 0) ackTime = now;

    u8 numReceived = (u8)payload[offset++];
    for (u8 i = 0; i < numReceived && offset + 2 <= payload.size(); ++i) {
        u8 from = (u8)payload[offset++];
        u8 to = (u8)payload[offset++];
        setAcknowledged(from, to, ackTime);
    }

    if (offset < payload.size()) {
        u8 numUnavailable = (u8)payload[offset++];
        for (u8 i = 0; i < numUnavailable && offset + 2 <= payload.size(); ++i) {
            u8 from = (u8)payload[offset++];
            u8 to = (u8)payload[offset++];
            pretendReceived(from, to);
        }
    }

    advanceSendBase();
    retransmitFrom = 0;
}

// ---------------------------------------------------------------------------
// Periodic Maintenance & Retransmission Loop
// ---------------------------------------------------------------------------

void Lines::update(bool callBandUpdates) {
    u64 now = millis();

    // Call update on bands if requested
    if (callBandUpdates) {
        for (usz i = 0; i < bands.size(); ++i) {
            if (bands[i] && bands[i]->band) {
                bands[i]->band->update(/* doSlotUpdates = */ false);
            }
        }
    }

    // Check Idle Timeout
    if (isUpgraded() && timeout > 0) {
        if (now - lastSeen >= timeout) {
            reset();
            return;
        }
    }

    // Rolling Statistics Decay (Reset counters each second)
    updateRollingStats();

    if (!isUpgraded()) return;

    // Flush any pending toBeBundled packets
    flushBundles();

    // Keepalive SACK on best band
    if (nextBestEffortHeartbeat > 0 && now >= nextBestEffortHeartbeat) {
        i64 idx = getBestBand();
        LinesBandSlot *slot = (idx >= 0 && (usz)idx < bands.size()) ? bands[(usz)idx] : nullptr;
        sendSack(false, slot);
        scheduleNextBestEffortHeartbeat();
    }

    // Exploratory SACK on unexplored band
    if (nextCuriosityHeartbeat > 0 && now >= nextCuriosityHeartbeat) {
        i64 idx = selectUnexploredBand(2);
        LinesBandSlot *slot = (idx >= 0 && (usz)idx < bands.size()) ? bands[(usz)idx] : nullptr;
        sendSack(true, slot);
        scheduleNextCuriosityHeartbeat();
    }

    // Retransmit Unacknowledged Reliable Bundles
    for (auto &pair : outbox) {
        SentBundle &sb = pair.value;
        if (sb.ackTime == 0 && sb.bundle.size() > 0) {
            u64 bandRtt = 2 * (sb.bandSlot ? sb.bandSlot->getLatency() : 10);
            if (bandRtt < 20) bandRtt = 20;

            if (now - sb.sentTime >= bandRtt) {
                i64 bestIdx = getBestBand();
                LinesBandSlot *currentBestSlot = (bestIdx >= 0 && (usz)bestIdx < bands.size()) ? bands[(usz)bestIdx] : sb.bandSlot;
                if (currentBestSlot && currentBestSlot->band) {
                    currentBestSlot->band->push(sb.bundle);
                    sb.sentTime = now;
                    sb.bandSlot = currentBestSlot;
                    lastSent = now;
                }
            }
        }
    }
}

void Lines::updateRollingStats() {
    u64 now = millis();
    for (usz i = 0; i < bands.size(); ++i) {
        LinesBandSlot *s = bands[i];
        if (s && now - s->windowResetTime >= 1000) {
            s->bytesSentLastSec = 0;
            s->bytesRecvLastSec = 0;
            s->ackedBytesLastSec = 0;
            s->dutyConsumedLastSec = 0;
            s->windowResetTime = now;
        }
    }
}

bool Lines::matchesBundle(const String &bundle) const {
    if (bundle.size() < 10) return false;
    if (!isEncrypted(bundle)) return false;
    if (sharedKey.size() < 32) return false;

    u16 rawHeader = (u16)(u8)bundle[0] | ((u16)(u8)bundle[1] << 8);
    u16 maskedDelta = rawHeader & 0x7FFF;

    const u8 *ct = (const u8*)bundle.data() + 10;
    usz ctLen = bundle.size() - 10;
    u16 mask = computeDeltaMask(theirDirectionalKey, ct, ctLen);
    u16 low15 = (maskedDelta ^ mask) & 0x7FFF;

    u64 high = base & ~0x7FFFULL;
    u64 bundleId = high | (u64)low15;
    if (bundleId + 16384 < base) bundleId += 32768;
    else if (bundleId > base + 16384 && bundleId >= 32768) bundleId -= 32768;

    if (bundleId < base) return false;
    u64 delta = bundleId - base;
    if (delta >= size) return false;

    const u8 *macInBundle = (const u8*)bundle.data() + 2;
    return verifyBundleMac(macInBundle, theirDirectionalKey, bundleId, ct, ctLen);
}

bool Lines::isEncrypted(const String &bytes) {
    if (bytes.size() < 2) return false;
    u16 header = (u16)(u8)bytes[0] | ((u16)(u8)bytes[1] << 8);
    return (header & 0x8000) != 0;
}

} // namespace Ksee
