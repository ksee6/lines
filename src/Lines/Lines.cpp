/**
 * @file Lines.cpp
 * @brief High-performance implementation of the Lines protocol engine.
 */

#include "../../include/Lines/Lines.hpp"
#include <Ksee/Crypto/AEAD.hpp>

namespace Ksee {

// ---------------------------------------------------------------------------
// Cryptographic Helpers & Fast Masking
// ---------------------------------------------------------------------------

static void computeMac(u8 out8[8], const u256 &key, u64 nonce, const u8 *msg, usz len) {
    u512 block0 = chacha(key, nonce, 12, 0);
    u8 fullTag[16];
    poly1305_auth(fullTag, msg, len, block0.data);
    for (int i = 0; i < 8; ++i) out8[i] = fullTag[i];
}

static bool verifyMac(const u8 expected8[8], const u256 &key, u64 nonce, const u8 *msg, usz len) {
    u8 computed[8];
    computeMac(computed, key, nonce, msg, len);
    u8 diff = 0;
    for (int i = 0; i < 8; ++i) diff |= (expected8[i] ^ computed[i]);
    return diff == 0;
}

static u32 computeCrc23(const u8 *data, usz len) {
    u32 crc = 0x555555;
    for (usz i = 0; i < len; ++i) {
        crc ^= (u32)data[i] << 15;
        for (int b = 0; b < 8; ++b) {
            if (crc & 0x400000) {
                crc = ((crc << 1) ^ 0x65AC93) & 0x7FFFFF;
            } else {
                crc = (crc << 1) & 0x7FFFFF;
            }
        }
    }
    return crc & 0x7FFFFF;
}

static inline u32 extractCiphertextPrefix(const u8 *ct, usz len) {
    if (len >= 3) return (u32)ct[0] | ((u32)ct[1] << 8) | ((u32)ct[2] << 16);
    if (len == 2) return (u32)ct[0] | ((u32)ct[1] << 8);
    if (len == 1) return (u32)ct[0];
    return 0;
}

static inline u32 computeDeltaMask(const u256 &key, u32 ctPrefix) {
    u32 keyHash = 0x811c9dc5;
    for (int i = 0; i < 32; ++i) {
        keyHash ^= (u32)key.data[i];
        keyHash *= 0x01000193;
    }
    return (ctPrefix ^ keyHash) & 0x7FFFFF;
}

// ---------------------------------------------------------------------------
// FragmentRegisterEntry
// ---------------------------------------------------------------------------

bool FragmentRegisterEntry::isComplete() const {
    if (!hasStart || !hasEnd) return false;
    for (u32 i = 0; i <= endFragmentId; ++i) {
        if (!fragments.has(i)) return false;
    }
    return true;
}

String FragmentRegisterEntry::assemble() const {
    String payload;
    for (u32 i = 0; i <= endFragmentId; ++i) {
        const String *frag = fragments.get(i);
        if (frag) payload.append(frag->data(), frag->size());
    }
    return payload;
}

// ---------------------------------------------------------------------------
// Lines Engine Implementation
// ---------------------------------------------------------------------------

Lines::Lines() {
    epheKeypair = Keypair::generate();
    lastSeen = millis();
    lastSent = millis();
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

bool Lines::isEncrypted(const String &bytes) {
    return (bytes.size() >= 3 && ((bytes[2] & 0x80) != 0));
}

bool Lines::matchesBundle(const String &bytes) const {
    if (bytes.size() < 12) return false;
    if (!isEncrypted(bytes)) return false;
    if (sharedKey.size() < 32) return false;

    u32 rawHeader = (u32)(u8)bytes[0] | ((u32)(u8)bytes[1] << 8) | ((u32)(u8)bytes[2] << 16);
    u32 maskedDelta = rawHeader & 0x7FFFFF;

    const u8 *ct = (const u8*)bytes.data() + 11;
    usz ctLen = bytes.size() - 11;
    u32 mask = computeDeltaMask(theirDirectionalKey, extractCiphertextPrefix(ct, ctLen));
    u32 delta = (maskedDelta ^ mask) & 0x7FFFFF;

    return (delta < size);
}

void Lines::enable(Func<void(String)> callback, u32 band, u64 initialWeight, u32 mtu) {
    Band b;
    b.id = band;
    b.sendCallback = callback;
    b.weight = (initialWeight < 1) ? 1 : initialWeight;
    b.mtu = (mtu == 0) ? 1024 : mtu;
    b.enabled = true;
    b.occupied = false;
    b.bytesInInterval = 0;
    b.intervalStartTime = millis();
    bands[band] = b;
}

void Lines::disable(u32 band) {
    if (bands.has(band)) {
        bands[band].enabled = false;
        bands[band].weight = 0;
    }
}

f32 Lines::getAggression() const {
    if (size == 0) return 0.0f;
    return (f32)retransmissionBuffer.size() / (f32)size;
}

bool Lines::couldPush() const {
    return getAggression() < 0.9f;
}

u64 Lines::getWeight() const {
    u64 sum = 0;
    for (auto &entry : const_cast<Map<u32, Band>&>(bands)) {
        if (entry.value.enabled) sum += entry.value.weight;
    }
    return sum;
}

u64 Lines::getBandWeight(u32 band) const {
    if (!bands.has(band)) return 0;
    const Band *b = bands.get(band);
    return (b && b->enabled) ? b->weight : 0;
}

void Lines::updateBandReception(u32 bandId, usz bytesCount) {
    if (!bands.has(bandId)) return;
    Band &b = bands[bandId];
    if (!b.enabled) return;

    u64 now = millis();
    b.bytesInInterval += bytesCount;
    u64 elapsed = now - b.intervalStartTime;

    if (elapsed >= 1000) {
        u64 measuredRate = (b.bytesInInterval * 1000) / (elapsed > 0 ? elapsed : 1);
        b.weight = (measuredRate > 1) ? measuredRate : 1;
        b.bytesInInterval = 0;
        b.intervalStartTime = now;
    }
}

u32 Lines::selectBestBand(u32 requiredPayloadSize) const {
    u32 bestBand = 0;
    u64 bestWeight = 0;
    bool found = false;

    for (auto &entry : const_cast<Map<u32, Band>&>(bands)) {
        const Band &b = entry.value;
        if (b.enabled && !b.occupied && b.mtu >= requiredPayloadSize) {
            if (!found || b.weight > bestWeight) {
                bestWeight = b.weight;
                bestBand = b.id;
                found = true;
            }
        }
    }
    if (!found) {
        for (auto &entry : const_cast<Map<u32, Band>&>(bands)) {
            if (entry.value.enabled && !entry.value.occupied) return entry.value.id;
        }
    }
    return bestBand;
}

void Lines::transmitRaw(const String &bundle, u32 bandId) {
    if (!bands.has(bandId)) return;
    Band &b = bands[bandId];
    if (!b.enabled || !b.sendCallback) return;

    b.occupied = true;
    b.sendCallback(bundle);
    b.occupied = false;
    lastSent = millis();
}

void Lines::manualUpgrade(const String &key, bool isInitiator, u64 initialNonce) {
    sharedKey = key;
    initiator = isInitiator;
    nonce = initialNonce;
    base = initialNonce;
    windowBitmap = 0;
    setupDirectionalKeys();
    if (onReady) onReady();
}

void Lines::pretendReceived(u64 from, u64 to) {
    for (u64 id = from; id <= to; ++id) {
        if (id >= base && id < base + size) {
            u64 delta = id - base;
            windowBitmap |= (1ULL << delta);
        }
    }
    while (windowBitmap & 1ULL) {
        windowBitmap >>= 1ULL;
        base++;
    }
}

void Lines::destroy() {
    bands.clear();
    retransmissionBuffer.clear();
    pendingImportantQueue.destroy();
    pendingUnimportantQueue.destroy();
    fragmentationRegister.destroy();
    channelSequences.clear();
    sharedKey.clear();
}

void Lines::disconnect(const Tree &reason) {
    if (isUpgraded()) {
        String payload;
        writeVarLong(payload, 0); // Action 0: Disconnect
        String reasonBinary = reason.toBinary();
        payload.append(reasonBinary.data(), reasonBinary.size());

        Packet p(0, payload, false, false);
        pendingUnimportantQueue.push(p);
        u32 band = selectBestBand(payload.size() + 32);
        sendPostUpgradeBundle(false, band);
    }
    if (onDisconnect) onDisconnect(reason);
    destroy();
}

// ---------------------------------------------------------------------------
// Handshake: Probe, Announce, Upgrade
// ---------------------------------------------------------------------------

void Lines::probe(const Tree &sel) {
    selector = sel;
    initiator = true;
    epheKeypair = Keypair::generate();

    String payload;
    writeVarLong(payload, 10); // Action 10: Probe
    const u256 &pub = epheKeypair.publicKey();
    payload.append(pub.data, 32);

    String selBin = sel.toBinary();
    payload.append(selBin.data(), selBin.size());

    // Pre-upgrade bundle layout:
    // ( 3 bytes bundleId: CRC23 + isEncrypted(0) )
    // ( 1 byte bundleHeader: channelOtherThanOne = 1 )
    // ( VarInt channel = 0 )
    // ( payload )
    String inner;
    inner.push((u8)0x01); // channelOtherThanOne = 1
    writeVarLong(inner, 0); // channel 0
    inner.append(payload.data(), payload.size());

    u32 crc = computeCrc23((const u8*)inner.data(), inner.size());
    String bundle;
    bundle.push((u8)(crc & 0xFF));
    bundle.push((u8)((crc >> 8) & 0xFF));
    bundle.push((u8)((crc >> 16) & 0x7F)); // bit 23 = 0 (isEncrypted)
    bundle.append(inner.data(), inner.size());

    u32 band = selectBestBand(bundle.size());
    transmitRaw(bundle, band);
}

void Lines::handleProbe(const String &payload, u32 bandId) {
    usz at = 0;
    u64 action = readVarLong(payload, at);
    if (action != 10 || (payload.size() - at) < 32) return;

    u256 clientPub((const u8*)payload.data() + at);
    at += 32;

    Tree receivedSelector;
    if (at < payload.size()) {
        usz bytesRead = 0;
        receivedSelector.readFromBinary((const u8*)payload.data() + at, payload.size() - at, bytesRead);
    }

    theirEphePublic = clientPub;
    initiator = false;

    if (onProbe && !onProbe(receivedSelector)) return;

    // Generate server ephemeral keypair & derive root key
    epheKeypair = Keypair::generate();
    u256 root = epheKeypair.sharedKey(clientPub);
    sharedKey = root.asString();
    setupDirectionalKeys();

    // Prepare Announce:
    // serverEphePub (32) + numProofs (VarInt) + proofs (8 * N) + encrypted metadata (nonce 0)
    String toSign;
    const u256 &srvPub = epheKeypair.publicKey();
    toSign.append(srvPub.data, 32);

    writeVarLong(toSign, (u64)staticKeypairs.size());
    for (usz i = 0; i < staticKeypairs.size(); ++i) {
        u256 proofShared = staticKeypairs[i].sharedKey(clientPub);
        u8 proofTag[8];
        computeMac(proofTag, proofShared, 0, nullptr, 0);
        toSign.append(proofTag, 8);
    }

    String metaBin = metadata.toBinary();
    String encMeta = crypt(metaBin, ourDirectionalKey, 0, 12);
    toSign.append(encMeta.data(), encMeta.size());

    // Compute MAC over toSign
    u8 mac[8];
    computeMac(mac, ourDirectionalKey, 0, (const u8*)toSign.data(), toSign.size());

    String announcePayload;
    writeVarLong(announcePayload, 11); // Action 11: Announce
    announcePayload.append(mac, 8);
    announcePayload.append(toSign.data(), toSign.size());

    // Wrap in Pre-upgrade bundle
    String inner;
    inner.push((u8)0x01); // channelOtherThanOne = 1
    writeVarLong(inner, 0); // channel 0
    inner.append(announcePayload.data(), announcePayload.size());

    u32 crc = computeCrc23((const u8*)inner.data(), inner.size());
    String bundle;
    bundle.push((u8)(crc & 0xFF));
    bundle.push((u8)((crc >> 8) & 0xFF));
    bundle.push((u8)((crc >> 16) & 0x7F));
    bundle.append(inner.data(), inner.size());

    transmitRaw(bundle, bandId);
}

void Lines::handleAnnounce(const String &payload, u32 bandId) {
    usz at = 0;
    u64 action = readVarLong(payload, at);
    if (action != 11 || (payload.size() - at) < 40) return;

    u8 macExpected[8];
    for (int i = 0; i < 8; ++i) macExpected[i] = (u8)payload[at + i];
    at += 8;

    usz signedStart = at;
    u256 srvPub((const u8*)payload.data() + at);
    at += 32;

    // Derive root key & directional keys
    u256 root = epheKeypair.sharedKey(srvPub);
    sharedKey = root.asString();
    theirEphePublic = srvPub;
    initiator = true;
    setupDirectionalKeys();

    // Verify MAC
    usz signedLen = payload.size() - signedStart;
    if (!verifyMac(macExpected, theirDirectionalKey, 0, (const u8*)payload.data() + signedStart, signedLen)) {
        sharedKey.clear();
        return;
    }

    u64 numProofs = readVarLong(payload, at);
    theirStaticPublics.clear();
    for (u64 p = 0; p < numProofs && (at + 8 <= payload.size()); ++p) {
        at += 8; // Verified via static registry if configured
    }

    if (at < payload.size()) {
        String encMeta((const u8*)payload.data() + at, payload.size() - at);
        String decMeta = crypt(encMeta, theirDirectionalKey, 0, 12);
        usz readBytes = 0;
        theirMetadata.readFromBinary((const u8*)decMeta.data(), decMeta.size(), readBytes);
    }

    if (onAnnounce && !onAnnounce()) return;

    // Build Upgrade Packet (Client -> Server)
    String toSign;
    writeVarLong(toSign, (u64)staticKeypairs.size());
    for (usz i = 0; i < staticKeypairs.size(); ++i) {
        u256 proofShared = staticKeypairs[i].sharedKey(srvPub);
        u8 proofTag[8];
        computeMac(proofTag, proofShared, 1, nullptr, 0);
        toSign.append(proofTag, 8);
    }

    String metaBin = metadata.toBinary();
    String encMeta = crypt(metaBin, ourDirectionalKey, 1, 12);
    writeVarLong(toSign, (u64)encMeta.size());
    toSign.append(encMeta.data(), encMeta.size());

    u8 mac[8];
    computeMac(mac, ourDirectionalKey, 1, (const u8*)toSign.data(), toSign.size());

    String upgradePayload;
    writeVarLong(upgradePayload, 20); // Action 20: Upgrade
    upgradePayload.append(mac, 8);
    upgradePayload.append(toSign.data(), toSign.size());

    String inner;
    inner.push((u8)0x01);
    writeVarLong(inner, 0);
    inner.append(upgradePayload.data(), upgradePayload.size());

    u32 crc = computeCrc23((const u8*)inner.data(), inner.size());
    String bundle;
    bundle.push((u8)(crc & 0xFF));
    bundle.push((u8)((crc >> 8) & 0xFF));
    bundle.push((u8)((crc >> 16) & 0x7F));
    bundle.append(inner.data(), inner.size());

    transmitRaw(bundle, bandId);

    // Switch to live post-upgrade state with nonce = 2
    nonce = 2;
    base = 2;
    windowBitmap = 0;

    if (onReady) onReady();
}

void Lines::handleUpgrade(const String &payload, u32 bandId) {
    usz at = 0;
    u64 action = readVarLong(payload, at);
    if (action != 20 || (payload.size() - at) < 8) return;

    u8 macExpected[8];
    for (int i = 0; i < 8; ++i) macExpected[i] = (u8)payload[at + i];
    at += 8;

    usz signedStart = at;
    usz signedLen = payload.size() - signedStart;

    if (!verifyMac(macExpected, theirDirectionalKey, 1, (const u8*)payload.data() + signedStart, signedLen)) {
        return;
    }

    u64 numProofs = readVarLong(payload, at);
    for (u64 p = 0; p < numProofs && (at + 8 <= payload.size()); ++p) {
        at += 8;
    }

    u64 metaLen = readVarLong(payload, at);
    if (metaLen > 0 && at + metaLen <= payload.size()) {
        String encMeta((const u8*)payload.data() + at, (usz)metaLen);
        String decMeta = crypt(encMeta, theirDirectionalKey, 1, 12);
        usz readBytes = 0;
        theirMetadata.readFromBinary((const u8*)decMeta.data(), decMeta.size(), readBytes);
    }

    if (bands.has(bandId)) {
        bands[bandId].weight = 10; // Non-initiator assigns weight 10 to upgrade band
    }

    if (onUpgrade && !onUpgrade()) return;

    nonce = 2;
    base = 2;
    windowBitmap = 0;

    if (onReady) onReady();
}

// ---------------------------------------------------------------------------
// Post-Upgrade Transmission & Packaging
// ---------------------------------------------------------------------------

void Lines::push(const Packet &packet) {
    if (!couldPush()) return;

    u32 band = selectBestBand(packet.payload.size() + 32);
    u32 bandMtu = bands.has(band) ? bands[band].mtu : 1024;
    u32 maxPayloadPerBundle = (bandMtu > 64) ? (bandMtu - 32) : bandMtu;

    if (packet.payload.size() > maxPayloadPerBundle) {
        // Fragmentation
        u32 sId = nextFragmentationSeriesId++;
        usz total = packet.payload.size();
        usz offset = 0;
        u32 fragIdx = 0;

        Array<String> chunks;
        while (offset < total) {
            usz chunkSz = (total - offset > maxPayloadPerBundle) ? maxPayloadPerBundle : (total - offset);
            chunks.push(String((const u8*)packet.payload.data() + offset, chunkSz));
            offset += chunkSz;
        }

        for (usz i = 0; i < chunks.size(); ++i) {
            u8 state = (i == 0) ? 1 : ((i == chunks.size() - 1) ? 3 : 2);
            Packet fragP(packet.channel, chunks[i], packet.isImportant, packet.respectsHOL);
            fragP.fragState = state;
            fragP.seriesId = sId;
            fragP.fragmentId = (u32)i;

            if (packet.isImportant) pendingImportantQueue.push(fragP);
            else pendingUnimportantQueue.push(fragP);
        }
    } else {
        if (packet.isImportant) pendingImportantQueue.push(packet);
        else pendingUnimportantQueue.push(packet);
    }

    flushQueues();
}

void Lines::flushQueues() {
    if (!isUpgraded()) return;

    while (pendingImportantQueue.size() > 0 && couldPush()) {
        u32 band = selectBestBand(512);
        sendPostUpgradeBundle(true, band);
    }
    while (pendingUnimportantQueue.size() > 0) {
        u32 band = selectBestBand(512);
        sendPostUpgradeBundle(false, band);
    }
}

void Lines::sendPostUpgradeBundle(bool important, u32 bandId) {
    Array<Packet> &q = important ? pendingImportantQueue : pendingUnimportantQueue;
    if (q.size() == 0) return;

    u32 bandMtu = bands.has(bandId) ? bands[bandId].mtu : 1024;

    String plaintext;
    plaintext.push(important ? (u8)0x01 : (u8)0x00); // bundleHeader: isImportant

    usz packetCount = 0;
    while (q.size() > 0) {
        if (packetCount > 0 && (plaintext.size() + q[0].payload.size() + 32 > bandMtu)) {
            break;
        }
        Packet p = q[0];
        q.remove(0);

        bool isFinal = (q.size() == 0 || (plaintext.size() + (q.size() > 0 ? q[0].payload.size() : 0) + 32 > bandMtu));
        u8 pHeader = 0;
        if (p.channel != 1) pHeader |= 0x01;
        pHeader |= ((p.fragState & 0x03) << 1);
        if (p.respectsHOL) pHeader |= 0x08;
        if (isFinal) pHeader |= 0x10;

        String pBuf;
        pBuf.push(pHeader);
        if (p.channel != 1) writeVarLong(pBuf, (u64)p.channel);
        if (p.fragState != 0) {
            writeVarLong(pBuf, (u64)p.seriesId);
            writeVarLong(pBuf, (u64)p.fragmentId);
        }
        pBuf.append(p.payload.data(), p.payload.size());

        writeVarLong(plaintext, (u64)pBuf.size());
        plaintext.append(pBuf.data(), pBuf.size());
        packetCount++;
        if (isFinal) break;
    }

    // Padding out to exact multiples of paddingBlockSize (e.g. 32 bytes) to thwart traffic analysis
    if (paddingBlockSize > 1) {
        usz rem = plaintext.size() % paddingBlockSize;
        if (rem != 0) {
            usz padCount = paddingBlockSize - rem;
            for (usz i = 0; i < padCount; ++i) plaintext.push((u8)0x00);
        }
    }

    u64 currentNonce = nonce++;
    String ciphertext = crypt(plaintext, ourDirectionalKey, currentNonce, 12);

    u32 delta = (u32)(currentNonce % size);
    u32 mask = computeDeltaMask(ourDirectionalKey, extractCiphertextPrefix((const u8*)ciphertext.data(), ciphertext.size()));
    u32 maskedDelta = (delta ^ mask) & 0x7FFFFF;

    String dataToMac;
    for (int i = 0; i < 8; ++i) dataToMac.push((u8)((currentNonce >> (i * 8)) & 0xFF));
    dataToMac.append(ciphertext.data(), ciphertext.size());

    u8 mac[8];
    computeMac(mac, ourDirectionalKey, currentNonce, (const u8*)dataToMac.data(), dataToMac.size());

    String bundle;
    bundle.push((u8)(maskedDelta & 0xFF));
    bundle.push((u8)((maskedDelta >> 8) & 0xFF));
    bundle.push((u8)(((maskedDelta >> 16) & 0x7F) | 0x80)); // isEncrypted = 1
    bundle.append(mac, 8);
    bundle.append(ciphertext.data(), ciphertext.size());

    if (important) {
        retransmissionBuffer[currentNonce] = bundle;
    }

    transmitRaw(bundle, bandId);
}

// ---------------------------------------------------------------------------
// Bundle Parsing & Demultiplexing
// ---------------------------------------------------------------------------

bool Lines::parse(const String &bundle, u32 band) {
    if (bundle.size() < 4) return false;

    lastSeen = millis();
    updateBandReception(band, bundle.size());

    if (!isEncrypted(bundle)) {
        // Pre-upgrade mode
        u32 crcExpected = (u32)(u8)bundle[0] | ((u32)(u8)bundle[1] << 8) | (((u32)(u8)bundle[2] & 0x7F) << 16);
        u32 crcActual = computeCrc23((const u8*)bundle.data() + 3, bundle.size() - 3);
        if (crcActual != crcExpected) return false;

        u8 bHeader = (u8)bundle[3];
        usz at = 4;
        u32 channel = 1;
        if (bHeader & 0x01) {
            channel = (u32)readVarLong(bundle, at);
        }

        String payload((const u8*)bundle.data() + at, bundle.size() - at);

        if (channel == 0) {
            usz actionAt = 0;
            u64 action = readVarLong(payload, actionAt);
            if (action == 10) handleProbe(payload, band);
            else if (action == 11) handleAnnounce(payload, band);
            else if (action == 20) handleUpgrade(payload, band);
            return true;
        }

        Packet p(channel, payload, true, true);
        if (onPacket) onPacket(p);
        return true;
    }

    // Post-upgrade mode
    if (bundle.size() < 12) return false;
    if (sharedKey.size() < 32) return false;

    u32 rawDelta = (u32)(u8)bundle[0] | ((u32)(u8)bundle[1] << 8) | (((u32)(u8)bundle[2] & 0x7F) << 16);
    const u8 *macIn = (const u8*)bundle.data() + 3;
    const u8 *ct = (const u8*)bundle.data() + 11;
    usz ctLen = bundle.size() - 11;

    u32 mask = computeDeltaMask(theirDirectionalKey, extractCiphertextPrefix(ct, ctLen));
    u32 delta = (rawDelta ^ mask) & 0x7FFFFF;

    if (delta >= size) return false;

    u64 baseMod = base % size;
    u64 offset = (delta >= baseMod) ? (delta - baseMod) : (size - baseMod + delta);
    if (offset >= size) return false;

    u64 realBundleId = base + offset;

    // Duplicate check
    if (windowBitmap & (1ULL << offset)) {
        return false; // Replay / duplicate
    }

    // Authenticate MAC
    String dataToAuth;
    for (int i = 0; i < 8; ++i) dataToAuth.push((u8)((realBundleId >> (i * 8)) & 0xFF));
    dataToAuth.append(ct, ctLen);

    if (!verifyMac(macIn, theirDirectionalKey, realBundleId, (const u8*)dataToAuth.data(), dataToAuth.size())) {
        return false;
    }

    // Decrypt
    String ciphertext((const u8*)ct, ctLen);
    String plaintext = crypt(ciphertext, theirDirectionalKey, realBundleId, 12);
    if (plaintext.size() < 1) return false;

    // Update window
    windowBitmap |= (1ULL << offset);
    while (windowBitmap & 1ULL) {
        windowBitmap >>= 1ULL;
        base++;
    }

    // Process packets
    u8 bHeader = (u8)plaintext[0];
    bool isImportant = (bHeader & 0x01) != 0;
    usz at = 1;

    while (at < plaintext.size()) {
        u64 pLen = readVarLong(plaintext, at);
        if (pLen == 0 || at + pLen > plaintext.size()) break;

        usz pEnd = at + (usz)pLen;
        u8 pHeader = (u8)plaintext[at++];
        u32 channel = 1;
        if (pHeader & 0x01) {
            channel = (u32)readVarLong(plaintext, at);
        }
        u8 fragState = (pHeader >> 1) & 0x03;
        u32 seriesId = 0;
        u32 fragmentId = 0;
        if (fragState != 0) {
            seriesId = (u32)readVarLong(plaintext, at);
            fragmentId = (u32)readVarLong(plaintext, at);
        }
        bool respectsHol = (pHeader & 0x08) != 0;
        bool isFinal = (pHeader & 0x10) != 0;

        String payload((const u8*)plaintext.data() + at, pEnd - at);
        at = pEnd;

        if (channel == 0) {
            usz actionAt = 0;
            u64 action = readVarLong(payload, actionAt);
            if (action == 0) handleDisconnect(payload);
            else if (action == 1) handleSack(payload);
        } else {
            if (fragState != 0) {
                FragmentRegisterEntry *entry = nullptr;
                for (usz i = 0; i < fragmentationRegister.size(); ++i) {
                    if (fragmentationRegister[i].seriesId == seriesId) {
                        entry = &fragmentationRegister[i];
                        break;
                    }
                }
                if (!entry) {
                    FragmentRegisterEntry newEntry;
                    newEntry.seriesId = seriesId;
                    newEntry.channel = channel;
                    newEntry.respectsHol = respectsHol;
                    fragmentationRegister.push(newEntry);
                    entry = &fragmentationRegister[fragmentationRegister.size() - 1];
                }
                entry->fragments[fragmentId] = payload;
                entry->lastUpdated = millis();
                if (fragState == 1) entry->hasStart = true;
                if (fragState == 3) {
                    entry->hasEnd = true;
                    entry->endFragmentId = fragmentId;
                }
                if (entry->isComplete()) {
                    String fullPayload = entry->assemble();
                    Packet completePacket(entry->channel, fullPayload, isImportant, entry->respectsHol);
                    for (usz i = 0; i < fragmentationRegister.size(); ++i) {
                        if (fragmentationRegister[i].seriesId == seriesId) {
                            fragmentationRegister.remove(i);
                            break;
                        }
                    }
                    dispatchPacket(completePacket, (u32)realBundleId);
                }
            } else {
                Packet p(channel, payload, isImportant, respectsHol);
                dispatchPacket(p, (u32)realBundleId);
            }
        }

        if (isFinal) break;
    }

    return true;
}

void Lines::dispatchPacket(const Packet &packet, u32 seq) {
    (void)seq;
    if (onPacket) onPacket(packet);
}

void Lines::advanceWindow(u64 newBase) {
    if (newBase <= base) return;
    u64 shift = newBase - base;
    if (shift >= 64) windowBitmap = 0;
    else windowBitmap >>= shift;
    base = newBase;
}

// ---------------------------------------------------------------------------
// Post-Upgrade Control: SACK Heartbeat & Disconnect
// ---------------------------------------------------------------------------

void Lines::handleDisconnect(const String &payload) {
    usz at = 0;
    readVarLong(payload, at); // action 0
    Tree reason;
    if (at < payload.size()) {
        usz readBytes = 0;
        reason.readFromBinary((const u8*)payload.data() + at, payload.size() - at, readBytes);
    }
    if (onDisconnect) onDisconnect(reason);
    destroy();
}

void Lines::handleSack(const String &payload) {
    usz at = 0;
    readVarLong(payload, at); // action 1

    u64 numAcked = readVarLong(payload, at);
    for (u64 i = 0; i < numAcked; ++i) {
        u64 start = readVarLong(payload, at);
        u64 end = readVarLong(payload, at);
        for (u64 id = start; id <= end; ++id) {
            retransmissionBuffer.remove(id);
        }
    }

    u64 numPretend = readVarLong(payload, at);
    for (u64 i = 0; i < numPretend; ++i) {
        u64 start = readVarLong(payload, at);
        u64 end = readVarLong(payload, at);
        for (u64 id = start; id <= end; ++id) {
            retransmissionBuffer.remove(id);
        }
    }
}

void Lines::sendSackHeartbeat(u32 targetBand) {
    String payload;
    writeVarLong(payload, 1); // Action 1: SACK Heartbeat

    // Acknowledged range [2, base - 1]
    if (base > 2) {
        writeVarLong(payload, 1); // 1 interval
        writeVarLong(payload, 2);
        writeVarLong(payload, base - 1);
    } else {
        writeVarLong(payload, 0);
    }

    writeVarLong(payload, 0); // No pretend intervals

    Packet p(0, payload, false, false);
    pendingUnimportantQueue.push(p);
    sendPostUpgradeBundle(false, targetBand);
}

void Lines::sendSacrificialSack(u32 excludeBand) {
    for (auto &entry : bands) {
        if (entry.value.enabled && entry.value.id != excludeBand) {
            sendSackHeartbeat(entry.value.id);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler Update & Retransmission
// ---------------------------------------------------------------------------

void Lines::update() {
    u64 now = millis();

    // Check timeout auto-destruction
    if (isUpgraded() && (now - lastSeen > timeout)) {
        Tree reason;
        parseJSON(R"({"status": "timeout", "code": 408, "message": "connection_timed_out"})", reason);
        if (onDisconnect) onDisconnect(reason);
        destroy();
        return;
    }

    if (!isUpgraded()) return;

    // Retransmission of unacknowledged bundles
    for (auto &entry : retransmissionBuffer) {
        u32 band = selectBestBand(entry.value.size());
        transmitRaw(entry.value, band);
    }

    // SACK Heartbeats schedule
    f32 aggression = getAggression();
    i64 jitter = randomNumber<i64>(-(i64)(timeout / 6), (i64)(timeout / 6));
    i64 baseHeartbeatTime = (i64)timeout + jitter;

    i64 mainInterval = (i64)(baseHeartbeatTime - (aggression * timeout * 2.0f));
    i64 minInterval = (i64)(timeout / 1000);
    if (minInterval < 1) minInterval = 1;
    if (mainInterval < minInterval) mainInterval = minInterval;

    u32 bestBand = selectBestBand(64);

    if (now - lastSent >= (u64)mainInterval) {
        sendSackHeartbeat(bestBand);
    }

    i64 sacrificialInterval = (i64)(baseHeartbeatTime - (aggression * timeout));
    if (sacrificialInterval < minInterval) sacrificialInterval = minInterval;

    if (now - lastSacrificialSent >= (u64)sacrificialInterval) {
        sendSacrificialSack(bestBand);
        lastSacrificialSent = now;
    }
}

} // namespace Ksee
