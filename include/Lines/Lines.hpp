/**
 * @file Lines.hpp
 * @brief The Lines Protocol - A high-performance multiplexed, encrypted,
 * multi-band stochastic transport layer for Ksee.
 */

#ifndef LINES_LINES_HPP
#define LINES_LINES_HPP

#include <Ksee/Types.hpp>
#include <Ksee/Func.hpp>
#include <Ksee/Array.hpp>
#include <Ksee/String.hpp>
#include <Ksee/Map.hpp>
#include <Ksee/Tree.hpp>
#include <Ksee/Time.hpp>
#include <Ksee/Crypto/ECC.hpp>
#include <Ksee/Crypto/Chacha.hpp>
#include <Ksee/Crypto/Hash.hpp>
#include <Ksee/Crypto/AEAD.hpp>
#include <Ksee/Format/Yaml.hpp>
#include <Ksee/Math/Random.hpp>

namespace Ksee {

using Keypair = XKeypair;

/**
 * @struct FromTo
 * @brief Represents a closed interval [from, to] for SACK heartbeats.
 */
struct FromTo {
    u64 from = 0;
    u64 to = 0;

    FromTo() = default;
    FromTo(u64 f, u64 t) : from(f), to(t) {}
};

/**
 * @class Bitmap
 * @brief Dynamic bitset respecting arbitrary window sizes.
 */
class Bitmap {
public:
    Array<u64> words;
    usz numBits = 64;

    Bitmap(usz bits = 64) {
        resize(bits);
    }

    void resize(usz bits) {
        numBits = (bits == 0) ? 64 : bits;
        usz numWords = (numBits + 63) / 64;
        words.allocate(numWords);
        for (usz i = 0; i < words.size(); ++i) {
            words[i] = 0;
        }
    }

    void clear() {
        for (usz i = 0; i < words.size(); ++i) {
            words[i] = 0;
        }
    }

    void reset() {
        clear();
    }

    bool test(usz bit) const {
        if (bit >= numBits) return false;
        usz wordIdx = bit / 64;
        usz bitIdx = bit % 64;
        if (wordIdx >= words.size()) return false;
        return (words[wordIdx] & (1ULL << bitIdx)) != 0;
    }

    void set(usz bit, bool value = true) {
        if (bit >= numBits) {
            resize(bit + 64);
        }
        usz wordIdx = bit / 64;
        usz bitIdx = bit % 64;
        if (wordIdx >= words.size()) return;
        if (value) {
            words[wordIdx] |= (1ULL << bitIdx);
        } else {
            words[wordIdx] &= ~(1ULL << bitIdx);
        }
    }

    void shiftRight(usz count) {
        if (count == 0) return;
        if (count >= numBits) {
            clear();
            return;
        }
        usz wordShift = count / 64;
        usz bitShift = count % 64;
        usz numWords = words.size();

        for (usz i = 0; i < numWords; ++i) {
            usz src = i + wordShift;
            u64 low = (src < numWords) ? (words[src] >> bitShift) : 0ULL;
            u64 high = 0ULL;
            if (bitShift > 0 && src + 1 < numWords) {
                high = words[src + 1] << (64 - bitShift);
            }
            words[i] = low | high;
        }
    }

    Bitmap &operator=(u64 val) {
        clear();
        if (words.size() > 0) words[0] = val;
        return *this;
    }

    u64 operator&(u64 mask) const {
        if (words.size() == 0) return 0;
        return words[0] & mask;
    }

    Bitmap &operator>>=(u64 shift) {
        shiftRight(shift);
        return *this;
    }

    Bitmap &operator|=(u64 mask) {
        if (words.size() > 0) words[0] |= mask;
        return *this;
    }

    bool operator[](usz bit) const {
        return test(bit);
    }
};

/**
 * @struct Packet
 * @brief Individual multiplexed data unit carried inside Lines bundles.
 */
struct Packet {
    u32 channel = 1;
    String payload;
    bool isImportant = true;
    bool respectsHOL = true;
    u8 fragState = 0;       ///< 0=none, 1=start, 2=middle, 3=end
    u32 seriesId = 0;
    u32 fragmentId = 0;
    u32 channelSeq = 0;     ///< Per-channel sequence for HOL blocking

    Packet() = default;
    Packet(u32 ch, const String &p, bool important = true, bool hol = true)
        : channel(ch), payload(p), isImportant(important), respectsHOL(hol) {}
};

/**
 * @class FragmentRegisterEntry
 * @brief Tracks and reassembles incoming fragment series across stochastic datagrams.
 */
class FragmentRegisterEntry {
public:
    u32 seriesId = 0;
    u32 channel = 1;
    bool respectsHol = true;
    u32 channelSeq = 0;
    bool hasStart = false;
    bool hasEnd = false;
    u32 endFragmentId = 0;
    Map<u32, String> fragments;
    u64 lastUpdated = 0;

    FragmentRegisterEntry() = default;

    bool isComplete() const;
    String assemble() const;
};

/**
 * @class Lines
 * @brief The core Lines protocol engine.
 */
class Lines {
public:
    using Tree = Ksee::Tree<void>;

    // --- Cryptographic Identity & Handshake State ---
    Keypair epheKeypair;             ///< Ephemeral keypair for session ECDH
    u256 theirEphePublic;            ///< Peer ephemeral public key
    Tree theirMetadata;              ///< Metadata received from peer
    Tree metadata;                   ///< Local metadata to prove to peer
    Tree selector;                   ///< Probing selector tree
    Array<Keypair> staticKeypairs;   ///< Static keypairs to prove to peer
    Array<String> theirStaticPublics;///< Static public keys proven by peer
    Array<String> theirStatics;      ///< Synced alias for theirStaticPublics

    // --- Directional Session Keys & Configuration ---
    String sharedKey;                ///< 32-byte shared root session key
    u256 ourDirectionalKey;          ///< Direction-specific transmission key
    u256 theirDirectionalKey;        ///< Direction-specific reception key
    bool initiator = false;          ///< Whether local instance initiated handshake
    u32 size = 64;                   ///< Window size and retransmission buffer capacity
    u64 nonce = 2;                   ///< Last sent bundle nonce / ID
    u64 base = 2;                    ///< Sliding window base bundle ID
    Bitmap windowBitmap;             ///< Dynamic sliding window bitmap respecting size
    u64 retransmitFrom = 0;          ///< Retransmission offset / cursor

    u64 lastSeen = 0;                ///< Timestamp (millis) of last received bundle
    u64 lastSent = 0;                ///< Timestamp (millis) of last sent bundle
    u64 lastSacrificialSent = 0;     ///< Timestamp (millis) of last sacrificial heartbeat
    u64 timeout = 20000;             ///< Milliseconds before automatic teardown
    u32 paddingBlockSize = 32;       ///< Padding block size alignment (default 32 bytes)

    // --- Multi-Band Architecture ---
    struct Band {
        u32 id = 0;
        Func<void(String)> sendCallback;
        u64 weight = 1;              ///< Reception speed in bytes/sec (min 1 when active)
        u32 mtu = 1024;              ///< Maximum transmission unit for this band
        bool enabled = false;
        bool occupied = false;
        u64 bytesInInterval = 0;
        u64 intervalStartTime = 0;
    };
    Map<u32, Band> bands;

    // --- Transmission & Retransmission Buffers ---
    Map<u64, String> retransmissionBuffer; ///< Unacknowledged important bundles
    Array<Packet> pendingImportantQueue;
    Array<Packet> pendingUnimportantQueue;
    Array<FragmentRegisterEntry> fragmentationRegister;

    // --- Channel Sequencing for Head-of-Line Blocking ---
    struct ChannelSeq {
        u32 nextExpected = 0;
        Map<u32, Packet> holQueue;
    };
    Map<u32, ChannelSeq> channelSequences;
    Map<u32, u32> outgoingChannelSeq;
    u32 nextFragmentationSeriesId = 1;

    // --- Callbacks ---
    Func<bool()> onUpgrade;          ///< Triggered on server side on upgrade receipt
    Func<void(Tree)> onDisconnect;   ///< Triggered when connection is severed
    Func<void()> onReady;            ///< Triggered when encrypted channel is live
    Func<bool(Tree)> onProbe;        ///< Triggered on server when probed
    Func<bool()> onAnnounce;         ///< Triggered on client when announce arrives
    Func<void(Packet)> onPacket;     ///< Triggered when application packet arrives

    // --- Lifecycle & Initialization ---
    Lines();
    ~Lines();

    bool isUpgraded() const { return sharedKey.size() > 0; }
    void probe(const Tree &sel);
    void manualUpgrade(const String &key, bool isInitiator, u64 initialNonce = 2);
    void disconnect(const Tree &reason = Tree());
    void destroy();

    // --- Multi-Band Management ---
    void enable(Func<void(String)> callback, u32 band = 0, u64 initialWeight = 1, u32 mtu = 1024);
    void disable(u32 band = 0);
    f32 getAggression() const;
    bool couldPush() const;
    u64 getWeight() const;
    u64 getBandWeight(u32 band = 0) const;

    // --- Data Transmission & Sliding Window ---
    void push(const Packet &packet);
    void pretendReceived(u64 from, u64 to);
    Array<FromTo> showReceived() const;
    Array<FromTo> showUnavailableToRetransmit() const;

    // --- Parsing & Roaming Engine ---
    bool parse(const String &bundle, u32 band = 0);
    bool matchesBundle(const String &bundle) const;
    static bool isEncrypted(const String &bytes);

    // --- Periodic Scheduler & Retransmission ---
    void update();
    void tick() { update(); }
    void sendSackHeartbeat(u32 targetBand = 0);

private:
    void setupDirectionalKeys();
    u32 selectBestBand(u32 requiredPayloadSize) const;
    void flushQueues();
    void sendPostUpgradeBundle(bool important, u32 bandId);
    void sendSacrificialSack(u32 excludeBand);
    void transmitRaw(const String &bundle, u32 bandId);
    void advanceWindow(u64 newBase);
    void dispatchPacket(const Packet &packet, u32 seq);
    void updateBandReception(u32 bandId, usz bytesCount);

    // Handshake packet handlers
    void handleProbe(const String &payload, u32 bandId);
    void handleAnnounce(const String &payload, u32 bandId);
    void handleUpgrade(const String &payload, u32 bandId);
    void handleDisconnect(const String &payload);
    void handleSack(const String &payload);
};

} // namespace Ksee

// Global alias for compatibility
using Lines = Ksee::Lines;
using Packet = Ksee::Packet;
using FromTo = Ksee::FromTo;
using Bitmap = Ksee::Bitmap;

#endif // LINES_LINES_HPP
