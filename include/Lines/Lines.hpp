/**
 * @file Lines.hpp
 * @brief High-performance, cryptographically secure transport engine.
 */

#ifndef LINES_LINES_HPP
#define LINES_LINES_HPP

#include <Ksee/Types.hpp>
#include <Ksee/String.hpp>
#include <Ksee/Array.hpp>
#include <Ksee/Map.hpp>
#include <Ksee/Func.hpp>
#include <Ksee/Tree.hpp>
#include <Ksee/Crypto/ECC.hpp>
#include <Ksee/Crypto/Hash.hpp>
#include <Ksee/Crypto/AEAD.hpp>
#include <Ksee/Crypto/Chacha.hpp>
#include <Ksee/Format/Yaml.hpp>
#include <Ksee/Math/Random.hpp>
#include <Ksee/Math/Interval.hpp>
#include <Ksee/Resource/Comms.hpp>

namespace Ksee {

class Lines;
struct LinesBandSlot;
struct SentBundle;
struct RecvBundle;

using Band = Ksee::Resource::Comms::Band;
using Packet = Ksee::Resource::Comms::Packet;

/**
 * @struct LinesBandSlot
 * @brief Represents a logical slot connecting a Lines instance to a Band.
 */
struct LinesBandSlot {
    Band *band = nullptr;
    Lines *lines = nullptr;
    u64 id = 1;

    ~LinesBandSlot();

    // Rolling statistics for this slot
    u64 bytesSentLastSec = 0;
    u64 bytesRecvLastSec = 0;
    u64 ackedBytesLastSec = 0;
    u64 dutyConsumedLastSec = 0;
    u64 windowResetTime = 0;
    u64 minObservedLatency = 0;

    u64 getSendThroughput() const { return bytesSentLastSec; }
    u64 getRecvThroughput() const { return bytesRecvLastSec; }
    u64 getThroughput() const { return bytesSentLastSec + bytesRecvLastSec; }

    u64 getSendCapacity() const {
        if (dutyConsumedLastSec == 0) return ackedBytesLastSec * 1000;
        return (ackedBytesLastSec * 1000) / dutyConsumedLastSec;
    }

    u64 getRecvCapacity() const { return bytesRecvLastSec; }
    u64 getCapacity() const { return getSendCapacity(); }

    u64 getPotential() const {
        if (!band) return 0;
        u64 cap = getCapacity();
        if (band->idealCapacity > cap) {
            return band->idealCapacity - cap;
        }
        return 0;
    }

    u64 getLatency() const {
        return (minObservedLatency > 0) ? minObservedLatency : 1;
    }

    bool isAvailable() const;
};

/**
 * @struct SentBundle
 * @brief Metadata and payload tracked in outbox.
 */
struct SentBundle {
    u64 sentTime = 0;
    u64 ackTime = 0;                    ///< in ms; 0 if unacknowledged
    u64 duty = 0;                       ///< airtime in ms
    u64 size = 0;                       ///< bundle wire size
    String bundle;                      ///< Kept ONLY for reliable bundles; empty for unreliable/sacrificial
    LinesBandSlot *bandSlot = nullptr;  ///< the band slot we sent on
    bool reliable = true;
    bool sacrificial = false;
};

/**
 * @struct RecvBundle
 * @brief Reception record tracked in inbox.
 */
struct RecvBundle {
    u64 recvTime = 0;
    u64 size = 0;
    LinesBandSlot *bandSlot = nullptr;  ///< the band slot we received on
};

/**
 * @class Lines
 * @brief The Lines protocol engine.
 */
class Lines {
public:
    using Tree = Ksee::Tree<void>;

    // Window and Buffer constants
    static constexpr u32 size = 64;

    // Special Control & Config Packet Intents (Channel 0)
    static constexpr u64 IntentDisconnect = 0;
    static constexpr u64 IntentData = 1;       ///< Default payload intent
    static constexpr u64 IntentSack = 2;       ///< Selective Acknowledgement Heartbeat

    // Cryptographic Identity & Handshake State
    XKeypair epheKeypair;
    u256 theirEphePublic;
    Tree theirMetadata;
    Array<XKeypair> staticKeypairs;
    Array<String> theirStaticPublics;
    Array<String> theirStatics;

    // Session Keys & Directionality
    String sharedKey;
    u256 ourDirectionalKey;
    u256 theirDirectionalKey;
    bool initiator = false;

    // Silicon Sliding Window (Native 64-bit word)
    u64 nonce = 2;
    u64 base = 2;                      ///< Our receiving sliding window base
    u64 sendBase = 2;                  ///< Peer's receive base (our outbox base)
    u64 windowBitmap = 0;
    u64 baseMoveTime = 0;
    u64 retransmitFrom = 0;

    // Buffer Backpressure & Pressure
    Map<u64, SentBundle> outbox;
    Map<u64, RecvBundle> inbox;
    Array<Packet> toBeBundled;         ///< Staged pushes waiting to be bundled

    // Timing & Metrics
    String tune = "";                  ///< Pre-upgrade tuning tag; incorporates into CRC-15 with 0 wire bytes
    u64 lastSeen = 0;
    u64 lastSent = 0;
    u64 upgradeTime = 0;
    u64 timeout = 21300;               ///< Default 21.3s session timeout
    u32 paddingBlockSize = 32;         ///< Block padding alignment (default 32 bytes)
    u32 paddingSize = 32;              ///< Alias for paddingBlockSize
    u64 maxThroughput = 0;             ///< 0 = unlimited

    // Dual Heartbeat Schedulers
    u64 nextBestEffortHeartbeat = 0;
    u64 nextCuriosityHeartbeat = 0;

    // Multi-Band Architecture
    Array<LinesBandSlot*> bands;
    u64 primingBandSlot = 0;

    // Handle Queues & Reordering
    struct HandleSeq {
        u64 nextDeliverBundleId = 0;
        Map<u64, Packet> holQueue;
    };
    Map<u64, HandleSeq> handleSequences;

    // Handshake Callback Wrappers
    struct OnProbeHandler {
        Func<bool(Tree, Tree&)> withMeta;
        Func<bool(Tree)> simple;

        OnProbeHandler() = default;

        template <typename F>
        OnProbeHandler& operator=(F &&f) {
            if constexpr (std::is_invocable_v<F, Tree, Tree&>) {
                withMeta = [fn = std::forward<F>(f)](Tree sel, Tree &meta) -> bool { return (bool)fn(sel, meta); };
                simple = nullptr;
            } else if constexpr (std::is_invocable_v<F, Tree>) {
                simple = [fn = std::forward<F>(f)](Tree sel) -> bool { return (bool)fn(sel); };
                withMeta = nullptr;
            } else if constexpr (std::is_invocable_v<F>) {
                simple = [fn = std::forward<F>(f)](Tree) -> bool { return (bool)fn(); };
                withMeta = nullptr;
            }
            return *this;
        }

        bool operator()(const Tree &sel, Tree &meta) const {
            if (withMeta) return withMeta(sel, meta);
            if (simple) return simple(sel);
            return true;
        }

        explicit operator bool() const {
            return (bool)withMeta || (bool)simple;
        }
    };

    struct OnAnnounceHandler {
        Func<bool(Tree)> withMeta;
        Func<bool()> simple;

        OnAnnounceHandler() = default;

        template <typename F>
        OnAnnounceHandler& operator=(F &&f) {
            if constexpr (std::is_invocable_v<F, Tree>) {
                withMeta = [fn = std::forward<F>(f)](Tree meta) -> bool { return (bool)fn(meta); };
                simple = nullptr;
            } else if constexpr (std::is_invocable_v<F>) {
                simple = [fn = std::forward<F>(f)]() -> bool { return (bool)fn(); };
                withMeta = nullptr;
            }
            return *this;
        }

        bool operator()(const Tree &meta) const {
            if (withMeta) return withMeta(meta);
            if (simple) return simple();
            return true;
        }

        explicit operator bool() const {
            return (bool)withMeta || (bool)simple;
        }
    };

    struct OnUpgradeHandler {
        Func<void(Tree)> withMeta;
        Func<void()> simple;

        OnUpgradeHandler() = default;

        template <typename F>
        OnUpgradeHandler& operator=(F &&f) {
            if constexpr (std::is_invocable_v<F, Tree>) {
                withMeta = [fn = std::forward<F>(f)](Tree t) { (void)fn(t); };
                simple = nullptr;
            } else if constexpr (std::is_invocable_v<F>) {
                simple = [fn = std::forward<F>(f)]() { (void)fn(); };
                withMeta = nullptr;
            }
            return *this;
        }

        void operator()(const Tree &meta) const {
            if (withMeta) withMeta(meta);
            else if (simple) simple();
        }

        explicit operator bool() const {
            return (bool)withMeta || (bool)simple;
        }
    };

    struct OnDisconnectHandler {
        Func<void(Tree, bool)> withByUs;
        Func<void(Tree)> simple;

        OnDisconnectHandler() = default;

        template <typename F>
        OnDisconnectHandler& operator=(F &&f) {
            if constexpr (std::is_invocable_v<F, Tree, bool>) {
                withByUs = [fn = std::forward<F>(f)](Tree t, bool b) { (void)fn(t, b); };
                simple = nullptr;
            } else if constexpr (std::is_invocable_v<F, Tree>) {
                simple = [fn = std::forward<F>(f)](Tree t) { (void)fn(t); };
                withByUs = nullptr;
            } else if constexpr (std::is_invocable_v<F>) {
                simple = [fn = std::forward<F>(f)](Tree) { (void)fn(); };
                withByUs = nullptr;
            }
            return *this;
        }

        void operator()(const Tree &reason, bool byUs) const {
            if (withByUs) withByUs(reason, byUs);
            else if (simple) simple(reason);
        }

        explicit operator bool() const {
            return (bool)withByUs || (bool)simple;
        }
    };

    // Callbacks
    OnProbeHandler onProbe;
    OnAnnounceHandler onAnnounce;
    OnUpgradeHandler onUpgrade;
    OnDisconnectHandler onDisconnect;
    Func<void(Packet)> onPacket;

    Lines();
    ~Lines();

    // Lifecycle
    bool isUpgraded() const { return upgradeTime > 0; }
    void probe(const Tree &sel = Tree());
    void upgrade(const Tree &clientMetadata = Tree());
    void manualUpgrade(const String &key, bool isInitiator, u64 initialNonce = 2);
    void disconnect(const Tree &reason = Tree());
    void reset();

    // Multi-Band Management
    LinesBandSlot* enable(Func<void(String)> sendCallback, Func<String()> recvCallback = nullptr);
    LinesBandSlot* enable(Band &band);
    LinesBandSlot* enable(Band *band);
    LinesBandSlot* enable(LinesBandSlot *slot);
    LinesBandSlot* enable();

    void disable(LinesBandSlot *slot);
    void disable(u64 bandSlotIdx);
    void stun(LinesBandSlot *slot, u64 duration = 0);
    void stun(u64 bandSlotIdx = 0, u64 duration = 0);

    // Band Routing Selectors (returns index in bands, or -1 on failure)
    i64 getBestBand() const;
    i64 selectUnexploredBand(u32 jitter = 2) const;

    // System-wide Metrics
    u64 getSendThroughput() const;
    u64 getRecvThroughput() const;
    u64 getThroughput() const;
    u64 getLatency() const;
    f32 getPressure() const;
    bool couldPush() const;

    // Transmission & Window Operations
    void push(const Packet &packet);
    void flushBundles();
    void pretendReceived(u64 fromDelta, u64 toDelta);
    void setAcknowledged(u64 fromDelta, u64 toDelta, u64 ackTime = 0);

    Array<Interval<u64>> showReceived() const;
    Array<Interval<u64>> showUnavailableToRetransmit() const;

    // Scheduling
    void scheduleNextBestEffortHeartbeat();
    void scheduleNextCuriosityHeartbeat();
    void sendSackHeartbeat(LinesBandSlot *targetSlot = nullptr);
    void sendSackHeartbeat(u64 targetBandSlotIdx);

    // Wire Processing & Parsing
    bool parse(const String &bundle, LinesBandSlot *slot = nullptr);
    bool recv(const String &bundle, LinesBandSlot *slot = nullptr) { return parse(bundle, slot); }

    bool matchesBundle(const String &bundle) const;
    static bool isEncrypted(const String &bytes);

    void update(bool callBandUpdates = true);
    void tick() { update(); }

private:
    u16 getTuneSeed() const;
    void setupDirectionalKeys();
    void transmitBundle(u64 bundleId, const String &rawBundle, LinesBandSlot *slot, bool reliable, bool sacrificial);
    void sendPostUpgradeBundle(const Array<Packet> &packets, bool reliable, bool sacrificial, LinesBandSlot *preferredSlot = nullptr);
    void sendSack(bool sacrificial = false, LinesBandSlot *targetSlot = nullptr);
    void advanceWindow(u64 newBase);
    void advanceSendBase();
    void dispatchPacket(const Packet &packet, u64 bundleId);
    void updateRollingStats();

    void handleProbe(const String &payload, LinesBandSlot *slot);
    void handleAnnounce(const String &payload, LinesBandSlot *slot);
    void handleUpgrade(const String &payload, LinesBandSlot *slot);
    void handleDisconnect(const String &payload);
    void handleSack(const String &payload);
};

} // namespace Ksee

#endif // LINES_LINES_HPP
