/**
 * @file Lines.hpp
 * @brief The Lines Protocol - A high-performance, multi-band stochastic transport layer.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
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
#include <Ksee/Math/Interval.hpp>

namespace Ksee {

class Lines;
class PhysicalBand;
struct BandSlot;
struct SentBundle;
struct RecvBundle;

/**
 * @struct Packet
 * @brief Multiplexed application data unit.
 */
struct Packet {
    enum Delivery : u8 {
        Reliable = 0,    ///< Speed-routed, retransmitted, stored in outbox
        BestEffort = 1,  ///< Min-latency routed, fire-and-forget, never retransmitted
        Curiosity = 2    ///< Headroom-routed stochastic exploration probe
    };

    String payload;
    u64 channel = 1;
    Delivery delivery = Reliable;
    bool respectsOrder = true;

    Packet() = default;

    Packet(const String &p, u64 ch = 1, Delivery del = Reliable, bool order = true)
        : payload(p), channel(ch), delivery(del), respectsOrder(order) {}

    // Backwards-compatible constructor
    Packet(u64 ch, const String &p, bool reliable = true, bool order = true)
        : payload(p), channel(ch), delivery(reliable ? Reliable : BestEffort), respectsOrder(order) {}

    bool isReliable() const { return delivery == Reliable; }
    bool isBestEffort() const { return delivery == BestEffort; }
    bool isCuriosity() const { return delivery == Curiosity; }
};

/**
 * @struct BandSlot
 * @brief Represents a logical slot connecting a Lines instance to a PhysicalBand.
 */
struct BandSlot {
    PhysicalBand *physical = nullptr;
    Lines *lines = nullptr;
    u64 id = 1;

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

    u64 getLatency() const {
        return (minObservedLatency > 0) ? minObservedLatency : 1;
    }

    bool isAvailable() const;
};

/**
 * @class PhysicalBand
 * @brief Physical transmission medium with duty cycle limits, debt regeneration, and shared slot dispatch.
 */
class PhysicalBand {
public:
    u64 lastDebtRegenTime = 0;     ///< Deducts maxDuty from duty every second
    u64 duty = 0;                  ///< Current debt in ms; may exceed maxDuty while transmitting a full packet
    u64 maxDuty = 0;               ///< Duty cycle limit in ms per second (0 = infinite)
    u64 stunnedUntil = 0;          ///< Backoff timestamp in millis
    u64 idealCapacity = 0;         ///< Defaults to 0; favors curiosity packets stochastically
    u64 maxBundleSize = 1400;      ///< Maximum bundle size allowed (0 = infinite)

    Func<String()> recvCallback;
    Func<void(String)> sendCallback;

    Array<BandSlot*> slots;
    bool isDynamicallyAllocated = false;

    PhysicalBand();
    ~PhysicalBand();

    bool couldPush() const;
    void stun(u64 duration = 0);
    void push(const String &bundle);
    void recv(const String &bundle);
    void addSlot(BandSlot *slot);
    void removeSlot(BandSlot *slot);
    void update(bool doLinesUpdates = true);
};

/**
 * @struct SentBundle
 * @brief Metadata and payload tracked in outbox.
 */
struct SentBundle {
    u64 sentTime = 0;
    u64 ackTime = 0;               ///< in ms; 0 if unacknowledged
    u64 duty = 0;                  ///< airtime in ms
    u64 size = 0;                  ///< bundle wire size
    String bundle;                 ///< Kept ONLY for Reliable delivery; empty for BestEffort/Curiosity
    BandSlot *bandSlot = nullptr;  ///< the band slot we sent on
    u64 band = 1;                  ///< legacy numeric ID alias
    Packet::Delivery delivery = Packet::Reliable;
};

/**
 * @struct RecvBundle
 * @brief Reception record tracked in inbox.
 */
struct RecvBundle {
    u64 recvTime = 0;
    u64 size = 0;
    BandSlot *bandSlot = nullptr;  ///< the band slot we received on
    u64 band = 1;                  ///< legacy numeric ID alias
};

/**
 * @class Lines
 * @brief The Lines protocol engine.
 */
class Lines {
public:
    using Tree = Ksee::Tree<void>;
    using BandSlot = Ksee::BandSlot;

    // Window and Buffer constants
    static constexpr u32 size = 64;

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
    Map<u64, String> retransmissionBuffer; ///< Kept for backward compatibility
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
    Array<BandSlot*> bands;
    u64 primingBandSlot = 0;
    u64 primingBand = 1;               ///< Backwards-compatible alias

    // Channel Queues & Reordering
    struct ChannelSeq {
        u64 nextDeliverBundleId = 0;
        Map<u64, Packet> holQueue;
    };
    Map<u64, ChannelSeq> channelSequences;

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
    Func<void()> onReady;              ///< Backwards-compatible alias for onUpgrade
    OnDisconnectHandler onDisconnect;
    Func<void(Packet)> onPacket;
    Func<void()> onDestroy;

    Lines();
    ~Lines();

    // Lifecycle
    bool isUpgraded() const { return upgradeTime > 0; }
    void probe(const Tree &sel = Tree());
    void upgrade(const Tree &clientMetadata = Tree());
    void manualUpgrade(const String &key, bool isInitiator, u64 initialNonce = 2);
    void disconnect(const Tree &reason = Tree());
    void destroy();

    // Multi-Band Management
    BandSlot* enable(Func<void(String)> sendCallback, Func<String()> recvCallback = nullptr);
    BandSlot* enable(PhysicalBand &physicalBand);
    BandSlot* enable(PhysicalBand *physicalBand);
    BandSlot* enable(BandSlot *bandSlot);
    BandSlot* enable();
    BandSlot* enable(Func<void(String)> sendCallback, u64 legacyBandId, u64 initialWeight = 1, u64 maxBundleSize = 1400);

    void disable(BandSlot *slot);
    void disable(u64 bandSlotIdx);
    void stun(BandSlot *slot, u64 duration = 0);
    void stun(u64 bandSlotIdx = 0, u64 duration = 0);

    // Band Routing Selectors (returns index in bands, or -1 on failure)
    i64 getBestReliableBand() const;
    i64 getBestEffortBand() const;
    i64 getBestCuriosityBand() const;

    // System-wide Metrics
    u64 getSendThroughput() const;
    u64 getRecvThroughput() const;
    u64 getThroughput() const;
    u64 getLatency() const;
    f32 getPressure() const;
    bool couldPush() const;

    // Legacy Aliases for Test Compatibility
    f32 getAggression() const { return getPressure(); }
    u64 getWeight() const { return getSendThroughput(); }
    u64 getBandWeight(u64 band) const;

    // Transmission & Window Operations
    void push(const Packet &packet);
    void flushBundles();
    void pretendReceived(u64 fromDelta, u64 toDelta);
    void setAcknowledged(u64 fromDelta, u64 toDelta, u64 ackTime = 0);
    void dropRetransmission(u64 fromDelta, u64 toDelta) {
        setAcknowledged(fromDelta, toDelta, millis());
    }

    Array<Interval<u64>> showReceived() const;
    Array<Interval<u64>> showUnavailableToRetransmit() const;

    // Scheduling
    void scheduleNextBestEffortHeartbeat();
    void scheduleNextCuriosityHeartbeat();
    void sendSackHeartbeat(BandSlot *targetSlot = nullptr);
    void sendSackHeartbeat(u64 targetBandSlotIdx);

    // Wire Processing & Parsing
    bool parse(const String &bundle, BandSlot *slot = nullptr);
    bool parse(const String &bundle, u64 legacyBandId);
    bool recv(const String &bundle, BandSlot *slot = nullptr) { return parse(bundle, slot); }
    bool recv(const String &bundle, u64 legacyBandId) { return parse(bundle, legacyBandId); }

    bool matchesBundle(const String &bundle) const;
    static bool isEncrypted(const String &bytes);

    void update(bool callPBUpdates = true);
    void tick() { update(); }

private:
    u16 getTuneSeed() const;
    void setupDirectionalKeys();
    void transmitBundle(u64 bundleId, const String &rawBundle, BandSlot *slot, Packet::Delivery delivery);
    void sendPostUpgradeBundle(const Array<Packet> &packets, Packet::Delivery delivery, BandSlot *preferredSlot = nullptr);
    void sendSack(Packet::Delivery delivery, BandSlot *targetSlot = nullptr);
    void advanceWindow(u64 newBase);
    void advanceSendBase();
    void dispatchPacket(const Packet &packet, u64 bundleId);
    void updateRollingStats();

    void handleProbe(const String &payload, BandSlot *slot);
    void handleAnnounce(const String &payload, BandSlot *slot);
    void handleUpgrade(const String &payload, BandSlot *slot);
    void handleDisconnect(const String &payload);
    void handleSack(const String &payload);
};

} // namespace Ksee

#endif // LINES_LINES_HPP
