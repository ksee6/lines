/**
 * @file Patches.hpp
 * @brief The Patches Routing & Gateway Protocol.
 *
 * Sovereign fractal tree routing, multi-carrier BGP replacement,
 * cut-through channel switching, and protocol bridging built on top of Lines.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

#ifndef LINES_PATCHES_HPP
#define LINES_PATCHES_HPP

#include "Lines.hpp"
#include <Ksee/Tree.hpp>
#include <Ksee/Path.hpp>
#include <Ksee/Array.hpp>
#include <Ksee/String.hpp>
#include <Ksee/Func.hpp>

namespace Ksee {

struct PatchConnection {
    Lines *lines = nullptr;
    Array<Path> pathsRegisteredUnder;
    u8 ttl = 255;
    bool isUpstream = false;
    bool owned = true;

    PatchConnection() = default;
    PatchConnection(Lines *l, bool own = true) : lines(l), owned(own) {}
    ~PatchConnection();
};

struct PatchCircuit {
    PatchConnection *inConn = nullptr;
    u64 inChannel = 0;
    PatchConnection *outConn = nullptr;
    u64 outChannel = 0;
    Path source;
    Path destination;
    bool isLocalOverride = false;
};

struct PatchOverride {
    Path pattern;
    Func<void(const Path &source, const Path &destination, const String &bundle, u8 ttl)> handler;
};

struct PatchSuggestion {
    Array<String> statics;
    Array<Path> paths;
};

class Patches : public Tree<void> {
public:
    Array<PhysicalBand*> physicalBands;
    Path path;
    bool autoInferPath = true;
    XKeypair epheKeypair;
    Array<XKeypair> staticKeypairs;
    u64 maxConnections = 0; // 0 = unlimited
    Array<PatchConnection*> connections;
    String name = "Patches";

    Array<PatchSuggestion> suggestions;
    Array<PatchOverride> overrides;
    Array<PatchCircuit> circuits;

    // Handlers
    Func<Array<Path>(Lines &client, const Tree &metadata, const Array<Path> &selfProclaimedPath)> onUpgradeHandler;
    Func<bool(const Tree &selector, Tree &announceMetadata)> onProbeHandler;
    Func<bool(Lines &wouldBeClient, const Tree &metadata, const Array<String> &statics)> onAnnounceHandler;

    Patches();
    explicit Patches(const Path &p);
    virtual ~Patches();

    // Suggestions for static infrastructure peering (BGP multi-carrier transit)
    void addSuggestion(const Array<String> &statics, const Array<Path> &paths);
    void addSuggestion(const String &staticKey, const Path &grantedPath);

    // Callbacks
    template <typename F>
    void onUpgrade(F &&fn) {
        if constexpr (std::is_invocable_r_v<Array<Path>, F, Lines&, const Tree&, const Array<Path>&>) {
            onUpgradeHandler = [f = std::forward<F>(fn)](Lines &c, const Tree &m, const Array<Path> &p) -> Array<Path> {
                return f(c, m, p);
            };
        } else if constexpr (std::is_invocable_r_v<Array<Path>, F, Lines&, const Tree&>) {
            onUpgradeHandler = [f = std::forward<F>(fn)](Lines &c, const Tree &m, const Array<Path>&) -> Array<Path> {
                return f(c, m);
            };
        } else if constexpr (std::is_invocable_r_v<Array<Path>, F, Lines&>) {
            onUpgradeHandler = [f = std::forward<F>(fn)](Lines &c, const Tree&, const Array<Path>&) -> Array<Path> {
                return f(c);
            };
        } else if constexpr (std::is_invocable_v<F, Lines&>) {
            onUpgradeHandler = [f = std::forward<F>(fn)](Lines &c, const Tree&, const Array<Path>&) -> Array<Path> {
                f(c);
                return Array<Path>();
            };
        } else if constexpr (std::is_invocable_v<F>) {
            onUpgradeHandler = [f = std::forward<F>(fn)](Lines&, const Tree&, const Array<Path>&) -> Array<Path> {
                f();
                return Array<Path>();
            };
        }
    }

    template <typename F>
    void onProbe(F &&fn) {
        if constexpr (std::is_invocable_r_v<bool, F, const Tree&, Tree&>) {
            onProbeHandler = std::forward<F>(fn);
        } else if constexpr (std::is_invocable_v<F, const Tree&>) {
            onProbeHandler = [f = std::forward<F>(fn)](const Tree &sel, Tree&) -> bool {
                f(sel);
                return true;
            };
        } else if constexpr (std::is_invocable_v<F>) {
            onProbeHandler = [f = std::forward<F>(fn)](const Tree&, Tree&) -> bool {
                f();
                return true;
            };
        }
    }

    template <typename F>
    void onAnnounce(F &&fn) {
        if constexpr (std::is_invocable_r_v<bool, F, Lines&, const Tree&, const Array<String>&>) {
            onAnnounceHandler = std::forward<F>(fn);
        } else if constexpr (std::is_invocable_v<F, Lines&, const Tree&>) {
            onAnnounceHandler = [f = std::forward<F>(fn)](Lines &c, const Tree &m, const Array<String>&) -> bool {
                return f(c, m);
            };
        } else if constexpr (std::is_invocable_v<F, Lines&>) {
            onAnnounceHandler = [f = std::forward<F>(fn)](Lines &c, const Tree&, const Array<String>&) -> bool {
                f(c);
                return true;
            };
        } else if constexpr (std::is_invocable_v<F>) {
            onAnnounceHandler = [f = std::forward<F>(fn)]() -> bool {
                f();
                return true;
            };
        }
    }

    // Overrides for protocol bridging (e.g. IPv4, UDP, TUN)
    void override(const Path &sourcePattern, Func<void(const Path &source, const Path &destination, const String &bundle, u8 ttl)> handler);
    void override(const String &sourcePattern, Func<void(const Path &source, const Path &destination, const String &bundle, u8 ttl)> handler) {
        override(Path(sourcePattern), handler);
    }

    // Media & Discovery
    void addPhysicalBand(PhysicalBand *pb);
    void addPhysicalBand(PhysicalBand &pb) { addPhysicalBand(&pb); }

    void probe(const Tree &metadata = Tree());
    void announce(const Tree &metadata = Tree());

    // Circuit establishment & Transmission
    bool open(const Path &destination, u64 localChannel = 2, u8 ttl = 255);
    bool write(const Path &source, const Path &destination, const String &bundle, u8 ttl = 255);
    bool write(const Path &destination, const String &bundle, u8 ttl = 255) {
        return write(path.isEmpty() ? Path::Self : path, destination, bundle, ttl);
    }

    // Direct link binding
    PatchConnection* addConnection(Lines *lines, bool isUpstream = false, bool takeOwnership = false);

    // Lifecycle
    void update();
    void destroy();

private:
    void setupLinesInstance(Lines *l);
    void handleChannel1(PatchConnection *conn, const Packet &packet);
    void handleDataChannel(PatchConnection *conn, const Packet &packet);
    PatchConnection* findRoute(const Path &destination) const;
    PatchOverride* findOverride(const Path &destination);
    bool hasCommonPath(PatchConnection *conn, const Path &source) const;
    u64 allocateLocalChannel(PatchConnection *conn);
    void setupClientHandlers(Lines *client, PatchConnection *conn);
};

} // namespace Ksee

#endif // LINES_PATCHES_HPP
