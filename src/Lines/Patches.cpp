/**
 * @file Patches.cpp
 * @brief High-performance implementation of the Patches routing and gateway fabric.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

#include "../../include/Lines/Patches.hpp"
#include <cstdio>

namespace Ksee {

// ---------------------------------------------------------------------------
// VarInt Helper Primitives
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

static inline bool isPathPrefix(const Path &prefix, const Path &target) {
    if (prefix.parts.size() > target.parts.size()) return false;
    for (usz i = 0; i < prefix.parts.size(); ++i) {
        if (prefix.parts[i] != target.parts[i]) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// PatchConnection Lifecycle
// ---------------------------------------------------------------------------

PatchConnection::~PatchConnection() {
    if (owned && lines) {
        lines->destroy();
        delete lines;
        lines = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Patches Construction & Configuration
// ---------------------------------------------------------------------------

Patches::Patches() : Tree<void>() {
    path = Path();
    autoInferPath = true;
}

Patches::Patches(const Path &p) : Tree<void>() {
    path = p;
    autoInferPath = false;
}

Patches::~Patches() {
    destroy();
}

void Patches::destroy() {
    circuits.clear();
    overrides.clear();
    for (usz i = 0; i < connections.size(); ++i) {
        delete connections[i];
    }
    connections.clear();
}

void Patches::addSuggestion(const Array<String> &statics, const Array<Path> &paths) {
    PatchSuggestion s;
    s.statics = statics;
    s.paths = paths;
    suggestions.push(s);
}

void Patches::addSuggestion(const String &staticKey, const Path &grantedPath) {
    Array<String> statics;
    statics.push(staticKey);
    Array<Path> paths;
    paths.push(grantedPath);
    addSuggestion(statics, paths);
}

void Patches::override(const Path &sourcePattern, Func<void(const Path &source, const Path &destination, const String &bundle, u8 ttl)> handler) {
    PatchOverride ov;
    ov.pattern = sourcePattern;
    ov.handler = handler;
    overrides.push(ov);
}

void Patches::addPhysicalBand(PhysicalBand *pb) {
    if (pb) physicalBands.push(pb);
}

void Patches::setupLinesInstance(Lines *l) {
    if (!l) return;
    l->tune = "Patches";
    for (usz i = 0; i < physicalBands.size(); ++i) {
        if (physicalBands[i]) l->enable(*physicalBands[i]);
    }
}

PatchConnection* Patches::addConnection(Lines *lines, bool isUpstream, bool takeOwnership) {
    if (!lines) return nullptr;
    lines->tune = "Patches";

    PatchConnection *conn = new PatchConnection(lines, takeOwnership);
    conn->isUpstream = isUpstream;
    connections.push(conn);

    setupClientHandlers(lines, conn);
    return conn;
}

// ---------------------------------------------------------------------------
// Client / Peer Handlers & Channel Setup
// ---------------------------------------------------------------------------

void Patches::setupClientHandlers(Lines *client, PatchConnection *conn) {
    client->onPacket = [this, conn](Packet p) {
        if (p.channel == 1) {
            handleChannel1(conn, p);
        } else {
            handleDataChannel(conn, p);
        }
    };

    client->onUpgrade = [this, client, conn](Tree peerMetadata) {
        // Collect self-proclaimed paths
        Array<Path> selfProclaimed;
        if (peerMetadata.has("path")) {
            selfProclaimed.push(Path(peerMetadata.get("path")->asString()));
        }

        // Apply suggestions matching client static public keys
        for (usz s = 0; s < suggestions.size(); ++s) {
            for (usz cp = 0; cp < client->theirStaticPublics.size(); ++cp) {
                const String &pk = client->theirStaticPublics[cp];
                for (usz sk = 0; sk < suggestions[s].statics.size(); ++sk) {
                    if (suggestions[s].statics[sk] == pk) {
                        for (usz p = 0; p < suggestions[s].paths.size(); ++p) {
                            conn->pathsRegisteredUnder.push(suggestions[s].paths[p]);
                        }
                    }
                }
            }
        }

        // Invoke user onUpgrade handler
        if (onUpgradeHandler) {
            Array<Path> userGranted = onUpgradeHandler(*client, peerMetadata, selfProclaimed);
            for (usz i = 0; i < userGranted.size(); ++i) {
                conn->pathsRegisteredUnder.push(userGranted[i]);
            }
        }

        // If no path was assigned, automatically generate child under our path
        if (conn->pathsRegisteredUnder.isEmpty()) {
            Path leased = generate(path);
            conn->pathsRegisteredUnder.push(leased);
        }

        // Register in local Tree
        for (usz i = 0; i < conn->pathsRegisteredUnder.size(); ++i) {
            push(conn->pathsRegisteredUnder[i]);
        }

        // Send message 1 on Channel 1: Your Path
        String msg;
        encodeVarInt(1, msg); // action 1: Your path
        encodeVarInt(conn->pathsRegisteredUnder.size(), msg);
        for (usz i = 0; i < conn->pathsRegisteredUnder.size(); ++i) {
            String pStr = conn->pathsRegisteredUnder[i].toString();
            encodeVarInt(pStr.size(), msg);
            msg += pStr;
        }
        client->push(Packet(msg, 1, Packet::BestEffort));
    };

    client->onDisconnect = [this, conn](Tree, bool) {
        // Free all paths taken by this client
        for (usz i = 0; i < conn->pathsRegisteredUnder.size(); ++i) {
            deleteKey(conn->pathsRegisteredUnder[i]);
        }

        // Clean up circuits associated with this connection
        for (usz i = circuits.size(); i > 0; --i) {
            usz idx = i - 1;
            if (circuits[idx].inConn == conn || circuits[idx].outConn == conn) {
                circuits.remove(idx);
            }
        }

        // Mark connection as inactive
        for (usz i = 0; i < connections.size(); ++i) {
            if (connections[i] == conn) {
                connections.remove(i);
                delete conn;
                break;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Probing & Announcing
// ---------------------------------------------------------------------------

void Patches::probe(const Tree &metadata) {
    Lines *lines = new Lines();
    setupLinesInstance(lines);
    lines->staticKeypairs = staticKeypairs;

    PatchConnection *conn = addConnection(lines, true, true);

    Tree selector = metadata;
    selector.push("name", name);
    if (!autoInferPath && !path.isEmpty()) {
        selector.push("path", path.toString());
    }

    lines->onAnnounce = [this, lines](Tree serverMeta) {
        if (onAnnounceHandler && !onAnnounceHandler(*lines, serverMeta, lines->theirStaticPublics)) {
            lines->destroy();
            return false;
        }
        Tree clientMeta;
        clientMeta.push("name", name);
        if (!autoInferPath && !path.isEmpty()) {
            clientMeta.push("path", path.toString());
        }
        lines->upgrade(clientMeta);
        return true;
    };

    lines->probe(selector);
}

void Patches::announce(const Tree &metadata) {
    for (usz i = 0; i < connections.size(); ++i) {
        if (connections[i] && connections[i]->lines) {
            Tree meta = metadata;
            meta.push("name", name);
            connections[i]->lines->onProbe = [this](Tree, Tree &announceMeta) {
                announceMeta.push("name", name);
                return true;
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Routing & Overrides
// ---------------------------------------------------------------------------

PatchOverride* Patches::findOverride(const Path &destination) {
    for (usz i = 0; i < overrides.size(); ++i) {
        if (destination.isIpv4() && overrides[i].pattern.parts.size() > 0 &&
            (overrides[i].pattern.parts[0] == "4" || overrides[i].pattern.parts[0] == "3")) {
            return &overrides[i];
        }
        if (destination.isIpv6() && overrides[i].pattern.parts.size() > 0 &&
            (overrides[i].pattern.parts[0] == "6" || overrides[i].pattern.parts[0] == "4")) {
            return &overrides[i];
        }
        if (overrides[i].pattern.common(destination) || isPathPrefix(overrides[i].pattern, destination)) {
            return &overrides[i];
        }
    }
    return nullptr;
}

PatchConnection* Patches::findRoute(const Path &destination) const {
    String dstStr = destination.toString();
    // 1. Check if destination is a child registered under one of our connections
    for (usz i = 0; i < connections.size(); ++i) {
        PatchConnection *c = connections[i];
        if (c->isUpstream) continue;
        for (usz p = 0; p < c->pathsRegisteredUnder.size(); ++p) {
            String pStr = c->pathsRegisteredUnder[p].toString();
            if (dstStr == pStr ||
                dstStr.startsWith(pStr + ".") ||
                dstStr.startsWith(pStr + "/") ||
                isPathPrefix(c->pathsRegisteredUnder[p], destination) ||
                c->pathsRegisteredUnder[p].common(destination)) {
                return c;
            }
        }
    }

    // 2. Default Gateway (upstream connection / 1.1)
    for (usz i = 0; i < connections.size(); ++i) {
        if (connections[i]->isUpstream) {
            return connections[i];
        }
    }

    return nullptr;
}

bool Patches::hasCommonPath(PatchConnection *conn, const Path &source) const {
    if (conn->isUpstream) return true;
    if (conn->pathsRegisteredUnder.isEmpty()) return true;
    String srcStr = source.toString();
    for (usz i = 0; i < conn->pathsRegisteredUnder.size(); ++i) {
        String pStr = conn->pathsRegisteredUnder[i].toString();
        if (srcStr == pStr ||
            srcStr.startsWith(pStr + ".") ||
            srcStr.startsWith(pStr + "/") ||
            isPathPrefix(conn->pathsRegisteredUnder[i], source) ||
            conn->pathsRegisteredUnder[i].common(source)) {
            return true;
        }
    }
    return false;
}

u64 Patches::allocateLocalChannel(PatchConnection *conn) {
    u64 candidate = 2;
    while (true) {
        bool used = false;
        for (usz i = 0; i < circuits.size(); ++i) {
            if ((circuits[i].inConn == conn && circuits[i].inChannel == candidate) ||
                (circuits[i].outConn == conn && circuits[i].outChannel == candidate)) {
                used = true;
                break;
            }
        }
        if (!used) return candidate;
        candidate++;
    }
}

// ---------------------------------------------------------------------------
// Channel 1 Control Protocol Handling
// ---------------------------------------------------------------------------

void Patches::handleChannel1(PatchConnection *conn, const Packet &packet) {
    const u8 *data = (const u8*)packet.payload.data();
    usz len = packet.payload.size();
    usz offset = 0;

    u64 action = 0;
    if (!decodeVarInt(data, len, offset, action)) return;
    // printf("[Patches %s] handleChannel1 action=%llu\n", path.toString().data(), (unsigned long long)action);

    // Action 1: Your Path (Lease assignment from upstream)
    if (action == 1) {
        u64 pathCount = 0;
        if (!decodeVarInt(data, len, offset, pathCount)) return;

        Array<Path> granted;
        for (u64 i = 0; i < pathCount; ++i) {
            u64 pLen = 0;
            if (!decodeVarInt(data, len, offset, pLen) || offset + pLen > len) return;
            String pStr(data + offset, (usz)pLen);
            offset += pLen;
            granted.push(Path(pStr));
        }

        if (autoInferPath) {
            if (granted.size() > 0) {
                path = granted[0];
                autoInferPath = false;
            }
        } else {
            bool found = false;
            for (usz i = 0; i < granted.size(); ++i) {
                if (granted[i] == path) {
                    found = true;
                    break;
                }
            }
            if (!found || granted.isEmpty()) {
                conn->lines->disconnect();
            }
        }
        return;
    }

    // Action 2: Open (Request End-to-End Virtual Circuit)
    if (action == 2) {
        if (offset >= len) return;
        u8 ttl = data[offset++];
        u64 clientChannel = 0;
        if (!decodeVarInt(data, len, offset, clientChannel)) return;

        u64 srcLen = 0;
        if (!decodeVarInt(data, len, offset, srcLen) || offset + srcLen > len) return;
        String srcStr(data + offset, (usz)srcLen);
        offset += srcLen;

        u64 dstLen = 0;
        if (!decodeVarInt(data, len, offset, dstLen) || offset + dstLen > len) return;
        String dstStr(data + offset, (usz)dstLen);
        offset += dstLen;

        Path srcPath(srcStr);
        Path dstPath(dstStr);

        // Check loop prevention TTL
        if (ttl == 0) {
            String err;
            encodeVarInt(4, err); // Action 4: Open Err
            encodeVarInt(clientChannel, err);
            conn->lines->push(Packet(err, 1, Packet::BestEffort));
            return;
        }

        // Verify that client owns or shares prefix with source
        if (!hasCommonPath(conn, srcPath)) {
            String err;
            encodeVarInt(4, err);
            encodeVarInt(clientChannel, err);
            conn->lines->push(Packet(err, 1, Packet::BestEffort));
            return;
        }

        // Check if destination hits a local override (e.g. IPv4 bridge, local service)
        PatchOverride *ov = findOverride(dstPath);
        if (ov) {
            PatchCircuit circ;
            circ.inConn = conn;
            circ.inChannel = clientChannel;
            circ.outConn = nullptr;
            circ.outChannel = 0;
            circ.source = srcPath;
            circ.destination = dstPath;
            circ.isLocalOverride = true;
            circuits.push(circ);

            String ok;
            encodeVarInt(3, ok); // Action 3: Open OK
            encodeVarInt(clientChannel, ok);
            conn->lines->push(Packet(ok, 1, Packet::BestEffort));
            return;
        }

        // Route to next hop
        PatchConnection *nextHop = findRoute(dstPath);
        if (!nextHop || nextHop == conn) {
            String err;
            encodeVarInt(4, err);
            encodeVarInt(clientChannel, err);
            conn->lines->push(Packet(err, 1, Packet::BestEffort));
            return;
        }

        u64 forwardChannel = allocateLocalChannel(nextHop);

        PatchCircuit circ;
        circ.inConn = conn;
        circ.inChannel = clientChannel;
        circ.outConn = nextHop;
        circ.outChannel = forwardChannel;
        circ.source = srcPath;
        circ.destination = dstPath;
        circ.isLocalOverride = false;
        circuits.push(circ);

        // Forward Open on next hop link
        String fwd;
        encodeVarInt(2, fwd);
        fwd.push((char)(ttl - 1));
        encodeVarInt(forwardChannel, fwd);
        encodeVarInt(srcStr.size(), fwd);
        fwd += srcStr;
        encodeVarInt(dstStr.size(), fwd);
        fwd += dstStr;
        nextHop->lines->push(Packet(fwd, 1, Packet::BestEffort));
        return;
    }

    // Action 3: Open OK (Circuit Confirmed)
    if (action == 3) {
        u64 channel = 0;
        if (!decodeVarInt(data, len, offset, channel)) return;

        for (usz i = 0; i < circuits.size(); ++i) {
            if (circuits[i].outConn == conn && circuits[i].outChannel == channel) {
                if (circuits[i].inConn && circuits[i].inConn->lines) {
                    String ok;
                    encodeVarInt(3, ok);
                    encodeVarInt(circuits[i].inChannel, ok);
                    circuits[i].inConn->lines->push(Packet(ok, 1, Packet::BestEffort));
                }
                return;
            }
        }
        return;
    }

    // Action 4: Open Err (Circuit Failed)
    if (action == 4) {
        u64 channel = 0;
        if (!decodeVarInt(data, len, offset, channel)) return;

        for (usz i = circuits.size(); i > 0; --i) {
            usz idx = i - 1;
            if (circuits[idx].outConn == conn && circuits[idx].outChannel == channel) {
                if (circuits[idx].inConn && circuits[idx].inConn->lines) {
                    String err;
                    encodeVarInt(4, err);
                    encodeVarInt(circuits[idx].inChannel, err);
                    circuits[idx].inConn->lines->push(Packet(err, 1, Packet::BestEffort));
                }
                circuits.remove(idx);
                return;
            }
        }
        return;
    }
}

// ---------------------------------------------------------------------------
// Cut-Through Data Plane Switching (Channels >= 2)
// ---------------------------------------------------------------------------

void Patches::handleDataChannel(PatchConnection *conn, const Packet &packet) {
    for (usz i = 0; i < circuits.size(); ++i) {
        PatchCircuit &c = circuits[i];

        // Inbound -> Outbound
        if (c.inConn == conn && c.inChannel == packet.channel) {
            if (c.isLocalOverride) {
                PatchOverride *ov = findOverride(c.destination);
                if (ov) {
                    ov->handler(c.source, c.destination, packet.payload, 255);
                }
                return;
            }
            if (c.outConn && c.outConn->lines) {
                c.outConn->lines->push(Packet(packet.payload, c.outChannel, Packet::BestEffort));
            }
            return;
        }

        // Outbound -> Inbound (Reverse direction)
        if (c.outConn == conn && c.outChannel == packet.channel) {
            if (c.inConn && c.inConn->lines) {
                c.inConn->lines->push(Packet(packet.payload, c.inChannel, Packet::BestEffort));
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Manual Circuit Opening & Transmission
// ---------------------------------------------------------------------------

bool Patches::open(const Path &destination, u64 localChannel, u8 ttl) {
    if (localChannel < 2) return false;

    PatchOverride *ov = findOverride(destination);
    if (ov) {
        PatchCircuit circ;
        circ.inConn = nullptr;
        circ.inChannel = localChannel;
        circ.outConn = nullptr;
        circ.outChannel = localChannel;
        circ.source = path.isEmpty() ? Path::Self : path;
        circ.destination = destination;
        circ.isLocalOverride = true;
        circuits.push(circ);
        return true;
    }

    PatchConnection *nextHop = findRoute(destination);
    if (!nextHop || !nextHop->lines) return false;

    PatchCircuit circ;
    circ.inConn = nullptr;
    circ.inChannel = localChannel;
    circ.outConn = nextHop;
    circ.outChannel = localChannel;
    circ.source = path.isEmpty() ? Path::Self : path;
    circ.destination = destination;
    circ.isLocalOverride = false;
    circuits.push(circ);

    String openPkt;
    encodeVarInt(2, openPkt); // Action 2: Open
    openPkt.push((char)ttl);
    encodeVarInt(localChannel, openPkt);
    String srcStr = circ.source.toString();
    String dstStr = destination.toString();
    encodeVarInt(srcStr.size(), openPkt); openPkt += srcStr;
    encodeVarInt(dstStr.size(), openPkt); openPkt += dstStr;

    nextHop->lines->push(Packet(openPkt, 1, Packet::BestEffort));
    return true;
}

bool Patches::write(const Path &source, const Path &destination, const String &bundle, u8 ttl) {
    // 1. Direct override check
    PatchOverride *ov = findOverride(destination);
    if (ov) {
        ov->handler(source, destination, bundle, ttl);
        return true;
    }

    // 2. Existing circuit check
    for (usz i = 0; i < circuits.size(); ++i) {
        if (circuits[i].destination == destination) {
            if (circuits[i].isLocalOverride) {
                if (ov) ov->handler(source, destination, bundle, ttl);
                return true;
            }
            if (circuits[i].outConn && circuits[i].outConn->lines) {
                circuits[i].outConn->lines->push(Packet(bundle, circuits[i].outChannel, Packet::BestEffort));
                return true;
            }
        }
    }

    // 3. Fallback: find route, open circuit on channel 2 and transmit
    PatchConnection *nextHop = findRoute(destination);
    if (!nextHop || !nextHop->lines) return false;

    u64 channel = allocateLocalChannel(nextHop);
    open(destination, channel, ttl);
    nextHop->lines->push(Packet(bundle, channel, Packet::BestEffort));
    return true;
}

// ---------------------------------------------------------------------------
// Periodic Processing Scheduler
// ---------------------------------------------------------------------------

void Patches::update() {
    // Update physical bands
    for (usz i = 0; i < physicalBands.size(); ++i) {
        if (physicalBands[i]) physicalBands[i]->update(false);
    }

    // Update Lines connections
    for (usz i = 0; i < connections.size(); ++i) {
        if (connections[i] && connections[i]->lines) {
            connections[i]->lines->update(false);
        }
    }
}

} // namespace Ksee
