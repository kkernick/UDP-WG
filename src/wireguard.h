#pragma once

#include "shared.h"
#include "udp.h"

using namespace shared;


/**
 * @brief This namespace includes the WireGuard implementation,
 * @remarks This implementation was created in reference to the WireGuard Whitepaper
 * (https://www.wireguard.com/papers/wireguard.pdf)
 * herein referred to as the "Reference"
 */
namespace wireguard {


  // The key pair is generated on runtime.
  auto pair = crypto::DH_GENERATE();


  // See Section 5.4 of the Reference, but these are just various
  // constants that are used as the base to construct the various
  // values we sent across the wire.
  const crypto::string

    // An empty value, its used frequently for AAD in encryption.
    // Why? it's just another way to detect if the data was modified.
    EPSILON = 32,

    // Used to initialize the C value, which eventually becomes our
    // Transport Keys. Why? You may notice that the string contains
    // each cryptographic function used in WireGuard:
    // Noise: The logic of the KeyExchange itself.
    // IKpsk2: The specific pattern of Noise: https://noiseexplorer.com/patterns/IKpsk2/
    // 22519: Curve25519 for Key Generation.
    // ChaChaPoly: ChaCha20-Poly1305 for Encryption/Decryption
    // BLAKE2s: For Hashing and HMAC.
    // So, this would allow for different version of WireGuard, say if a new cryptographic
    // scheme was released that was better than what we currently use, or a vulnerability
    // is discovered, without needing to provide a version flag in the packet. New versions
    // of WireGuard that use updated algorithms will communicate, but older versions that
    // use insecure/outdated values will fail immediately. Quite clver.
    CONSTRUCTION = ("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", 32),

    // This is used to initialize the H value, which is an accumulated
    // value by hashing pretty much every intermediary and final value
    // calculated in the Handshake. Why? As you can see from the string
    // This provides an EXPLICIT version, unlike CONSTRUCTION, which
    // again allows WireGuard to seamlessly "update" without allowing
    // outdates clients to work with newer ones.
    IDENTIFIER = ("WireGuard v1 zx2c4 Jason@zx2c4.com", 34),

    // Labels for generating the MAC1 and COOKIE. These are used as keys
    // for hashing and encrypting? Why? These values are hashed
    // prior to being used as keys with a public key, and we don't
    // want to transmit the public key in the clear unless we have to:
    // If a vulnerability is discovered in Curve25519, we don't want
    // to give attackers an ability to derive the private key. If
    // Curve25519 is broken in typical implementations where we DON'T
    // just send the public key across the wire, the attacker would
    // need to additionally break BLAKE2 to figure out the original
    // public key given only the hash, and the label used to construct it.
    // The Reference mentions this directly: "One modification [to the initiator's message]
    // would be to compute msg.static rather as Aead(κ, 0, Hash(S^pub_i), Hi).
    // The additional hash ensures that this elliptic curve point would not be transmitted directly,
    // and hence the entire handshake would have some limited degree of non-forward secret
    // post-quantum security, provided the public keys are not made known by some other means.)"
    LABEL_MAC1 = ("mac1----", 8),
    LABEL_COOKIE = ("cookie--", 8);


  // 6.1 of the Wiregurad Reference outlines these constants.
  // Either in messages or seconds, where applicable.
  // I find the MSGS constants comically large, especially
  // given the RJECT_TIME is only 3 minutes. For reference,
  // a peer would need to send 6405119 message every NANOSECOND
  // to reach the REKEY_MSGS in 3 minutes. I presume the idea
  // was not TIME or MSGS, but TIME and MSGS, such that a rekey
  // happens both when the time is up, and when the message
  // count is hit, but it is still such a massive amount of messages
  // compared to such a small timeout.
  const uint64_t
    // How many messages before we rekey.
    REKEY_MSGS = 1152921504606846976,

    // How many messages before we reject the connection
    RJECT_MSGS = 1.844674407370954e19,

    // How long since we last got a packet until we rekey.
    REKEY_TIME = 120,

    // How long since we last got a packet until we reject.
    RJECT_TIME = 180,

    // How long we wait before timing out on a rekey attempt
    REKEY_TOUT = 5,

    // How often we're allowed to ping. We don't actually use
    // this value, because the Network Thread manages heartbeats
    // itself, but it's here for completeness.
    KEEPALIVE = 10;


  /**
   * @brief A WireGuard Configuration.
   * @remarks For every WireGuard connection, both the server and client create a
   * config object that contains all the information needed to talk; the server
   * supplies this to the newly spawned WG Thread, whereas the client saves it within
   * wireguard_server value in the Main Thread. This includes everything from timestamps
   * to indicate a rekey, identities, send/recv, the source, and cookies.
   */
  typedef struct config {

    // The last timestamp they sent
    crypto::string timestamp = 12;

    // The peer's identity, and ours.
    crypto::string identity = 4;
    crypto::string self = 4;

    // Our shared transport keys.
    crypto::keypair keys;

    // Our send/recv nonces.
    uint64_t send = 0;
    uint64_t recv = 0;

    // So the network thread know's how to spoof connections.
    // Packets that reach the thread are directed to src.
    // Packets that are sent by source are spoofed to be
    // coming from us before being encrypted and sent.
    connection src = {};

    // The main network thread also receives a connection,
    // but doesn't actually use wireguard. Set it to false in that case.
    bool on = false;

    // The cookie. This is randomly generated garbage that is
    // encrypted by the server, sent across, and then decrypted
    // by the client and stored. On reconnection, the client
    // then computes it's mac2 using this decrypt noise,
    // which the server can verify, so long as the timestamp
    // hasn't exceed 120 seconds (And thus the random noise)
    // has changed.
    crypto::string cookie;
    uint64_t cookie_timestamp;
  } config;


  /**
   * @brief A controlled wrapper for the secret random value used for the WireGuard cookies.
   * @remarks See the CookiePacket for a more detailed explanation of what this is for.
   */
  class Rm {
    private:

    // The random value, and a timer.
    crypto::string R = crypto::DH_GENERATE().priv();
    uint64_t timer = TimeSeconds();

    public:
    Rm() = default;

    /**
     * @brief Get the current value.
     * @returns The current value.
     * @remarks If the value is older than 120 seconds,
     * generate a new value.
     * @remarks See 5.4.7
     */
    const crypto::string& Get() {
      auto current = TimeSeconds();
      if (current - timer > 120) {
        R = crypto::DH_GENERATE().priv();
        timer = current;
      }
      return R;
    }
  };
  Rm cookie_random;


  /**
   * @brief For both security and ease of use, we want to use crypto::string
   * as much as possible. This makes it easy to run all our cryptographic functions
   * on the handshake and transport, but it raises an issue in that these objects
   * are not contiguous values in memory (Or, they are, but casting it into a character
   * array isn't going to get you the bytes). If you tried to just cast the string
   * and send it across the wire, you'd get garbage. Instead, we need to Serialize
   * and Expand from a collection of crypto::strings making up a packet (Whether that
   * be the handshake packets or transport packets), so that we can work with
   * crypto::string, but be able to serialize it down when we need to send it,
   * and construct it back from bytes when receiving it. To unify this
   * functionality, the Packet object contains a list of crypto::string's in a vector
   * and will serialize the contents of it, and construct a itself from bytes.
   * Other objects derive from this class, and specify the size of the vector and
   * its elements, and values to access specific parts.
   */
  class Packet {
    protected:

    // Our list of strings that makes up the pack
    std::vector<crypto::string> values;

    public:
    Packet() = default;

    /**
      * @brief Serialize the packet.
      * @return A std::string representation that can be sent across the wire.
      */
    std::string Serialize() {
        std::stringstream out;
        for (const auto& x : values)
          out << std::string(reinterpret_cast<const char*>(x.bytes()), x.length());
        return out.str();
    }

    /**
      * @brief Construct a Packet from a std::string.
      * @param buffer: The byte array obtained by Serialize.
      * @param fill: Some Packets, like the TransportPacket, do not have a fixed
      * size for the final element. When fill is enabled, the final member of
      * the vector will be provided the remainder of the string's bytes.
      */
    void Expand(const std::string& buffer, const bool& fill=false) {

      // Extract from the buffer based on the pre-set size of each vector
      // string. Because this uses the current length, Expand needs to be
      // used on a new Packet, as making changes could change the internal sizes!
      size_t index = 0;
      for (auto& x : values) {
        // If we run out of bytes, throw an error.
        if (index > buffer.length())
        throw std::runtime_error("Buffer does not contain entire packet!");

        // Otherwise write the requested about of bytes into the crypto::string,
        // from the current position in the buffer
        memcpy(x.bytes(), &buffer[index], x.length());

        // Update the index.
        index += x.length();
      }

      // If we're filling, dump all the remaining bytes into the last element.
      if (fill && index < buffer.length()) {
      auto& last = values.back();
      size_t extra = buffer.length() - index, start = last.length();
      last.resize(start + extra);
      memcpy(last.bytes() + start, &buffer[index], extra);
      }
    }
  };


  /**
   * @brief The initial packet sent from initiator to responder.
   */
  class InitPacket : public Packet {
    public:

    // So we can index the vector a la packet[InitPacket::reserved];
    // We combine type + reserve because they're both static.
    static constexpr size_t reserved = 0, sender = 1, ephemeral = 2, stat = 3,
    timestamp = 4, mac1 = 5, mac2 = 6;

    // Initialize the InitPacket with the correct byte sizes.
    InitPacket() {Packet::values = {4, 4, 32, 48, 28, 16, 16}; values[0][0] = WG_HANDSHAKE;}

    // Initialize the InitPacket from a buffer.
    InitPacket(const std::string& buffer) : InitPacket() {Expand(buffer);}

    // Index operator
    crypto::string& operator[](const size_t& val) {return Packet::values[val];}
    const crypto::string& operator[](const size_t& val) const {return Packet::values[val];}
  };


  /**
   * @brief The packet sent by the responder to the initiator during the handshake.
   */
  class ResponsePacket : public Packet {
    public:

    // Names
    static constexpr size_t reserved = 0, sender = 1, receiver = 2, ephemeral = 3,
    empty = 4, mac1 = 5, mac2 = 6;

    // Default values and constructors
    ResponsePacket() {Packet::values = {4, 4, 4, 32, 48, 16, 16}; values[0][0] = WG_HANDSHAKE;}
    ResponsePacket(const std::string& buffer) : ResponsePacket() {Expand(buffer);}

    // Index operator.
    crypto::string& operator[](const size_t& val) {return Packet::values[val];}
    const crypto::string& operator[](const size_t& val) const {return Packet::values[val];}
  };


  /**
   * @remarks The WireGuard Reference at 5.4.7 explains the idea of Cookie, where if the
   * Server is overloaded and cannot accept new connections, it will return a cookie packet
   * as opposed to the second packet of the handshake. The idea is that the peer will wait the
   * timeout period, and when they request a handshake again, provide this cookie. Don't think
   * of this cookie like an internet cookie: It doesn't cache any part of the handshake such that
   * the peer can just sent the cookie as opposed to the first packet of the handshake. They still
   * need to do the work, including generating new ephemeral keys; to my understanding, the cookie
   * is little more than a priority queue. The Reference stipulates that (5.3): "When
   * the responder receives the message, if it is under load, it may choose whether or not to accept and process the
   * message based on whether or not there is a correct MAC that uses the cookie as the key. This mechanism ties
   * messages sent from an initiator to its IP address, giving proof of IP ownership, allowing for rate limiting using
   * classical IP rate limiting algorithms (token bucket, etc—see section 7.4 for implementation details)"
   * You may notice the language "choose to accept based on a correct MAC based on the cookie." (mac2). This, to
   * me, reads that peers connecting without cookies are deprioritized to those that do have cookies.
   * @remarks Now, onto how the Cookie actually works: The random value cookie_random is hashed with the clients IP and Port.
   * This creates a random value, cycled every 2 minutes, that the server sends to clients. By setting the value with the
   * client's IP, it necessarily ties the cookie to a particular client, so it can't be reused by other peers. However, if we
   * send the cookie across the wire it would be possible to brute force the random value given that we know the IP of the
   * peer; so, we add additional measures. Firstly, we encrypt the message with the server's public key (Nothing too
   * special here), and use a randomized nonce (So a cookie cannot be reused), but then provide AAD as the mac1 of the
   * the original packet. In doing so, only the person who sent the original handshake packet is able to decrypt the cookie.
   */
  class CookiePacket : public Packet {
    public:

    // Names
    static constexpr size_t reserved = 0, receiver = 1, nonce = 2, cookie = 3;
    // Default values and constructors. We bump the cookie size to accommodate AAD info.
    CookiePacket() {Packet::values = {4, 4, 24, 32}; values[0][0] = WG_COOKIE;}
    CookiePacket(const std::string& buffer) : CookiePacket() {Expand(buffer);}

    // Index operator.
    crypto::string& operator[](const size_t& val) {return Packet::values[val];}
    const crypto::string& operator[](const size_t& val) const {return Packet::values[val];}
  };


  /**
   * @brief A WireGuard packet for sending Transport Messages
   * @remarks See 5.4.6 of the WireGuard Reference
   */
  class TransportPacket : public Packet {
    public:

    // Names
    static constexpr size_t reserved = 0, receiver = 1, counter = 2, packet = 3;

    // Default values. Notice we default the packet value to 1, but tell Expand
    // to fill however many bytes were in the buffer.
    TransportPacket() {Packet::values = {4, 4, 8, 1}; values[0][0] = WG_TRANSPORT;}
    TransportPacket(const std::string& buffer) : TransportPacket() {Expand(buffer, true);}

    //Construct a packet with a valid WireGuard connection, and some data.
    static udp::packet Create(config& config, const udp::packet& in) {
      // Build the package
      TransportPacket packet;
      packet[TransportPacket::receiver] = config.identity;
      packet[TransportPacket::counter] = {reinterpret_cast<unsigned char*>(&config.send), sizeof(uint64_t)};
      packet[TransportPacket::packet] = crypto::ENCRYPT(config.keys.priv(), config.send, in.buffer(), EPSILON);

      // Increment our send nonce, then collapse the struct into a byte array.
      ++config.send;
      return {config.src, packet.Serialize()};
    }


    /**
     * @brief Receive an encrypted WireGuard communication
     * @param buffer: The raw bytes of the UDP data containing our WireGuard payload.
     * @param length: The size of the buffer
     * @returns The data.
     * @remarks See 5.4.6 of the Reference.
     */
    static udp::packet Return(config& config, const udp::packet& packet) {

      // Rebuild the packet.
      TransportPacket t_packet = packet.data();

      // Ensure the counter is correct, decrypt content, update nonce.
      auto counter = *reinterpret_cast<const uint64_t*>(&t_packet[TransportPacket::counter]);
      if (counter < config.recv) throw std::runtime_error("Incorrect counter!");
      auto data = crypto::DECRYPT(config.keys.second(), config.recv, t_packet[TransportPacket::packet], EPSILON);
      ++config.recv;
      return udp::packet(data.to());
    }

    // Index operator.
    crypto::string& operator[](const size_t& val) {return Packet::values[val];}
    const crypto::string& operator[](const size_t& val) const {return Packet::values[val];}
  };



  /**
   * @brief The first half of the Handshake process.
   * @param ephemeral: The ephemeral keypairs of the peer.
   * @param remote_pub: The peer's public key.
   * @param con: The configuration that we populate for subsequent communication.
   * @param msg: The InitPacket. The initiator builds this Packet, and then sends it
   * to the responder, who uses the pre-populated Packet for this function.
   * @param init: Whether this is the initiator.
   * @param C: The chaining key value.
   * @param H: The hash result value.
   * @throws std::runtime_error If the handshake fails.
   * @remarks This part of the Handshake builds the InitPacket, or the information the
   * initiator of the exchange sends over to the responder. Both run this function,
   * but their behavior is different. The initiator runs through this function and populates
   * an empty InitPacket msg, computing its Ephemeral Keys, and then returning the completed
   * InitPacket, and the values it got for C and H. All this time, the responder is just sitting
   * in wait for the initiator. Once the initiator finishes, they return from this function back
   * to Handshake, where it will then send the InitPacket across the wire. The responsder
   * then runs through this function (init = false), and not only performs checks to ensure that
   * the peer is the person they're expecting, but extracts the relevant information. The way
   * this function works such that both peers will return with the same C and H value. All this time,
   * the initiator has been sitting, and the responder then heads into Handshake2, which is where
   * the responder generates its own Ephemeral Keys, constructs the ResponsePacket, and finally sends
   * it back to the initiator. The initiator then brings this packet into Handshake2, generating the
   * required details and verifying, and the result is a set of Transport Keys, one for receiving,
   * one for sending, that has been generated through a combination of both the peers Static and
   * Ephemeral Keys.
   * @remarks This is based on the Noise Framework: https://noiseprotocol.org/noise.pdf
   * @remarks This may look a little daunting (I'm sure the wall of comments probably isn't helping), but
   * Jason, the creator of WireGuard has a really nice presentation that he has given at several conventions:
   * https://www.wireguard.com/talks/eindhoven2018-slides.pdf It helps explain more of the protocol.
   */
  void Handshake1(
    crypto::keypair& ephemeral,
    const crypto::string& remote_pub,
    config& con,
    InitPacket& msg,
    const bool& init,
    crypto::string& C,
    crypto::string& H
  ) {

    // Randomly generate an identity
    if (init) {
      std::uniform_int_distribution<std::mt19937::result_type> byte_dist(0,0xFF);
      for (size_t x = 0; x < 4; ++x) {
        msg[InitPacket::sender][x] = byte_dist(rng);
      }
    }

    // C is our chaining key value. Starting with CONSTRUCTION,
    // (Hence the name, we build off this with subsequent crytographic
    // operations. This value will be the same on both peers, and will
    // be used to derive the transport keys.
    C = crypto::HASH(CONSTRUCTION);

    // H is the hash result value. We use the
    // responder's public key to hash
    H = crypto::HASH(C + IDENTIFIER);

    // The initiator hashes the the responder's public key into H,
    // linking it with the responder.
    if (init) H = crypto::HASH(H + remote_pub);
    else H = crypto::HASH(H + pair.pub());

    // The initiator generates new Ephemeral keys, whereas
    // the responder simply takes the public that was added.
    // An important thing to understand is the difference between
    // a peer's Static and Ephemeral Keys. The Static Keys are
    // stored in the pair variable at the top of this namespace.
    // They don't change (Normal WireGuard applications would
    // generate this to be permanent between two peers).
    // However, for every handshake, each peer generates a set
    // of Ephemeral Keys, which they use alongside their static
    // keys to derive the eventual Transport Keys. These Ephemeral
    // Keys are regenerated on each handshake, and re-key.
    // The idea is to ensure perfect forward secrecy: The
    // leakage of either peer's private keys will prevent
    // past messages from being decrypted, since they were encrypted
    // with Ephemeral Keys that are changed every two minutes.
    if (init) {
      ephemeral = crypto::DH_GENERATE();
      msg[InitPacket::ephemeral] = ephemeral.pub();
    }

    // The responder simply extracts the public component of the initiator's
    // Ephemeral Key (Which was sent along in the InitPacket.
    else ephemeral.pub() = msg[InitPacket::ephemeral];

    // Tie both C and H to the initiator's public ephemeral key.
    C = KDF(1, C, ephemeral.pub())[0];
    H = crypto::HASH(H + ephemeral.pub());

    // This is really neat; because the initiator creates
    // this value by multiplying the private key of the ephemeral,
    // (Which the responder doesn't know), with the RESPONDER'S PUBLIC KEY
    // The responder can derive the same value by using their key,
    // the RESPONDER'S PRIVATE KEY, against the ephemeral's public
    // portion, sent in msg[ephemeral].
    // This is the ECC of how g**(b*a) = g**(a*b) of
    // traditional DH, and ensures that the only person who
    // can return a shared value, as this dh is used immediately
    // after, is the person who has the private part of the
    // remote public the initiator used, IE the remote.
    crypto::string dh;
    if (init) dh = crypto::DH(ephemeral.priv(), remote_pub);
    else dh = crypto::DH(pair.priv(), ephemeral.pub());

    // Use KDF to not only update our C, but create an encryption
    // key K that we can use to encrypt the noise of the InitPacket.
    auto temp = KDF(2, C, dh);
    C = temp[0]; auto K = temp[1];

    // Now, we can ensure that both sides have the same information.
    // If the above DH did not match, then K cannot be correctly derived,
    // which means the attempt to decrypt the static value of the
    // message would return garbage. The remote knows that its
    // speaking to the intended target if it can successfully
    // decrypt the initiator's public key.
    //
    // Cleverly, we attach H as AAD. H can only be correctly derived
    // from the remote's public key, which means that anyone that
    // is sniffing for packets will be unable to make this decryption
    // off of only the information contained in the packet.
    if (init) msg[InitPacket::stat] = crypto::ENCRYPT(K, 0, pair.pub(), H);

    // The responder need only decrypt and ensure that value is their public key.
    else if (!init && crypto::DECRYPT(K, 0, msg[InitPacket::stat], H) != remote_pub)
      throw std::runtime_error("Static could not be decrypted!");

    // Update the hash to include the static, tying this
    // exchange to the message.
    H = crypto::HASH(H + msg[InitPacket::stat]);

    // Now, we tie in the actual Static Keys. You may notice that there's no
    // if (init) block here, because multiplying the PRIVATE-INIT with PUBLIC-RESPONSE
    // is the same as multiplying the PRIVATE_RESPONSE with PUBLIC_INIT, and based
    // on how we provide that information, this returns the same value, despite
    // the input being different values. Again, this is like the magic of traditional
    // Diffie-Hellman.
    temp = KDF(2, C, crypto::DH(pair.priv(), remote_pub));

    // Again, we use KDF to not only update C with our static keys,
    // but derive an encrypt key to encrypt the next piece of information
    // in the packet: The timestamp.
    C = temp[0]; K = temp[1];

    // The initiator now adds the timestamp. As Per Section 5.1
    // of the Reference, the server keeps track of the greatest
    // value timestamp sent across an entire connection, and will
    // drop those that are before it. We encrypt the timestamp with
    // our K derived from the second key-exchange, hiding the current
    // timestamp from being transmitted in the clear.
    if (init) {msg[InitPacket::timestamp] = crypto::ENCRYPT(K, 0, Timestamp(), H);}

    // Decrypt the timestamp.
    else {
      // Add all the information we need to communicate with this peer in the future.
      auto timestamp = crypto::DECRYPT(K, 0, msg[InitPacket::timestamp], H);

      // Remember, this Handshake is run not only on initial connection, but every
      // 2 minutes (And also after 2**60 messages, which is the equvilent of sending
      // 30,000 packets every second for the next 1,000,000 years straight), so
      // if we're passing an existing configuration, ensure that there isn't any
      // replay attack by sending older packets.
      if (TimestampGreater(con.timestamp, timestamp))
        throw std::runtime_error("Invalid timestamp!");
      con.timestamp = timestamp; con.identity = msg[InitPacket::sender];
    }

    // Store the timestamp into our running hash value.
    H = crypto::HASH(H + msg[InitPacket::timestamp]);

    // Now, we hash everything up to the mac in our packet, ensuring that none of it is modified
    // in transit.
    auto ma = msg[InitPacket::reserved] + msg[InitPacket::sender] +
              msg[InitPacket::ephemeral] + msg[InitPacket::stat] + msg[InitPacket::timestamp];
    if (init) msg[InitPacket::mac1] = crypto::MAC(crypto::HASH(LABEL_MAC1 + remote_pub), ma);

    // The responder ensures that the mac is valid.
    else if (crypto::MAC(crypto::HASH(LABEL_MAC1 + pair.pub()), ma) != msg[InitPacket::mac1])
      throw std::runtime_error("Invalid MAC!");

    // So long as the cookie sent across is not older than the refreshing random number, we
    // compute and verify mac2. We don't actually check if the cookie timestamp is valid,
    // because then we'd need to store that on the server. Instead, an invalid cookie
    // will simply cause an exception to be raised when the server tries to decrypt it,
    // which we can catch and thus stop the exchange
    if (con.cookie_timestamp != 0) {

      // Add the first mac to be included in our mac2.
      ma = ma + msg[InitPacket::mac1];

      // Store our previously decrypted cookie
      if (init) msg[InitPacket::mac2] = crypto::MAC(con.cookie, ma);

      // According to the Reference, this is supposed to be the expected behavior:
      // If there was no mac2 provided, or the mac2 is invalid (IE the client doesn't
      // have a cookie, or their cookie is expired), and they are under load,
      // they can send a cookie in response as opposed to the second part of the handshake.
      // If the cookie IS valid, then the behavior is somewhat ambiguous. The Reference don't explicitly
      // say that the server is REQUIRED to continue the handshake when presented with a valid cookie,
      // but that seems to be the whole point: If Server under load, give the client a cookie so that
      // they are prioritized once the situation calms down. Here, we don't have any means to detect
      // whether the server is under load, and the server explicitly just asks if they want
      // to send a cookie instead of completing the handshake. Therefore, all the responder does here
      // is verify that the cookie is correct.
      else {
        auto cookie = crypto::MAC(cookie_random.Get(), connection_string(con.src));
        if (crypto::MAC(cookie, ma) != msg[InitPacket::mac2])
          throw std::runtime_error("Invalid Cookie MAC!");
      }
    }
  }


  /**
   * @brief Complete the Handshake.
   * @param init_ephemeral: The ephemeral keys the initiator created. If this is the responder,
   * we only know the public component.
   * @param remote_pub: The other peer's public key.
   * @param con: The WireGuard configuration we're building.
   * @param msg: The packet to send back. If we are the initiator, this is already populated. If
   * we're the responder, we build this before returning, and then sending it to the initiator.
   * @param init: Whether we are the initiator.
   * @param C: The chaining key value.
   * @param H: The hash result value.
   * @remarks This function complete the Handshake we started in Handshake1, and does largely
   * the same thing as the prior one; now, the Responder generates their Ephemeral Keys, and ties
   * them into the chaining key and hash result, ensuring that both peer's have their Static
   * and Ephemeral Keys tied into the eventual Transport Keys. One important difference is that
   * the Responder's Packet is smaller than the Initiators. Why? It's to avoid amplification attacks.
   * The Responder cannot be flooded with small InitPackets, and send a barrage of massive packets
   * to whatever unassuming target you've pointed the server at.
   */
  void Handshake2(
    const crypto::keypair& init_ephemeral,
    const crypto::string& remote_pub,
    config& con,
    ResponsePacket& msg,
    const bool& init,
    crypto::string& C,
    crypto::string& H
  ) {


    // The responder generates an identity, and ephemeral keys.
    crypto::keypair ephemeral;
    if (!init) {
      std::uniform_int_distribution<std::mt19937::result_type> byte_dist(0,0xFF);
      for (size_t x = 0; x < 4; ++x) msg[ResponsePacket::sender][x] = byte_dist(rng);
      msg[ResponsePacket::receiver] = msg[InitPacket::sender];

      // Generate the responder's ephemeral keys.
      ephemeral = crypto::DH_GENERATE();
      msg[ResponsePacket::ephemeral] = ephemeral.pub();
    }

    // The initiator ensures we have a valid packet, and grabs the ephemeral public from the packet
    else {
      if (msg[ResponsePacket::receiver] != msg[InitPacket::sender])
        throw std::runtime_error("Receiver/Sender mismatch!");

      // Extract the public.
      ephemeral.pub() = msg[ResponsePacket::ephemeral];
    }

    // Update our C for the responder's public ephemeral.
    C = crypto::KDF(1, C, ephemeral.pub())[0];
    H = crypto::HASH(H + ephemeral.pub());

    // The responder then multiplies their ephemeral keys to the public of the initiators.
    // Just like before, the initiator, with the private key, can reach the same value
    // by simply reversing the two. This effecttively ties the two sets of ephemeral
    // keys together, ensuring that only the two peers that have the private keys
    // for each set can advance past this point (Both Static and Ephemeral).
    // Then, we tie these second set of ephemeral keys to the initiator, by
    // multiplying the private key once more against the initiator's public key.
    // Again, they can recreate the same state by simply multiplying the public
    // part of the response's ephemeral (Which is sent across the wire), and
    // their private static key.
    //
    if (!init) {
      C = crypto::KDF(1, C, crypto::DH(ephemeral.priv(), init_ephemeral.pub()))[0];
      C = crypto::KDF(1, C, crypto::DH(ephemeral.priv(), remote_pub))[0];
    }
    else {
      C = crypto::KDF(1, C, crypto::DH(init_ephemeral.priv(), ephemeral.pub()))[0];
      C = crypto::KDF(1, C, crypto::DH(pair.priv(), ephemeral.pub()))[0];
    }

    // Now we use KDF to generate a K for encryption of the empty section of the packet.
    // The "empty" section is quite literal: The KDF is passed an empty 32 byte
    // string for input, and we're encrypting EPSILON, or just zeros.
    // This is likely just for sanity testing: If the initiator doesn't decrypt
    // zeros (Their empty isn't quite so empty) Then they know that the person
    // they're talking to isn't the person they want to, and they hangup the
    // handshake immediately.
    auto temp = crypto::KDF(3, C, crypto::string(32));
    C = temp[0]; auto L = temp[1]; auto K = temp[2];
    H = crypto::HASH(H + L);

    // Encrypt the H into our empty section of the packet. This ensures
    // that we have the same C value, as otherwise our K wouldn't match,
    // and the decryption would fail.
    if (!init) {msg[ResponsePacket::empty] = crypto::ENCRYPT(K, 0, EPSILON, H);}
    else if (crypto::DECRYPT(K, 0, msg[ResponsePacket::empty], H) != EPSILON)
        throw std::runtime_error("Derived key is invalid! Refusing to continue!");

    // Again, update H with the content of this new section.
    H = crypto::HASH(H + msg[ResponsePacket::empty]);

    // Just like before, the responder creates a mac containing all the data in the packet, ensuring that
    // it doesn't get modified in transit. The initiator then ensures that the value matches.
    // A note: We don't do anything with mac2 here, since it's only updated if we have a Cookie. This implies
    // that the CLIENT can send a Cookie to the SERVER, which I find very funny. I like the idea
    // of the overworked server sending a cookie to the client, and then once they finally get around to
    // connecting with the client, the client--some personal computer--decides that they're a little too
    // busy right now, and passively aggressively send a cookie back. I presume that this is designed for
    // servers talking to one another, where the client might reasonably have a load, but for the purposes
    // of this implementation, a client cookie would just be petty.
    auto ma = msg[ResponsePacket::reserved] + msg[ResponsePacket::sender] + msg[ResponsePacket::receiver] + msg[ResponsePacket::ephemeral] + msg[ResponsePacket::empty];
    if (!init) msg[ResponsePacket::mac1] = crypto::MAC(crypto::HASH(LABEL_MAC1 + remote_pub), ma);
    else if (crypto::MAC(crypto::HASH(LABEL_MAC1 + pair.pub()), ma) != msg[ResponsePacket::mac1])
      throw std::runtime_error("Invalid MAC! Refusing to continue!");


    // Now that we have a shared key C that has been built
    // using both Static and Ephemeral keys from both sides,
    // we derive two transport keys, one for sending, and one for receiving.
    // See 5.4.5 of the Reference
    auto transport_keys = crypto::KDF(2, C, EPSILON);

    // When the initiator sends a packet encrypted with their sending key,
    // The responder decrypts it with the same key, but it's their receiving
    // key. So, we just need to flip them around accordingly.
    if (init) {

      // Add all the information we need to communicate with this peer in the future.
      con = {
          .identity = msg[ResponsePacket::sender],
          .self = msg[InitPacket::sender],
          .keys = {transport_keys[0], transport_keys[1]}
      };
    }

    // The responder just needs to flip the order of the keys, and do
    // some updating of the connection (Notice that the initiator is not updating
    // a connection, but creating a new one, but the Responder, updating an existing
    // connection, needs to reset the send/recv (Because we're definitely going to hit
    // that 2**60 REKEY).
    else {
      // Add the information we hadn't yet derived.
      con.self = msg[ResponsePacket::sender];
      con.keys =  {transport_keys[1], transport_keys[0]};
      con.recv = 0;
      con.send = 0;
    }
  }


  /**
   * @brief Perform a WireGuard Handshake
   * @tparam The queue ;)
   * @param remote_pub: The remote's public key
   * @param peer: The connection to the peer.
   * @param init: Whether we are the initiator.
   * @param in: The in queue
   * @param out: The out queue.
   * @param conf: The wireguard configuration to built.
   * @param cookie: Whether we are sending a cookie.
   * @remarks This function completes the entire Handshake Process for a
   * WireGuard connection. The flow of logic is somewhat complicated:
   * Both initiator and responder enter this function, where the responder
   * immediately waits for the client to provide an InitPacket. The client
   * stepping into Handshake1, dutifully produces that Packet, adds
   * some information to the configuration, and gets the working values
   * of H and C. It then steps back to this function, where it sends the
   * packet across, and then waits. The responder then receives this packet,
   * and uses the populated InitPacket runs through Handshake1, reaching the
   * same state as the initiator. It then steps into Handshake2, completing
   * its part of the Handshake, producing Transport Keys that have been derived
   * from both Static and Ephemeral of both peers, and sends the ResponsePacket
   * across. The client then wakes up, and uses this ResponsePacket to run through
   * Handshake2, ending with the same Transport Keys, and a completed configuration.
   * @remarks An aside for the template: in C++, if you have a circular dependencies
   * and you don't want there to be one, you can hand wave it away with templates.
   * The queue is defined in network.h, and for a while this function lived in that
   * header, but it didn't make much sense: it'S a WireGuard handshake. So, what do we do?
   * We make the function a template, and then each instance of the Handshake called (Spoilers,
   * it's only called with Q = network::queue), is created by the compiler. So, we can stick
   * Handshake here, and don't even need to explicitly provide Q in the function calls because
   * C++ is smart enough to deduce it based on the function arguments.
   */
  template <typename Q> config Handshake(
    const crypto::string& remote_pub,
    const connection& peer,
    const bool& init,
    Q& in,
    Q& out,
    config conf = {},
    const bool& cookie=false
  ) {

    // Setup our Packets.
    InitPacket init_packet;
    ResponsePacket response_packet;


    // Setup the values we need to carry across Handshake1 and Handshake2
    crypto::string C, H;
    crypto::keypair ephemeral;

    if (init) {

      // The initiator generates their InitPacket, and sends it across.
      Handshake1(ephemeral, remote_pub, conf, init_packet, init, C, H);
      out.enqueue({peer, init_packet.Serialize()});

      // Then, they wait for one of two things:
      // A HANDSHAKE, which means the responder sent us back a reply,
      // and we can finalize the connection.
      // A COOKIE, which means the server deferred the connection
      // for later.
      auto response = in.pop({WG_HANDSHAKE, WG_COOKIE}, 50);

      // If HANDSHAKE, extract the data, complete the handshake!
      if (response.data()[0] == WG_HANDSHAKE) {
        response_packet = ResponsePacket(response.data());
        Handshake2(ephemeral, remote_pub, conf, response_packet, init, C, H);

        // Ensure we can send a packet.
        conf.src = peer;
        auto packet = TransportPacket::Create(conf, {peer, "Hello!"});
        out.enqueue(packet);
      }

      // If COOKIE, decrypt the content to get the raw value, and
      // store that for later.
      else {
        auto cookie_packet = CookiePacket(response.data());
        auto key = crypto::HASH(LABEL_COOKIE + remote_pub);
        auto cipher = cookie_packet[CookiePacket::cookie];
        auto nonce = cookie_packet[CookiePacket::nonce];
        auto aad = init_packet[InitPacket::mac1];

        conf.cookie = crypto::XDECRYPT(key, {cipher, nonce}, aad);
        conf.cookie_timestamp = TimeSeconds();
        return conf;
      }
    }


    // The responder waits until the initiator finishes Handshake1, and then
    // runs through both it, and Handshake2, before returning the result of the
    // second back to the initiator.
    else {

      // The first packet we give slightly more time so that the
      // client can read our public key and ensure it's what they expected.
      init_packet = InitPacket(in.pop(WG_HANDSHAKE, 300).data());

      // If we want to send a cookie, and there isn't already one.
      if (cookie && conf.cookie_timestamp == 0) {

        // Generate the Cookie. See 5.4.7 of the Reference.
        CookiePacket cookie_packet;

        // Set the receiver.
        cookie_packet[CookiePacket::receiver] = init_packet[InitPacket::sender];

        // Generate the cookie by using our public key, and using it
        // to encrypt our random value, and the peer's IP+Port, using
        // the mac1 of the original message as AAD
        auto key = crypto::HASH(LABEL_COOKIE + pair.pub());
        auto plain = crypto::MAC(cookie_random.Get(), connection_string(peer));
        auto aad = init_packet[InitPacket::mac1];
        auto pair = crypto::XENCRYPT(key, plain, aad);
        cookie_packet[CookiePacket::cookie] = pair.first();
        cookie_packet[CookiePacket::nonce] = pair.second();

        // Send it back, update our cookie.
        out.enqueue({peer, cookie_packet.Serialize()});
        conf.cookie = plain;
        conf.cookie_timestamp = 1;
        return conf;
      }

      // Otherwise, complete the handshake.
      else {

        // We need to set this here for the cookie.
        conf.src = peer;
        Handshake1(ephemeral, remote_pub, conf, init_packet, init, C, H);
        Handshake2(ephemeral, remote_pub, conf, response_packet, init, C, H);

        // Send the result back, ensure we can communicate
        out.enqueue({peer, response_packet.Serialize()});
        conf.src = peer;
        auto packet = in.pop(WG_TRANSPORT, 50);
        if (TransportPacket::Return(conf, packet).data() != "Hello!")
          throw std::runtime_error("Test packet failed!");

        // Clear the timestamp.
        conf.cookie_timestamp = 0;
      }
    }
    conf.on = true;
    return conf;
  }


  /**
   * @brief Test the WireGuard Cryptographic Functions.
   * @remarks If the system has outdated OpenSSL, or the pre-compiled version
   * doesn't cooperate well, we should detect that as soon as possible to
   * prevent confusing bugs down the line.
   * @remarks This is probably excessive; OpenSSL has really good backward
   * compatibility, and any version of glibc within the last decade will
   * easily be able to handle our pre-compiled program.
   */
  void test() {
    using namespace crypto;

    // Ensure we can successfully derive a keypair.
    string pub_key, priv_key;
    string testing_string = "Hello, World!", data = ("Additional Data!", 32), encrypt, priv;
    keypair xencrypt;

    try {
      auto pair = DH_GENERATE();
      pub_key = pair.pub();
      priv_key = pair.priv();
      if (pub_key.length() != 32 || priv_key.length() != 32) throw std::runtime_error("Incorrect size!");
      output("Success!", "Key Generation", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "Key Generation", ERROR);}

    // Key Exchange
    try {
      auto server = DH_GENERATE();
      auto client = DH_GENERATE();
      if (crypto::DH(server.priv(), client.pub()) != crypto::DH(client.priv(), server.pub())) throw std::runtime_error("Exchange failed!");
      output("Success!", "Key Exchange", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "Key Exchange", ERROR);}

    // Ensure our FieldInteger operations work correctly.
    // Ensure we can successfully encrypt.
    try {
      encrypt = ENCRYPT(priv, 0, testing_string, data);
      xencrypt = XENCRYPT(priv, testing_string, data);
      output("Success!", "Encryption", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "Encryption", ERROR);}

    // Ensure we can successfully decrypt.
    try {
      auto decrypted = DECRYPT(priv, 0, encrypt, data);
      auto xdecrypted = XDECRYPT(priv, xencrypt, data);
      if (decrypted != testing_string.to()) throw std::runtime_error("Incorrect decryption");
      if (xdecrypted != testing_string.to()) throw std::runtime_error("Incorrect decryption");
      output("Success!", "Decryption", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "Decryption", ERROR);}

    // Ensure that changing the ciphertext results in errors.
    try {
      encrypt[0] = ~encrypt[0];
      auto decrypt = DECRYPT(priv, 0, encrypt, data);

      xencrypt.first()[0] = ~xencrypt.first()[0];
      auto xdecrypt = XDECRYPT(priv, xencrypt, data);
      output("Failed!", "AED", ERROR);
    }
    catch (std::runtime_error& c) {output("Success: " + std::string(c.what()), "AED", SUCCESS);}

    // Ensure the the Blake Hash works correctly
    try {
      if (HASH(testing_string) != HASH(testing_string)) throw std::runtime_error("Incorrect hash");
      if (HASH(testing_string) == HASH(data)) throw std::runtime_error("Incorrect hash");
      if (HASH(testing_string).length() != 32) throw std::runtime_error("Incorrect size!");
      output("Success!", "Hash", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "Hash", ERROR);}

    // Ensure the the Blake HMAC works correctly
    crypto::string hmac;
    try {
      hmac = HMAC(testing_string, data);
      if (hmac != HMAC(testing_string, data)) throw std::runtime_error("Incorrect HMAC");
      if (hmac.length() != 32) throw std::runtime_error("Incorrect size!");
      output("Success!", "HMAC", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "HMAC", ERROR);}

    try {
      auto mod = testing_string, mod2 = data;
      mod[0] = ~mod[0]; mod2[0] = ~mod2[0];

      if (HMAC(mod, data) == hmac) throw std::runtime_error("Failed modifying key");
      if (HMAC(testing_string, mod2) == hmac) throw std::runtime_error("Failed modifying input");
      output("Success!", "HMAC Authenticity", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "HMAC Authenticity", ERROR);}

    // Ensure the the Blake HMAC works correctly
    string mac;
    try {
      mac = MAC(testing_string, data);
      if (mac != MAC(testing_string, data)) throw std::runtime_error("Incorrect MAC");
      if (mac.length() != 16) throw std::runtime_error("Incorrect size!");
      output("Success!", "MAC", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "MAC", ERROR);}

    try {
      auto mod = testing_string, mod2 = data;
      mod[0] = ~mod[0]; mod2[0] = ~mod2[0];

      if (MAC(mod, data) == mac) throw std::runtime_error("Failed modifying key");
      if (MAC(testing_string, mod2) == hmac) throw std::runtime_error("Failed modifying input");
      output("Success!", "MAC Authenticity", SUCCESS);
    }
    catch (std::runtime_error& c) {output("Failed: " + std::string(c.what()), "MAC Authenticity", ERROR);}

    prompt("If there were any failures, the program is unstable and may not work properly! Ensure that OpenSSL is on the latest version, and try recompiling/using the precompiled version if issues persist!");
    clear();
  }
}
