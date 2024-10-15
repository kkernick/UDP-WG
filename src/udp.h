#pragma once

#include <format>        // For formatting strings.
#include "shared.h"      // For the network code.


using namespace shared;

// Forward declaration of variables so the packet can befriend the thread.
// Forward declarations like this are identical to how you might recognize them
// in C. If you have functions A calling function B, but function B is
// actually defined after function A's definition, the compiler isn't smart
// enough to read the entire file and notice the subsequent definition. To solve it,
// we typically just have a Forward Declaration, such as:
//
// void B();
//
// void A() {B();}
// void B() {}
//
// Here, because UDP is relied upon by WireGuard, which itself is relied
// upon by Network, we cannot just include those headers, so we instead
// forward declare the namespaces, and needed objects to that
// the packet knows that the network thread exists.
//
namespace wireguard {struct config;}
namespace network {void thread(port_t, wireguard::config wg);}

/**
 * @brief This namespace includes the UDP implementation,
 * @remarks This implementation was created in reference to RFC 768
 * (https://datatracker.ietf.org/doc/html/rfc768)
 * herein referred to as the "Reference"
 */
namespace udp {

  /**
   * @brief A UDP Packet.
   * @remarks The entire UDP Packet contains 2 parts: a Header, and the Data.
   * Looking at the structure, you may be slightly confused by this "pseudo-header". TCP/UDP
   * operates at the Transport Layer, which deals with Ports; the Network Layer deals with IP.
   * UDP/TCP should not need to deal with addresses, yet this pseudo-header contains them.
   * Why is this? The creator of UDP, David Reed, explains why the pseudo-header exists:
   * https://www.postel.org/pipermail/end2end-interest/2005-February/004616.html and it boils down
   * to historical reasons. TCP used to be one big protocol that encompassed both IP and TCP. When
   * TCP was split, we still wanted to include address within the checksum, and rather than include
   * that information both within an IP header, and a TCP/UDP header, we have this pseudo-header
   * that is "shared" by both layers. Interestingly, Reed further explains that the original
   * intention was to have everything but the pseudo-header encrypted, and by encrypting the
   * checksum that included this address information, man-in-the-middle attacks would be thwarted.
   * This plan was blocked by both the NSA, and by "the terrorists who invented NAT".
   * The pseudo-header isn't typically sent across the wire. The Reference states that:
   * "[it's] conceptually prefixed to the UDP header", and Wikipedia stresses that: "
   * "[it's] not the real IPv4 header used to send an IP packet, it is used only for the checksum
   * calculation." (https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header).
   * Since our implementation only deals with UDP, rather than implementing the IP protocol as
   * well, we send the Pseudo-Header across the wire for destination resolving.
   */
  class packet {
    private:

    // The thread gets privileged access to the packet: IE they can change the source.
    friend void network::thread(port_t, wireguard::config wg);

    // The UDP Pseudo-Header, as per the Reference.
    typedef struct pseudo_header {

      // The address that this packet is coming from. We use this for replies
      uint32_t src_addr = 0;

      // The destination of of the packet. We use this for the Network Thread
      // to resolve and connection to the destination.
      uint32_t dst_addr = 0;

      // The Reference stipulates a "zero" octet and protocol octet.
      // We can very easily just use a uint16_t, as 17 = 0000 0000 0001 0001b.
      // That, however, begs the question of what the zero octet is for. My best
      // guess is that they didn't think they'd need more than 256 different protocol
      // numbers, and so wanted to only use 8 bits. However, computers like working
      // aligned to words, particularly for memory.
      // (See: https://en.wikipedia.org/wiki/Data_structure_alignment#2)
      // By adding a zero byte, we can not only check it for potential corruption,
      // since it should always be zero, but also pad the pseudo-header into a neat,
      // orderly 96 bytes, which can be divided cleanly by 2, 3, and 4.
      uint16_t protocol = 17;

      // The length of the entire packet.
      uint16_t length = 0;
    } pseudo_header;


    // The UDP Header, as per the Reference.
    typedef struct header {

      // The port the sender used to transmit the packet. The Reference tells us
      // that this value isn't strictly necessary, and can be 0'd, but we use it
      // since it allows us to easily lookup the FD.
      uint16_t src_port = 0;

      // The port of the destination to which we send the packet.
      uint16_t dst_port = 0;

      // The length of the entire packet, in "octets". You may not recognize this term,
      // but might deduce the "oct-" prefix to mean 8, and you'd be right. This is eight
      // bits, otherwise known as a byte. Why do they use esoteric language? According
      // to https://en.wikipedia.org/wiki/Octet_(computing), a "Byte" used to be platform
      // dependent, and the octet was a network-specific, fixed-sized definition.
      // You may also recognize this as being within the pseudo-header. It's duplicated.
      uint16_t length = 0;

      // The Checksum is the 16-bit one's complement of the one's complement sum
      // of the content of the pseudo-header, which contains the source and
      // destination address, a zero, the protocol, and UDP length, and the data.
      uint16_t check = 0;
    } header;

    // Hold each part.
    pseudo_header p = {};
    header h = {};
    std::string content = {};

    // These are compile-time constants; the length of the entire header,
    // and how much space is available for data. Since the length value in the
    // header is 16 bits per the Reference, we can only have data so large
    static constexpr uint16_t h_length = sizeof(pseudo_header) + sizeof(header);
    static constexpr uint16_t available = UINT16_MAX - h_length;


    /**
     * @brief Compute a UDP checksum.
     * @param data: Any piece of data to compute the checksum for.
     * @param size: The size of the data.
     * @remarks The checksum is performed by adding the one's compliment
     * of every 16-bit of the data.
     * @remarks This function is an auxilitary, used to construct the
     * UDP checksum from the constituent parts. For that reason, it
     * does not change an all 0 to an all 1, as per the Reference.
     * @remarks Why iterate by 16 bits? Because that's the size of
     * the checksum value in the header.
     */
    template<typename T> static uint16_t checksum(const T* data, const size_t& size) {

      // Create our running checksum, and buffer
      uint16_t check = 0, buffer = 0;
      auto array = reinterpret_cast<const uint8_t*>(data);

      // Iterate through every byte of the data.
      for (size_t x = 0; x < size; ++x, buffer <<= 8) {

        // If we have iterated through 16 bits (IE 2 bytes), add that to our checksum.
        if (x % 2 == 0) {
          check += buffer;

          // The Reference stipulates that if the data is not sized in multiples
          // of two octets, to add zeros to the end. By using a buffer reset
          // to 0, we accomplish this.
          buffer = 0;
        }

        // Add the one's compliment of the current byte to the buffer,
        // (We then shift it to make room for the next byte on each loop)
        buffer |= ~array[x];
      }

      // Return the check once we've exhausted the data.
      return check;
    }


    /**
     * @brief Construct a UDP packet by recveiving data from a FD.
     * @param fd: The FD to pull from to construct the packet
     * @throws std::runtime_error if reading the FD fails.
     */
    packet(const fd_t& fd) {
      // Without receiving at least the header, we have no
      // idea how large the packet is. So we just consume the
      // packet section-by-section, constructing the final packet to return.
      if (recv(fd, reinterpret_cast<void*>(&p), sizeof(p), 0) < 1)
        throw std::runtime_error("Failed to receive packet");
      if (recv(fd, reinterpret_cast<void*>(&h), sizeof(h), 0) < 1)
        throw std::runtime_error("Failed to receive packet");

      // Figure out how big the data is by removing the headers.
      size_t length = h.length - sizeof(p) - sizeof(h);
      if (length > available) throw std::length_error("Invalid packet!");

      char buffer[length] = {};
      if (recv(fd, reinterpret_cast<void*>(&buffer[0]), length, 0) < 1)
        throw std::runtime_error("Failed to receive packet");
      content = std::string(buffer, length);

      // Validate the checksum.
      auto check = checksum(&p, sizeof(p));
      check += checksum(content.c_str(), content.length());
      if (check != h.check) throw std::runtime_error("Checksum error!");
    }

    /**
     * @brief Privileged constructor providing src.
     * @param src: The source
     * @param dst: The destination.
     * @param data: The data within the packet.
     */
    packet(const connection& src, const connection& dst, const std::string& data) {construct(src, dst, data);}


    /**
     * @brief Construct a UDP packet from the three major parts.
     * @param src: The source.
     * @param dst: The destination.
     * @param data: The data.
     */
    void construct(const connection& src, const connection& dst, const std::string& data) {
      // Figure out how many bytes we can take from the data, and the packet size.
      uint16_t used = data.length() > available ? available : data.length();
      uint16_t length = used + h_length;

      // Create our headers and content
      p = {.src_addr = src.pair.a, .dst_addr = dst.pair.a, .length = length};
      h = {.src_port = src.pair.p, .dst_port = dst.pair.p, .length = length};

      content = data.substr(0, used);

      // Compute the checksum of the pseudo-header, and the data string.
      h.check = checksum(&p, sizeof(p));
      h.check += checksum(content.c_str(), content.length());

      // The Reference dictates that if the checksum is 0, it should be set to all 1.
      // All 0 indicates that checksumming wasn't used.
      if (h.check == 0) h.check = UINT16_MAX;
    }

    void set_source(const connection& src) {p.src_addr = src.pair.a; h.src_port = src.pair.p;}
    void set_dest(const connection& dst) {p.dst_addr = dst.pair.a; h.dst_port = dst.pair.p;}

    public:

    packet() = default;

    /**
    * @brief Create a packet from a string.
    * @param dst: The connection receiving the packet.
    * @param data: The data string to send.
    * @warning This function will only take UINT16_MAX bytes from the data
    * string.
    */
    packet(const connection& dst, const std::string& data) {construct(self, dst, data);}

    /**
     * @brief Construct a packet from a string buffer.
     * @param The buffer, should be the value from udp::packet.buffer().
     */
    packet(const std::string& in) {
      size_t index = 0;

      // Get the header
      memcpy(&p, in.c_str(), sizeof(p));
      index += sizeof(p);
      memcpy(&h, in.c_str() + index, sizeof(h));
      index += sizeof(h);

      // Figure out how big the data is by removing the headers.
      size_t length = h.length - sizeof(p) - sizeof(h);
      char buffer[length] = {};

      memcpy(&buffer[0], in.c_str() + index, length);
      content = std::string(buffer, length);
    }


    /**
     * @brief Construct a packet from any variable data, and its size.
     * @param dst: The destination.
     * @param data: The data to store.
     * @param size: The size of that data.
     */
    template <typename T> packet(const connection& dst, const T& data, const size_t& size) {
      *this = packet(dst, {reinterpret_cast<const char*>(&data), size});
    }


    /**
    * @brief Print the packet.
    * @returns The string.
    * @remarks Turn on --packet-print to see the packets like this.
    */
    std::string str() const {
      std::stringstream out;

      // Print the pseudo-header.
      out <<
      "0======1======2======3======4\n" <<
      "|       PSEUDO-HEADER       |\n" <<
      "=============================\n" <<
      std::format("| {:^25} |\n", p.src_addr) <<
      std::format("| {:^25} |\n", p.dst_addr) <<
      std::format("| {:^4} | {:^4} | {:^11} |\n", p.protocol >> 8, p.protocol & 0xFF, p.length) <<

      // Print the header.
      "=============================\n" <<
      "|           HEADER          |\n" <<
      "=============================\n";

      out <<
      std::format("| {:^11} | {:^11} |\n", h.src_port, h.dst_port) <<
      std::format("| {:^11} | {:^11} |\n", h.length, h.check) <<

      // Print the content, with nice formatting.
      "=============================\n" <<
      "|            DATA           |\n" <<
      "=============================\n";

      size_t x = 0;
      out << "| " << content[x++];

      // Break at every 25th character. This isn't UDP specific, it's just so the size
      // of our string box. If the content isn't ASCII, this can mess up the
      // rendering, but the only types of packets that contain this information
      // is WireGuard, and those packets get decrypted before the user can
      // see them.
      for (; x < content.length(); ++x) {
        if (x % 25 == 0) {
          out << " |\n| ";
        }
        out << content[x];
      }

      // Pad and terminate.
      while (x % 25 != 0) {out << " "; x++;}
      out << " |\n";
      out << "=============================\n";


      return out.str();
    }


    /**
     * @brief Cast the content of the packet as a type.
     * @tparam T: The type to cast
     * @returns The casted value.
     */
    template <typename T> const T cast() const {return *reinterpret_cast<const T*>(content.c_str());}


    /**
     * @brief Return the data.
     * @returns The data.
     */
    std::string data() const {return content;}


    /**
    * @brief Create a buffer of the packet that can be sent across the network
    * @returns The buffer.
    */
    std::string buffer() const {
      std::string buffer = {};
      buffer.append(reinterpret_cast<const char*>(&p), sizeof(pseudo_header));
      buffer.append(reinterpret_cast<const char*>(&h), sizeof(header));
      buffer.append(content);
      return buffer;
    }


    /**
    * @brief Get the address and port of the destination.
    * @returns The connection.
    */
    connection destination() const {return {.pair = {.a = p.dst_addr, .p = h.dst_port}};}


    /**
    * @brief Get the address and port of the source.
    * @returns The connection.
    */
    connection source() const {return {.pair = {.a = p.src_addr, .p = h.src_port}};}


    /**
     * @brief An empty packet.
     * @param dst: The destination.
     * @returns The empty packet.
     * @remarks The Main Thread signals to the Network Thread that a destination
     * should be closed by sending an empty packet. This packet doesn't actually
     * get sent across the wire, just enqueued into the out thread. This is used
     * when a WireGuard client stops the connection, and wants to close the FD
     * associated with it. That way, the server can close the listening socket.
     */
    static packet empty(const connection& dst) {
      packet ret;
      // Create our headers and content
      ret.p = {.src_addr = 0, .dst_addr = dst.pair.a};
      ret.h = {.src_port = 0, .dst_port = dst.pair.p};
      return ret;
    }
  };
}
