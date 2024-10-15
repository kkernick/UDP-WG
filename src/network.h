#pragma once

#include <poll.h>         // For the poll function for timeouts.
#include <map>            // For our address -> fd map

#include "wireguard.h"    // For WireGuard

using namespace shared;

/**
 * @brief The core networking namespace.
 * @remarks This namespace contains all the low level networking
 * code that UDP-WG are built on. It presents an easy to use,
 * seamless interface for the Main Thread, where it need only provide
 * a destination, and then enqueue packets to the out queue to be sent,
 * and read from the in queue for messages sent by others.
 * The queue is a relatively straight-forward
 * object, it's just a collection of packets to which access is mediated
 * but a mutex to allow for multiple threads to access it at once.
 * The Network Thread is a complicated function; it drives the network
 * stack.
 */
namespace network {

  /**
   * @brief A thread-safe queue.
   * @remarks This is a wrapper that mediates access of packets through a
   * mutex. This ensures that the main and network threads don't have race conditions
   * when adding/removing information from queues.
   */
  class queue {
    private:

    // It shouldn't be surprising that the Network Thread gets privileged
    // access here, but what sometimes happens is if a signal is received,
    // say the user hitting Ctrl+C, while the Main Thread is listening
    // for packets, then it is taken out of the queue function, leaving
    // it locked, which can then lockup the entire application as both
    // the Main and Network Threads try and flush the in/out.
    //
    // The solution? Let the Network Thread bypass the mutex, but ONLY
    // on shutdown. Since we're already shutting down, a double-write/read
    // isn't an issue with the alternative is a deadlock that hangs
    // the program on abort.
    friend void thread(port_t, wireguard::config);

    // The mutex to mediate access.
    std::mutex lock;

    // A queue of packets. Why isn't this an actual queue? It's so our
    // pop function doesn't need to mangle the structure to iterate through it. It
    // was originally a std::queue, but pop required adding invalid packets to a
    // separate queue, since there was no iteration support.
    std::vector<udp::packet> packets;

    // Through a lot of trial and error, I've found that sometimes the Network
    // Thread and Queue can deadlock when the Network Queue is at the out stage,
    // and trying to determine whether the Queue is empty, while a queue is being
    // polled for packets. The solution is to simply make empty/size non-blocking,
    // but to do this in a thread-safe manner, we make it an atomic value, and
    // update it ourselves.
    std::atomic<size_t> length = 0;

    public:

    // Initialize the objects.
    queue() = default;


    /**
     * @brief Enqueue a packet.
     * @param in: The packet to enqueue
     * @warning This function is blocking.
     */
    void enqueue(const udp::packet& in) {
      std::lock_guard<std::mutex> guard(lock);
      packets.emplace_back(in);
      length = packets.size();
    }


    /**
     * @brief Remove the first packet of the type byte
     * @param type: The type to search for: NONE for any packet.
     * @param iterations: How many times to check before failing.
     * Defaults to -1 IE SIZE_MAX IE forever.
     * @returns The first matching packet.
     */
    udp::packet pop(const tag type = NONE, const size_t& iterations = -1) {
      udp::packet ret;

      // We continuously monitor the queue until we find a packet of the correct type.
      for (size_t x = 0; x < iterations; ++x) {

        // Lock the queue
        lock.lock();

        // Search.
        for (auto iter = packets.begin(); iter != packets.end(); ++iter) {
          if (type == NONE || iter->data()[0] == type) {
            auto ret = *iter;
            packets.erase(iter);
            length = packets.size();
            lock.unlock();
            return ret;
          }
        }

        // Unlock and sleep.
        lock.unlock();
        if (x != iterations -1) shared::sleep();
      }
      throw std::runtime_error("Timeout!");
    }


    /**
     * @brief Pop with multiple valid types.
     * @param types: A list of types to search for.
     * @param iterations: The iteration count
     * @returns The first matching packet.
     */
    udp::packet pop(const std::vector<uint8_t>& types, const size_t& iterations = -1) {
      for (size_t x = 0; x < iterations; ++x) {
        for (const auto& type : types) {
          try {return pop(type, 1);}
          catch (std::runtime_error&) {}
          shared::sleep();
        }
      }
      throw std::runtime_error("Timeout!");
    }


    /**
     * @brief Check if the queue is empty
     * @returns Whether the queue is empty.
     */
    bool empty() {return length == 0;}


    /**
     * @brief Get the current size of the queue.
     * @returns The size.
     */
    size_t size() {return length;}

    /**
     * @brief Flush the queue.
     * @warning Any messages in the queue will be dropped!
     * @warning This function is blocking.
     */
    void flush() {
      std::lock_guard<std::mutex> guard(lock);
      packets.clear();
    }
  };


  // Define the global in/out queue for the Network Thread.
  queue in, out;


  /**
   * @brief The Network Thread.
   * @param port: The port to bind to: 0 = randomized.
   * @param wg: An optional WireGuard configuration.
   */
  void thread(port_t port, wireguard::config wg = {}) {

    /*
     * Let me try my best explain everything. Firstly, the network thread is
     * broken up into lambda functions which handle essential operations,
     * such as sending a packet across a FD, attaching to sockets,
     * and brokering new connections. There were two main design
     * philosophies:
     *    1. It should be impossible to communicate across
     *       the network without doing it through the Network Thread.
     *       The network thread holds a monopoly on FDs, which
     *       means the main thread cannot actually talk to the peers.
     *       it can only send packets to the network thread and let
     *       the thread handle it. This significantly reduces
     *       the complexity needed in sending packets for the Main Thread.
     *    2. The thread should be the only privileged component regarding
     *       UDP packets. The thread is the only part of the code that
     *       is friends with the packet, and as thus is the only one who
     *       can modify the source information to something other than
     *       the host (For WireGuard).
     * These decisions have made the networking of this application really
     * nice to use, just give a destination and data and let the Network
     * Thread handle it.
     *
     * Another thing that needs to be addressed is the two modes that a
     * network thread can be in (Yes, there can be more than one). At the
     * beginning of program execution, the main thread creates the
     * special network_thread variable, who is distinct because it does
     * not take a WireGuard configuration. This thread is the fundamental
     * thread and will teardown the application if it fails, and
     * communicates its status directly through stat. It also doesn't
     * deal with any of the WireGuard communication, as it exists to
     * send standard UDP, or broker a WireGuard connection.
     *
     * When a user wants to setup a WireGuard connection, the Main Network
     * Thread will pass the initial packets across, at least until the
     * server, or responder, spawns a new network thread that serves as
     * the client's endpoint. What does this mean in practical terms?
     *    1. A new WireGuard thread is spawned for each WireGuard connection
     *       on the machine where it is the server.
     *    2. The WireGuard Thread binds to a random socket which acts as the endpoint
     *       for the client. Any packets sent to this port will be encrypted
     *       and sent to the client. Any packets the client sends to the
     *       endpoint will be decrypted, and the plaintext UDP will be sent
     *       to the intended target with the source spoofed back to the server.
     *    3. The WireGuard thread is ephemeral. While the Network Thread can
     *       be communicated with the global in/out queues, the WireGuard thread
     *       has its own internal queue that does nothing more than route packets from and to the client.
     *    4. The WireGuard thread cannot affect the Main/Network threads. It is prohibited
     *       from modifying the stat, and any errors simply teardown the thread,
     *       leaving the rest of the program unchanged.
     *
     * To make it more clear, the documentation henceforth will refer to the Main Network
     * Thread run on startup as The Network Thread, whereas all threads for WireGuard will
     * be collectively called The WireGuard (WG) Threads.
     */

    /******************************************************************************
    *                                 ESSENTIALS                                  *
    *-----------------------------------------------------------------------------*
    * This section contains all the things that need to be done immediately upon  *
    * running the thread, such as setting the stat for the Network Thread         *
    * It also includes variable definitions for things that needs to be captured  *
    * by the lambdas, so must be therefore defined before them.                   *
    *******************************************************************************/

    // The Main Thread waits until the Network Thread is finished initializing before doing anything.
    if (!wg.on) shared::stat = INIT;

    // For verbose output.
    const std::string TNAME = wg.on ? "WIREGUARD" : "NETWORK";

    // The WG thread doesn't do anything more than sent packets
    // to their intended target, so it uses a local queue.
    // In this sceneraio the flow of packets is:
    // Client (ENC) -> WG Thread's IN -> DECRYPT -> WG Thread's OUT -> Recipient.
    // Peer -> WG Thread's IN -> ENCRYPT -> WG Thread's OUT -> Client (ENC).
    //
    // This is as opposed to the Network Thread, which is:
    // Main Thread -> Network Thread's OUT -> Peer
    // Peer -> Network Thread's IN -> Main Thread.
    queue local_in, local_out;
    queue& thread_in = wg.on ? local_in : in;
    queue& thread_out = wg.on ? local_out: out;

   // This keeps track of all active connections. The Main Thread
   // Only has access to a destination, so when they sent us a packet
   // We lookup to see if that connection has an existing FD to send to.
    std::map<con_t, fd_t> fds;

    // The socket that we listen for new connections on.
    int sock = -1;

    // Store the last second we tried re-keying.
    uint64_t last_second = 0;

    // The thread needs to communicate using it's real port.
    auto thread_self = self;

    // We send heartbeat packets on each iteration
    // to ensure the connection is still up.
    // This is just a packet with no destination.
    auto heartbeat = udp::packet({}, "");


    /******************************************************************************
     *                             LAMBDA FUNCTIONS                               *
     *----------------------------------------------------------------------------*
     * This section contains all the helper utilities that the we use within the  *
     * core loop. We use Lambdas here not only so we don't clutter the namespace  *
     * with functions, but also to prevent sensitive functions, like those        *
     * related to FD manipulation, from being accessed outside the the threads    *
     ******************************************************************************/


    /**
     * @brief Send a packet across a FD.
     * @param p: The packet to send.
     * @param fd: The FD to send across.
     * @throws runtime_error: If the packet failed to send.
     */
    auto send_fd = [&TNAME, &wg, &fds](const udp::packet& p, const fd_t& fd) {

      // Create a buffer string of the UDP packet.
      auto buffer = p.buffer();

      // We are interested in OUT.
      struct pollfd f;
      f.fd = fd;
      f.events = POLLOUT;
      switch (poll(&f, 1, 100)) {
        case -1: output("Send Error (poll)", TNAME, ERROR); break;
        case 0:
          close(fd);
          fds.erase(p.destination().num);
          break;
        default:
          if (send(fd, buffer.c_str(), buffer.length(), MSG_NOSIGNAL) < 1)
            throw std::runtime_error("Failed to send packet.");
      }
    };


    /**
     * @brief Open a socket at the specified port.
     * @param port: The port.
     * @returns The socket FD.
     * @warning This function can teardown the thread if the socket cannot be initialized.
     */
    auto open_socket = [&TNAME, &wg](const port_t& p) {

      // Create the socket.
      output("Setting up Listening Socket...", TNAME, INFO);
      auto sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock == -1) {
        output("Failed to initialize socket!", TNAME, ERROR);
        if (!wg.on) shared::stat = TERMINATE;
        return -1;
      }
      sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_port = htons(p),
        .sin_addr = {.s_addr = INADDR_ANY}
      };

      // Set a timeout, and allow reuse of the address (This way, a crash
      // does not require us to wait the WAIT_TIME before the address is
      // available to bind again.
      struct timeval timeout = {.tv_usec = 100};
      int yes = 1;
      setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

      // Bind.
      if (bind(sock, (struct sockaddr*)&server, sizeof(server)) == -1) {
        output("Failed to bind to socket!", TNAME, ERROR);
        if (!wg.on) shared::stat = TERMINATE;
        return -1;
      }

      // Return the FD.
      return sock;
    };


    /**
     * @brief Establish a new connection.
     * @param dest: The destination.
     * @returns The FD of the connection.
     * @remarks One function of the Network Thread is that it should transparently handle
     * new connections, maintain existing connections, and remove dead connections.
     * When a unknown destination is specified in a UDP packet, we call this lambda
     * to reach out and establish a FD to communicate over. Network Threads are cooperative
     * in the sense that they willingly exchange this information.
     */
    auto establish_connection = [&TNAME, &send_fd, &wg, &thread_self](const connection& dest) {
      output("New destination! Establishing connection...", TNAME, INFO);

      // Make the socket we'll communicate over.
      auto fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd == -1) {
        output("Failed to create socket to destination!", TNAME, WARN);
        return -1;
      }
      sockaddr_in connection = {
        .sin_family = AF_INET,
        .sin_port = htons(dest.pair.p),
        .sin_addr = {.s_addr = dest.pair.a},
      };

      // Try and connect to them.
      if (connect(fd, (struct sockaddr*)&connection, sizeof(connection)) == -1) {
        output("Failed to connect to destination!", TNAME, WARN);
        return -1;
      }

      // The FD should never block.
      int flags = fcntl(fd, F_GETFL, 0);
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);

      // Once we have a connection, send a packet to give them our IP information.
      // This way, both of us can associate IP+Port to FD.
      try {
        send_fd({thread_self, dest, "Hello!"}, fd);
        return fd;
      }
      catch (std::runtime_error& c) {return -1;}
    };


    /**
     * @brief Cleanup the thread.
     * @remarks This closes the listening socket and all active connections,
     * and flushes the queues.
     * @remarks Only the Network Threads sets stat to TERMINATE.
     */
    auto cleanup = [&sock, &fds, &thread_in, &thread_out, &wg, &TNAME]() {
      output("Shutting down...", TNAME, INFO);
      close(sock);
      for (auto f = fds.begin(); f != fds.end(); ++f) close(f->second);

      // The Network Thread has the authority to directly manipulate
      // the queues if we're on cleanup. This prevents a SIGNAL from
      // interrupting a thread that is waiting, causing a deadlock.
      // The WG thread is the sole owner of its threads, so this
      // doesn't cause any concern, but it allows the Network Thread
      // to free up the Main Thread if it's waiting when we abort.
      thread_in.packets.clear(); thread_out.packets.clear();
      thread_in.lock.unlock(); thread_out.lock.unlock();

      output("Goodbye!", TNAME, INFO);
      if (!wg.on) shared::stat = TERMINATE;
    };


    /**
     * @brief Wait for a connection of a specific type.
     * @param fd: The FD to listen on.
     * @param tag: The tag at the start of the packet data.
     * @returns The UDP packet.
     * @remarks This is for re-keying. See that section for a
     * more apt explanation.
     */
    auto wait_for = [&thread_in](const fd_t& fd, const tag& tag) {
      udp::packet response;
      while (true) {
        try {
          response = udp::packet(fd);
          if (response.data()[0] == tag) break;

          // Invalid packets are enqueued for later processing.
          else thread_in.enqueue(response);
        }
        catch (std::runtime_error&) {}
      }
      return response;
    };


    /******************************************************************************
     *                                  INIT                                      *
     *----------------------------------------------------------------------------*
     * The core initialization. We need to bind to our listening socket, and for  *
     * the WireGuard Threads, ensure we have an FD for the client by sending and  *
     * receiving a message.                                                       *
     ******************************************************************************/

    // Hello!
    output("Hello :)", TNAME, INFO);

    // First, create our listening socket. This is used between network
    // threads to establish a FD to communicate.
    // The WG Threads don't specify port, and we randomly assign one.
    if (port == 0) {
      std::uniform_int_distribution<std::mt19937::result_type> port_dist(2000,9000);
      do {
        port = port_dist(rng);
        sock = open_socket(port);
      } while (sock == -1);
    }
    else sock = open_socket(port);
    if (sock == -1) {
      output("Failed to open socket!", TNAME, ERROR);
      cleanup(); return;
    }
    thread_self.pair.p = port;
    int client_fd = -1;

    // We can now listen for new connection
    output("Listening!", TNAME, INFO);
    if (!wg.on) shared::stat = READY;


    /*
     * The WG Threads need to send a packet to the Client, not because
     * they need to know the endpoint, although it is kinda fun to ping
     * yourself by sending a packet to it, but more so because we need
     * the WG Thread to assign the client an FD. This lets it teardown
     * if the Client ever fails a heartbeat, and helps majorly with
     * re-keying.
     */
    if (wg.on) {

      // Establish the connection.
      output("Sending location to client", TNAME, INFO);
      client_fd = establish_connection(wg.src);

      // Send the packet across the FD.
      sys_packet info;
      info.source =  thread_self;
      auto packet = udp::packet(wg.src, info, sizeof(sys_packet));
      send_fd(packet, client_fd);

      // Put the client in the database.
      fds[wg.src.num] = client_fd;
    }

    /******************************************************************************
     *                                 MAIN LOOP                                  *
     *----------------------------------------------------------------------------*
     * This is the core loop of the threads, where they will do most of           *
     * their work. We only terminate if the global stat tells us to, which        *
     * can only be changed by the Main Thread (Such as if the user exits), or the *
     * Network Thread (Such as if it cannot bind to its listening socket). There  *
     * are 5 main steps that the thread performs on each iteration, going in      *
     * order:                                                                     *
     * 1. Sleep. There are no semaphores or other such threading objects for      *
     * waking the thread up when it needs to do something. We instead sleep       *
     * for 100 microseconds for each interaction. Why at the start? So the re-key *
     * stage works better.                                                        *
     * 2. Re-Key: This is exclusive to the WG Threads, but if a connection has    *
     * either reached the rekey limit for messages sent or duration of connection *
     * The WG Thread will initiate a key exchange to generate new Transport Keys, *
     * identifiers, and reset the send/recv counters. It will also reset the      *
     * timestamp. The Reference stipulates that when the rekey limit is reached   *
     * That the server should just politely inform them every TIMEOUT, and only   *
     * refuse to communicate once the REJECT limit has been reached (See 6.1 and  *
     * 6.2). We abide by these constraints, and while the initial handshake       *
     * requires explicit confirmation, re-keys are done transparently without     *
     * confirmation. If you haven't noticed, rekeying changes the mode on the the *
     * home screen, so you can tell when a rekeying takes place.                  *
     * 3. Listen: The thread checks its listening socket to see if any new        *
     * requests were made. These requests are made from other threads on remote   *
     * instances. While some aspects of the network, such as establishing a       *
     * WireGuard connection, require user consent, the threads lack the ability   *
     * to ask explicitly, and generates the FD behind the scenes. This is nice,   *
     * because if the user sends a packet to a destination that the thread        *
     * doesn't know, the endpoint will be resolved without hassle from either     *
     * side.                                                                      *
     * 4. Send: The thread cycles through every packet in the out queue. If the   *
     * destination on the UDP header is known, it grabs the associated FD and     *
     * sends the message across. If the destination is unknown, it sends a        *
     * request to the destination, which the destination will notice in step 3,   *
     * generate a FD, and then use that newly generated FD to send the packet.    *
     * 5. Receive: The thread cycles through all FDs that it currently knows, and *
     * polls them for new packets sent by peers. If any are found, they are       *
     * placed in the in queue for the Main Thread's consumption. If the thread    *
     * is a WG Thread, these packets will be inspected. If they are originating   *
     * from the client, the server will decrypt them, read the contained UDP      *
     * packet, and will spoof the source so that it points to the endpoint,       *
     * rather than the actual client. That way, the recipient will have no idea   *
     * who the original sender was, and will reply back to the endpoint.          *
     * Likewise, packets that hit the endpoint that aren't from the source and    *
     * encrypted and sent in a TransportPacmet back to the client so that they    *
     * can decrypt and read them. This works seamlessly so that two peers can     *
     * communicate without even realizing that the WireGuard endpoint was between *
     * them. This step also involves the heartbeat, where the thread will send    *
     * a ping to every known connection. If any of the them fail to respond, we   *
     * presume the connection to be lost, and close the FD and delete it from the *
     * database.                                                                  *
     ******************************************************************************/
    while(shared::stat != TERMINATE) {

      /*
       * Sleep, the easiest step ;)
       */
      sleep();

      /*
       * Re-Key.
       *
       * If you look at the Handshake function, you may be confused why
       * this function doesn't just use that code, and why it apparently is
       * more complicated. The problem is that Handshake() uses the in/out queue
       * and those queues are populated by THIS thread. If we sent a packet on
       * the out queue, it will only be sent across the wire at step 4 of this
       * loop, which means we cannot have any blocking behavior. This leaves us
       * with two options:
       *    1. Make all requests non-blocking, and orchestrate a dizzying
       *       amount of flags to know what step of the handshake we're on
       *       and pick up once we get the information.
       *    2. Be mean and stop all communication until the peer responds.
       * This behavior only applies to a WireGuard thread, which means
       * the only communication is from the client and to the client. Therefore
       * there's no qualms about simply stalling the client until they make
       * up their mind. The wait_for() lambda does exactly this, it simply
       * reads the FD of the client, pushing any irrelevant packets to the in
       * queue, and only resumes normal behavior once the correct packet is sent.
       * No packets are lost, but the thread isn't budging until the client plays
       * nice.
       */
      if (wg.on) {

        // We need to ensure we don't bombard the client with requests, so
        // we only ping every RKEY_TOUT period.
        auto current = Timestamp();
        auto time_since = TimestampDiff(current, wg.timestamp);

        // Save the connection, because the handshake clears it.
        auto connection = wg.src;
        bool fatal = time_since > wireguard::RJECT_TIME || wg.recv > wireguard::RJECT_MSGS;

        // If we've passed the RKEY threshold, we need to re-key.
        if (time_since > wireguard::REKEY_TIME || wg.recv > wireguard::REKEY_MSGS) {

          // Figure out how many seconds have passed.
          auto seconds = *reinterpret_cast<uint64_t*>(current.bytes());

          // Only attempt a wireguard::REKEY within an acceptable frequency.
          if (seconds % wireguard::REKEY_TOUT == 0 && seconds != last_second) {

            // Update so we only send one packet for any given second.
            last_second = seconds;

            // Put our public key into a sys_packet, and send it across.
            sys_packet info = {.source =  thread_self, .rekey = true};
            memcpy(&info.pub[0], wireguard::pair.pub().bytes(), 32);
            auto packet = udp::packet(connection, info, sizeof(info));
            auto fd = fds[wg.src.num];
            auto peer = wg.src;
            send_fd(packet, fd);

            try {

              // Wait until the client responds, and they better send their public key back.
              // This is blocking, so the client HAS to respond, even if they reject the
              // re key.
              auto pub = wait_for(fd, SYS).cast<sys_packet>();
              crypto::string remote_pub = {&pub.pub[0], 32};

              // If they agreed.
              if (pub.source.num == connection.num) {

                // This is just a slightly modified version of Handshake(), using wait_for and send_fd
                // to account for the lack of queues. No cookies, either.
                wireguard::InitPacket init_packet;
                wireguard::ResponsePacket response_packet;

                crypto::string C, H;
                crypto::keypair ephemeral;
                wireguard::Handshake1(ephemeral, remote_pub, wg, init_packet, true, C, H);
                send_fd({peer, init_packet.Serialize()}, fd);

                auto response = wait_for(fd, WG_HANDSHAKE);
                response_packet = wireguard::ResponsePacket(response.data());
                wireguard::Handshake2(ephemeral, remote_pub, wg, response_packet, true, C, H);
                wg.src = peer;
                packet = wireguard::TransportPacket::Create(wg, {peer, "Hello!"});
                send_fd(packet, fd);

                output("Completed Re-Exchange!", TNAME, INFO);
                pick_mode();
                wg.on = true;
                wg.timestamp = current;

                // Packets coming in can be encrypted with our new Transport Keys,
                // but any communication that the client sent prior will be encrypted
                // with now invalid Transport Keys, and thus are lost as random noise.
                // We could save these packets, store them decrypted, and then re-encrypt
                // them with new Transport Keys, but in truth I don't see how the client
                // would ever be able to slip in a packet: they can't refuse a re-key,
                // and it would require a purposely difficult client to actively refuse
                // rekeys while sending more packets. In this situation, I think the
                // server is perfectly reasonable in dropping those packets.
                local_out.flush();

                // On this continue, the timestamp has been updated, and the send/recv has been
                // cleared, so we're good for another period.
                continue;
              }
            }

            // If they didn't agree or errored, make it clear in the log.
            catch (std::runtime_error&) {}
            if (fatal) {
              output("Client refused wireguard::REKEY after exceeding rejection limit! WireGuard connection is terminating!", TNAME, ERROR);
            }
            else  {
              output("Client refused wireguard::REKEY after exceeding wireguard::REKEY threshold. Packets will not be processed until a re-key has been completed", TNAME, WARN);
            }
          }
        }

        // If we've only reached the rekey stage, we still process packets.
        // However, once we're over fatal, we loop back up to the top, which
        // means we do nothing but sleep, and check for a rekey. No
        // other communication is sent.
        if (fatal) continue;
      }


      /*
       * Listen.
       *
       * Listening requires successfully returning from listen(), and then
       * seeing if accept() returned a non -1 value. The returned value is the
       * FD we can use. A failure to listen would mean an inability to accept
       * new connections, and as such is considered a fatal error that
       * tears down the thread.
       */
      if (listen(sock, 255) != 0) {
        output("Failed to listen to socket!", TNAME, ERROR);
        cleanup(); return;
      }
      else {

        // Accept any connection.
        sockaddr_in peer;
        socklen_t size = sizeof(peer);
        fd_t connection = accept(sock, (struct sockaddr*)&peer, &size);
        if (connection != -1) {

          // If we have a peer, get the FD. We don't know what
          // the other process' IP/Port is, so we need them
          // to send us a packet that contains it.
          output("New connection!", TNAME, INFO);

          // Get the packet.
          try {

            // Get the packet from the FD. This is the remote network thread
            // sending us a packet so we can grab it's IP and store it.
            auto p = udp::packet(connection);

            // Store the source for this associated IP
            auto src = p.source();
            fds[src.num] = connection;
            output("Connected!", TNAME, INFO);
          }

          // If there's any failure, let them know.
          catch (std::runtime_error& c) {output(c.what(), TNAME, ERROR);}
        }
      }


      /*
       * Send
       *
       * We iterate through every packet in the out_thread (Which is not frozen in place)
       * but is mediated such that we can't read while the Main Thread writes, and resolves
       * the FD for whatever the Main Thread threw on the UDP headers. Then, we send it
       * to the intended target.
       */
      while (!thread_out.empty()) {

        // Get the packet, and where we're supposed to send it to.
        auto p = thread_out.pop();
        auto dest = p.destination();

        /*
         * This is a special case. Sometimes, say the client of a WireGuard connection wants
         * to terminate the connection, the Main Thread needs to be able to tell the Network Thread
         * to close a connection. This would allow for the closure to be picked up by the server,
         * who could then close the socket and WG thread gracefully. To do this, the Main Thread
         * needs only to send an empty UDP packet with a 0'd source. If we detect this, we close
         * whatever FD we have for the destination.
         */
        if (p.source().num == 0 && fds.count(dest.num)) {
          output("Closing destination: " + connection_string(dest), TNAME, INFO);
          close(fds[dest.num]);
          fds.erase(dest.num);
          continue;
        }

        // If the destination isn't known establish the connection.
        if (!fds.count(dest.num)) {
          fds[dest.num] = establish_connection(dest);
        }

        // Send the packet.
        auto fd = fds.at(dest.num);
        try {
          send_fd(p, fd);
          output("Sent Packet to " + connection_string(dest), TNAME, INFO);
        }
        catch (std::runtime_error& c) {output(c.what(), TNAME, WARN);}
      }


      /*
       * Receive
       *
       * This section is where most of the magic happens for the thread. Firstly,
       * we iterate through every known connection, but before blindly placing them
       * into the pollfd array to poll them, we sent an empty heartbeat packet. This
       * packet actually causes an exception on the other side, so nobody except
       * for the threads will ever see it, but if the current thread is unable
       * to send it, that means the connection is severed, and the thread
       * gracefully closes the connection on its side.
       *
       * Once the heartbeat cleanup has ran through, and we have a list of active
       * connections, we poll them for any new packets. For the Network Thread,
       * these new packets are placed on the in queue for the Main Thread to deal
       * with, but if this is a WG Thread, we have special behavior. If the
       * packet was sent by the client, that means its an encrypted UDP packet
       * within a plaintext UDP packet. We decrypt that internal packet with
       * our shared transport key, and retrieve the packet the client wants to
       * send. We then do something sneaky by forging the source to point back
       * at ourselves, and then send it off. When the recipient receives the
       * packet, it will be sourced from the End Point, and thus they will
       * only be able to reply by sending a packet at us, without knowing
       * the IP and Port of the original client. When a message that isn't
       * by our client hits the endpoint, we firstly modify the destination
       * so that it correctly points to the client, and then encrypt it
       * with our Transport Key before shipping it back. That way, the client
       * will receive a packet that is addressed to them, from the actual
       * recipient, and one that has been encrypted in transit (At least
       * across the VPN). If we wanted peer-to-peer encryption, the
       * second peer would just need to establish their own WireGuard
       * connection with the same server.
       */
      if (fds.size() != 0) {

        // Generate a list of fds.
        struct pollfd fs[fds.size()] = {};
        size_t x = 0;

        // Send a heartbeat to each connection, remove those that fail.
        for (auto f = fds.begin(); f != fds.end();) {
          try {
            send_fd(heartbeat, f->second);

            // If it passed, add it to the list.
            fs[x].fd = f->second;
            fs[x].events = POLLIN;
            ++f; ++x;
          }

          // If the packet couldn't be sent.
          catch (std::runtime_error& c) {
            output("Heartbeat failure. Removing connection", TNAME, INFO);
            close(f->second);

            // Remember how we pinged the client at the beginning of the WG Thread setup,
            // and how I said that was important. This is why. We need to figure out when
            // the client has disappeared, because once they do, the whole thread needs to
            // shut down.
            if (f->first == wg.src.num) {
              output("Client disconnected. Thank you for using WireGuard!", TNAME, INFO);
              cleanup();
              return;
            }
            fds.erase(f++);
          }
        }

        // Poll our connections with POLLIN.
        auto ready = poll(&fs[0], x, 100);

        // A failure to poll prevents us from receiving packets. Fatal error.
        if (ready == -1) {
          output("Failed to poll connections!", TNAME, ERROR);
          cleanup(); return;
        }

        // A positive means that one of our connections sent something.
        else if (ready > 0) {
          for (size_t y = 0; y < x; ++y) {
            // If they sent something, get the packet!
            if (fs[y].revents & POLLIN) {
              try {
                auto packet = udp::packet(fs[y].fd);

                // If wireguard is on.
                if (wg.on) {

                  // If it's from the source, decrypt, spoof source, send it to our out queue to be
                  // sent next iteration.
                  if (packet.source().num == wg.src.num) {
                    output("Received packet from client. Decrypting and routing", TNAME, INFO);
                    auto decrypted = wireguard::TransportPacket::Return(wg, packet);
                    decrypted.set_source(thread_self);
                    thread_out.enqueue(decrypted);
                  }

                  // If it's from someone else, send it across encrypted.
                  else {
                    output("Received packet from another peer. Sending to client", TNAME, INFO);
                    auto encrypted = wireguard::TransportPacket::Create(wg, packet);
                    thread_out.enqueue(encrypted);
                  }
                }

                // The Network Thread just sends the packets to the in queue.
                else {
                  thread_in.enqueue(packet);
                  output("Received Packet from " + connection_string(packet.source()), TNAME, INFO);
                }
              }

              // These happen when the heartbeat is sent, since it's a malformed packet.
              // We can just ignore it.
              catch (std::runtime_error& c) {}

              // This happens if we read to a socket that has closed. Close it.
              catch (std::length_error&) {
                output("Failed to read from connection!", TNAME, WARN);
                close(fs[y].fd);
                fds.erase(fs[y].fd);
              }
            }
          }
        }
      }
    }

    // Cleanup and return.
    cleanup();
    return;
  }
}
