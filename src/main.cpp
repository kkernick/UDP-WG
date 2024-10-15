#include <csignal>      // For our signal handler.
#include <termios.h>    // For more direct terminal manipulation
#include <fcntl.h>      // For FD manipulation.

#include "network.h"    // For networking

// Gross, but with how prolific values like
// port_t, fd_t, stat are, this makes the code
// significantly easier to read.
using namespace shared;

// Our network thread.
std::thread network_thread;

// Network Threads spawned for handling wg_communication.
std::vector<std::thread> wg_threads;

// Options for the main menu.
using option = int;
option NA = 0, NEW = 1, VIEW = 2, WG = 3, QUIT = 4;

// Whether to print packets as just source + data, or pretty print it.
bool packet_print = false;


/**
 * @brief Parse our arguments.
 * @param arguments: A vector of arguments.
 */
void argument_parser(const std::vector<std::string>& arguments) {

  // Iterate each argument
  for (const auto& arg : arguments) {

    // The user can specify port, it defaults to 5000
    if (arg.starts_with("--port=")) {
       self.pair.p = std::atoi(arg.substr(7).c_str());
    }

    // The user can specify address, it defaults to localhost.
    else if (arg.starts_with("--addr=")) {
       self.pair.a = inet_addr(arg.substr(7).c_str());
    }

    // Verbose logging.
    else if (arg.starts_with("--verbose")) {verbose = true;}

    // Print the entire packet
    else if (arg.starts_with("--packet")) {packet_print = true;}

    // Log information to the file.
    else if (arg.starts_with("--log")) {
      logfile = arg.substr(6);
      auto outfile = std::ofstream(logfile);
      outfile << "LOG" << std::endl;
      outfile.close();
      shared::log = true;
    }

    // Write the help and exit
    else if (arg.starts_with("--help")) {
      std::stringstream help;
      help <<
        "main (--port=5000) (--addr=127.0.0.1) (--help) (--verbose) (--packet) (--log=main.log)\n" <<
        "  --port=5000: The port to listen on for new connections\n" <<
        "  --addr=127.0.0.1: The address to listen on\n" <<
        "  --verbose: Print verbose information, including from the network thread\n" <<
        "  --packet: Print the entire packet for new messages, not just the data.\n" <<
        "  --log: Log information to main.log\n" <<
        "  --help: Display this message";
      std::cout << help.str() << std::endl;
      exit(0);
    }

    else {
      std::cerr << "Unrecognized argument: " << arg << std::endl;
    }
  }
}


/**
 * @brief Cleanup before exiting.
 * @param signal_num: For the signal handler.
 * @remarks The network thread needs to cleanly spin down.
 */
void cleanup(int signal_num) {
  output("Received Signal: " + std::to_string(signal_num), "SIG", INFO);

  if (shared::stat != DEAD) {
    // Let the thread know we're done, if it wasn't the one that initiated the termination.
    shared::stat = TERMINATE;
    network::in.flush(); network::out.flush();

    // Wait until it finishes, exit cleanly. We don't want for the input, because it doesn't
    // need to clean anything up.
    network_thread.join();

    for (auto& thread : wg_threads) thread.join();
  }
  exit(0);
}


/**
 * @brief The main function.
 * @param argc: The amount of command line arguments.
 * @param argv: The command line arguments.
 */
int main(int argc, char* argv[]) {
  #define MNAME "MAIN"

  // Set cleanup for SIGABRT, SIGINT, and SIGTERM.
  signal(SIGABRT, cleanup);
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);

  // Parse our arguments.
  std::vector<std::string> arguments(argv + 1, argv + argc);
  argument_parser(arguments);

  // Ensure OpenSSL is working correctly.
  wireguard::test();

  // Start the network thread, wait until it's ready
  output("Initializing Network Thread", MNAME, INFO);
  wireguard::config temp;
  network_thread = std::thread(network::thread, self.pair.p, temp);
  while (shared::stat != READY) {
    if (shared::stat == TERMINATE) {
      output("Network Thread exited! Exiting...", MNAME, ERROR);
      cleanup(0); exit(0);
    }
    sleep();
  }

  // When connecting to a WireGuard server, this contains
  // the information for talking to it. This is not to be
  // confused with the configuration when we are ourselves a
  // WireGuard server, in which case a new config is generated
  // and sent to the newly created WG Thread.
  wireguard::config wireguard_server = {};

  // Hold onto the cookies we send out to verify peers upon reconnection.
  std::map<con_t, crypto::string> cookies;

  // A mapping of names to connections, so the user doesn't need to type out 123.456.789.012:1234 every time.
  std::map<std::string, con_t> friends;
  auto get_dest = [&friends]() {

    // Get the destination.
    auto destination = input<std::string>("Enter IP:PORT or Alias", "NEW_UDP_ERROR");
    if (destination == "NEW_UDP_ERROR") throw std::runtime_error("Invalid destination");

    // Split up the address into the constiuent parts.
    connection f;
    auto colon = destination.find(":");
    if (colon != std::string::npos) {
      auto addr_str = destination.substr(0, colon);
      if (addr_str == "localhost") addr_str = "127.0.0.1";
      address_t address = inet_addr(addr_str.c_str());
      port_t port = std::atoi(destination.substr(colon + 1).c_str());

      // Ask the user to give this address an alias so they don't need to type it again.
      auto name = input<std::string>("Enter an alias name to associate with this peer!", "NEW_UDP_PEER_ERROR");
      if (name == "NEW_UDP_PEER_ERROR" || name.find(":") != std::string::npos)
        throw std::runtime_error("Invalid name! An alias name cannot contain ':'");

      // Put in the alias.
      f.pair = {.a = address, .p = port};
      friends[name] = f.num;
    }

    // Otherwise, assume it's an alias, and try and lookup.
    else {
      if (!friends.count(destination))
        throw std::runtime_error("Invalid destination! Ensure you either use IP:PORT, or provided the correct alias!");
      f.num = friends[destination];
    }
    return f;
  };

  // Non blocking access to standard input.
  int stdin = open("/dev/stdin", O_RDONLY | O_NONBLOCK);

  // We need noncanonical mode (IE we can poll from Standard Input without waiting for a newline/buffer)
  // On the main screen. This just saves our existing terminal configuration, and lets us swap
  // back to regular mode once we've made a choice.
  struct termios standard = {0}, noncanonical = {0};
  tcgetattr(0, &standard);
  tcgetattr(0, &noncanonical);
  noncanonical.c_lflag &= ~ICANON;
  noncanonical.c_lflag &= ~ECHO;
  noncanonical.c_cc[VMIN] = 1;
  noncanonical.c_cc[VTIME] = 0;

  // We loop until either the network thread terminates, or the user tells us to.
  while (true) {

    // If the network terminated, terminate as well.
    if (shared::stat == TERMINATE) {
      output("Network Thread exited! Exiting...", MNAME, ERROR);
      break;
    }

    // We poll standard input in non-canonical mode, letting us
    // accept characters without a new line buffer. However,
    // noncanonical mode requires us to manually update the input on delete/backspace.
    std::string input;
    char buf = 0;

    // Set noncanonical mode.
    tcsetattr(stdin, TCSANOW, &noncanonical);

    // Loop until the user presses enter.
    for (size_t x = 0; true; ++x) {
      clear();

      std::stringstream out;
      out << print_title(x / 2);

      // Check for handshake packets.
      // Just a note on implementation: I'm somewhat conflicted with
      // my opinion on the prolific usage of exceptions
      // (Especially in a loop). I could use
      // std::optional, but the amount of actual code would not change
      // since we would need an if/else to check if something was returned,
      // and it would also make it more difficult to understand:
      // auto ret = pop(); if (ret) auto packet = ret.value();
      // I think the idea that: if there's nothing to return,
      // raise a runtime exception, is more intuitive, but I've used
      // C++ since before std::optional existed, and as such the only
      // prior solution to convey a return of nothing WAS an exception.
      // That all said, if we were writing this for performance, we'd
      // want to use std::optional, rather than exceptions.
      try {

        // We only try to iterate once, such that we don't block the rest of the loop.
        const auto packet = network::in.pop(SYS, 1).cast<sys_packet>();

        // If we actually got a packet, then a peer wants to handshake.
        bool accept = packet.rekey;

        // This isn't strictly necessary according to the Reference, but if we already sent a cookie to the peer,
        // we aren't going to refuse them again.
        bool cookie = cookies.count(packet.source.num);
        crypto::string remote_pub = {&packet.pub[0], 32};

        // You don't get a choice if the server wants to rekey.
        if (!accept) {

          // Switch to standard mode to collect input.
          // (Input wouldn't be displayed on screen otherwise).
          tcsetattr(stdin, TCSANOW, &standard);
          std::stringstream msg;

          // Since we're sending the public key over the wire, make sure that it matches, and that
          // the server actually wants to accept this client.
          msg <<
          "Peer: " << connection_string(packet.source) << " Wants to connect to your WireGuard server.\n" <<
          "Their provided Public Key: " << remote_pub.substr(0,16).str() << '\n' <<
          "Your Public Key: " << wireguard::pair.pub().substr(0,16).str() << '\n' <<
          "Accept (y/N)?";

          // If the client already has a cookie, we don't allow the server to just
          // continually send cookies.
          if (!cookie) msg << " Or C to send a cookie";
          auto accept_str = shared::input<std::string>(msg.str());
          if (!cookie) cookie = (accept_str == "C" || accept_str == "c");
          accept = (accept_str == "Y" || accept_str == "y") || cookie;
        }

        // Rekeying does not require user confirmation.
        else output("Rekeying", MNAME, INFO);

        if (accept) {

          // We need to send the peer our own public key.
          sys_packet ret;
          ret.source =  self;
          memcpy(&ret.pub[0], wireguard::pair.pub().bytes(), 32);
          network::out.enqueue({packet.source, ret, sizeof(sys_packet)});

          // If the cookie exists, add it before starting the handshake
          wireguard::config wg = {};
          if (cookies.count(packet.source.num)) {
            wg.cookie = cookies[packet.source.num];

            // Just so the handshake knows there's a cookie to check.
            // If the actual timestamp was invalid, then the server
            // will fail to decrypt.
            wg.cookie_timestamp = 1;
            cookies.erase(packet.source.num);
          }

          // Try and commence the handshake. Note that the client may not accept our public
          // key, so this may fail with a timeout.
          try {
            auto connection = wireguard::Handshake(remote_pub, packet.source, false, network::in, network::out, wg, cookie);

            // If we just generated a cookie, and didn't actually complete a handshake,
            // then just store the cookie.
            if (connection.cookie_timestamp != 0) {
              cookies[packet.source.num] = connection.cookie;
              prompt("Cookie sent!");
            }

            // A rekey is initiated by the server. The client needs only update
            // their configuration.
            else if (packet.rekey) {
              wireguard_server = connection;
              wireguard_server.src = packet.source;

              // Visual indication for a rekey.
               pick_mode();
            }

            // Otherwise, the server spawns a new thread to handle these connections.
            else {
              connection.src = packet.source;
              port_t port = 0;
              wg_threads.emplace_back(std::thread(network::thread, port, connection));
              prompt("Success!");
              pick_title(); pick_mode();
            }
          }
          catch (std::runtime_error& e) {prompt(e.what());}
        }
      }

      // If there was no packet.
      catch (std::runtime_error& e) {}

      // Check for transport packets. These are just decrypted and added back into the in queue.
      try {
        const auto packet = network::in.pop(WG_TRANSPORT, 1);

        // If we got one, decrypt the packet and put it into the in queue to view.
        auto decrypted = wireguard::TransportPacket::Return(wireguard_server, packet);
        network::in.enqueue(decrypted);
      }
      catch (std::runtime_error& e) {}

      // Print the message.
      out <<
        "Public Key: " << wireguard::pair.pub().substr(0,16).str() << "\n" <<
        (!wireguard_server.on ? "Not connected to a WireGuard Server" : "Connected to server!") << "\n" <<
        "What would you like to do?\n" <<
        NEW << (!wireguard_server.on ? ". Send a UDP message" : ". Send a UDP message over WireGuard") << "\n" <<
        VIEW << ". View new messages (" << (network::in.size() > 0 ? GREEN : END) << network::in.size() << END  << ")\n" <<
        WG << (!wireguard_server.on ? ". Connect to a WireGuard Server" : ". Disconnect from the WireGuard Server") << "\n" <<
        QUIT << ". Quit\n";
      out << "Input: " << input << "\n";
      output(out.str());

      // Read from stdin; it's non-blocking, so if it returns <= 0, don't do anything.
      // We can't use std::cin if we want blocking, so we literally read the the STDOUT
      // FD in the same way we read from network FDs (Everything is a file).
      if (read(stdin, &buf, 1) > 0) {

        // In non-canonical mode, we need to handle things like ENTER/BACKSPACE.
        if (buf == '\n') break;
        else if (buf == 127 && !input.empty()) input.pop_back();

        // If no special case, just add it to our input.
        else input += buf;
      }

      // We update more regularly than the threads so the input update is more snappy.
      shared::sleep(50);
    }

    // Return back to canonical mode.
    tcsetattr(0, TCSANOW, &standard);

    // Cast it into a choice we can parse.
    option choice = std::atoi(input.c_str());

    // Send a UDP message
    if (choice == NEW) {
      try {
        auto connection = get_dest();
        // Get the message, enqueue the packet.
        output("What would you like to send?");
        std::string message;
        std::getline(std::cin, message);

        // If we have a WireGuard connection, encrypt the UDP packet and send
        // it across.
        auto packet = udp::packet(connection, message);
        if (wireguard_server.on)
          network::out.enqueue(wireguard::TransportPacket::Create(wireguard_server, packet));
        else network::out.enqueue(packet);
      }

      // If the user provides an invalid address/alias.
      // Again, reading this codebase in hindsight I can understand if you
      // find the use of exceptions... excessive, but I'm a fan of them
      // because they entirely eliminate the need of a special "error return"
      // (I'm looking at you, shared::input). If the user provides an
      // invalid value, "return" a runtime exception with context
      // as to what the error was. In the grand scheme of things,
      // a try/catch block would be replaced by an if/else block,
      // so it doesn't necessarily make the code messier, and
      // a prompt(e.what()) sure is cleaner than the OpenSSL
      // lambdas in crypto.h
      catch (std::runtime_error& e) {prompt_continue(e.what());}
    }

    // View new messages.
    else if (choice == VIEW) {
      // Iterate through each message, and display it.
      if (network::in.empty()) prompt("Nothing but crickets...");
      while (!network::in.empty()) {
        auto p = network::in.pop();
        std::string message;

        // If packet_print is on, display the entire formatted packet.
        if (packet_print) message = p.str();

        // Otherwise, just show source and data.
        else {
          std::stringstream msg;
          auto source = p.source();
          msg << "Message from: " << source.pair.a << ":" << source.pair.p << std::endl;
          msg << p.data() << std::endl;
          message = msg.str();
        }

        // You can reply, if you'd like.
        output(message);
        auto reply = shared::input<std::string>("Would you like to reply (y/N)", "N");
        if (reply == "y" || reply == "Y") {
          output("What would you like to send?");
          std::getline(std::cin, message);

          auto packet = udp::packet(p.source(), message);
          if (wireguard_server.on)
            network::out.enqueue(wireguard::TransportPacket::Create(wireguard_server, packet));
          else network::out.enqueue(packet);
        }
      }
    }

    // Manage WireGuard connections.
    else if (choice == WG) {

      // If the user selected this, and we have a server, then
      // we disconnect from the server.
      connection connection;
      if (wireguard_server.on) {

        // Tell the Network Thread to hangup the connection.
        network::out.enqueue(udp::packet::empty(wireguard_server.src));

        // Reset.
        wireguard_server = wireguard::config();
      }

      // I'm a fan of how else is a separate keyword, unlike the elif's of Python and others.
      // This lets us have else try, else switch, else throw, etc.
      else try {
        connection = get_dest();
        // Don't let the peer constantly ping the server.
        if (wireguard_server.cookie_timestamp != 0 && (TimeSeconds() - wireguard_server.cookie_timestamp < wireguard::REKEY_TOUT)) {
          prompt("Please wait before trying to connect to the server!");
          continue;
        }

        // Send our public key, wait them to send theirs.
        sys_packet info = {.source =  self};
        memcpy(&info.pub[0], wireguard::pair.pub().bytes(), 32);
        auto packet = udp::packet(connection, info, sizeof(info));
        network::out.enqueue(packet);

        // Wait the server public key.
        output("Waiting for peer to respond");
        auto response = network::in.pop(SYS, 300).cast<sys_packet>();
        crypto::string remote_pub = {&response.pub[0], 32};

        // Ensure that the public key is expected. As per The WireGuard Reference, we are supposed to be pretty stealthy,
        // so if we don't get the expected key, we just ghost the responder.
        auto accept = shared::input<std::string>("The Server's Public Key: " + remote_pub.substr(0,16).str() + ". Is this correct? (y/N)");
        if (accept != "Y" && accept != "y") {
          output("Incorrect public key. Refusing to continue Handshake", MNAME, WARN);
          continue;
        }

        // Request a handshake.
        wireguard_server = wireguard::Handshake(remote_pub, connection, true, network::in, network::out, wireguard_server);

        // We automatically store the cookie into the configuration, and
        // thus will automatically pass it to the
        if (wireguard_server.cookie_timestamp != 0) {
          prompt("The server sent back a cookie. Try again later!");
        }

        // Otherwise, get the initial packet from the Thread to setup
        // the client FD, and then let the user know we're connected.
        else {
          auto initial = network::in.pop(SYS).cast<sys_packet>();
          wireguard_server.src = initial.source;

          // We need the server to have a FD to the client in order for key-exchange
          // to work.
          network::out.enqueue({wireguard_server.src, "Hello!"});

          std::stringstream msg;
          msg << "Success! WireGuard endpoint at " << wireguard_server.src.pair.a << ":" << wireguard_server.src.pair.p;
          prompt(msg.str());
          pick_title();
          pick_mode();
        }
      }

      // If something failed, prompt.
      catch (std::runtime_error& e) {
        prompt(std::string("Handshake Error: ") + e.what());
        network::out.enqueue(udp::packet::empty(connection));
      }
    }

    // Quit
    else if (choice == QUIT) {
      shared::stat = TERMINATE;
      break;
    }

    // ;)
    else if (choice == QUIT + 1) {pick_title(); pick_mode();}

    else {prompt("Invalid input");}
    clear();
  }

  close(stdin);
  cleanup(0);
  return 0;
}
