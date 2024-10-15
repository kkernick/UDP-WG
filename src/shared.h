#pragma once

#include <arpa/inet.h>
#include <iostream>
#include <random>
#include <sys/ioctl.h>
#include <fstream>
#include <atomic>
#include <thread>
#include <sstream>

#include "crypto.h"

/**
 * @brief The shared namespace.
 * @param This namespace contains a smattering of objects and functions
 * that are used by the other files.
 */
namespace shared {

  // To make it more obvious what we're using these for.
  using port_t = uint16_t;
  using address_t = uint32_t;
  using fd_t = int32_t;
  using con_t = uint64_t;


  // WireGuard uses the first byte of each Packet to define what it's for.
  // We borrow this for our own internal packets.
  using tag = uint8_t;
  tag NONE = 0x0, WG_HANDSHAKE = 0x1, SYS = 0x2, WG_COOKIE = 0x3, WG_TRANSPORT = 0x4;


  // A connection contains both an address, and a port.
  // For hash maps, we want a single value, but when
  // constructing packets we want an address and port.
  // We can be clever about this, by simply making it
  // a union, one member being a 64 bit struct with the a,p,
  // and another being a 64 bit number. C will automatically
  // break the 64 bit value up for the former, or just leave
  // it as-is. Unions are really cool, and I sincerely regret
  // not implementing the AES State in AES-DH as an array of 4 unions,
  // with one element being a uin32_t to get the entire value, and
  // the other a series of 4 uint8_t's.
  typedef union {
    struct {
      address_t a = 0;
      port_t p = 0;
    } pair;
    con_t num = 0;
  } connection;


  /**
   * @brief Get a string representation of the connection.
   * @returns the string.
   */
  std::string connection_string(const connection& c) {
    return std::to_string(c.pair.a) + ":" + std::to_string(c.pair.p);
  }


  /**
    * @brief Get the current TAI64N timestamp.
    * @returns The formatted timestamp.
    * @remarks As per the WireGuard Reference (5.4): "[is] 12 bytes of output, the first 8
    * bytes being a big-endian integer of the number of seconds since 1970 TAI and the last 4 bytes being a
    * big-endian integer of the number of nanoseconds from the beginning of that second.
    * @remarks Getting the needed information is rather trivial, although we do need to do some bitshifting
    * to get the little-endian values into big-endian format into the string.
    */
  crypto::string Timestamp() {

    // Get the time.
    crypto::string time = 12;
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t seconds = ts.tv_sec; uint32_t nano = ts.tv_nsec;

    // Copy to the right sections.
    memcpy(time.bytes(), reinterpret_cast<char*>(&seconds), sizeof(uint64_t));
    memcpy(time.bytes() + 8, reinterpret_cast<char*>(&nano), sizeof(uint32_t));

    return time;
  }


  /**
   * @brief Compares two timestamps.
   * @param a: The first
   * @param b: The second
   * @returns If the timepoint at a is greater or equal to b.
   */
  bool TimestampGreater(const crypto::string& a, const crypto::string& b) {

    // Get the seconds, compare them
    const uint64_t
      sec_a = *reinterpret_cast<const uint64_t*>(a.bytes()),
      sec_b = *reinterpret_cast<const uint64_t*>(b.bytes());
    if (sec_a > sec_b) return true;
    if (sec_a < sec_b) return false;

    // If the seconds are the same, match the nanoseconds.
    const uint32_t
      nan_a = *reinterpret_cast<const uint32_t*>(a.bytes() + 8),
      nan_b = *reinterpret_cast<const uint32_t*>(b.bytes() + 8);

    // If the seconds+nano are equal, we return true.
    if (nan_a >= nan_b) return true;
    return false;
  }


  /**
   * @brief Return the time between each timestamp in seconds.
   * @param a: The first timestamp.
   * @param b: The second timestamp, defaulting to the current time.
   * @returns The time between the two in seconds.
   * @remarks This function returns the absolute difference.
   */
  size_t TimestampDiff(const crypto::string& a, const crypto::string& b = Timestamp()) {
    uint64_t as = *reinterpret_cast<const uint64_t*>(a.bytes()), bs = *reinterpret_cast<const uint64_t*>(b.bytes());
    return as < bs ? bs - as : as - bs;
  }


  /**
   * @brief Get the current UNIX timestamp.
   * @returns The seconds since January 1st, 1970.
   */
  uint64_t TimeSeconds() {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t seconds = ts.tv_sec; uint32_t nano = ts.tv_nsec;
    return seconds;
  }


  // These are our default source port/address. The user can change them
  // using command line arguments.
  connection self = {.pair {.a = inet_addr("127.0.0.1"), .p = 5000}};


  /**
   * @brief A system packet.
   * @remarks Originally, I had planned on making a separate program that
   * would generate WireGuard configurations to files, which would then
   * be read by the client/server prior to connecting. However, I decided against
   * it to not make the connection process cumbersome; instead, when a client
   * wants to establish a wireguard connection, they'll send one of these across,
   * which just contains their public key and source (The only parts of knowledge
   * needed to facilitate a handshake). Does this theoretically present a security
   * vulnerability? I don't think so. The local public key is truncated and
   * displayed on the main page, and both the server and client need to manually
   * confirm that the public key they received is the one they expected. Without
   * the corresponding private key, it's impossible for an attacker to try and
   * sit in the middle.
   */
  typedef struct sys_packet {
    uint8_t tag = SYS;
    unsigned char pub[32] = {0};
    connection source = {};
    bool rekey = false;
  } sys_packet;


  /**
   * @brief Status used to communicate between Main and Network Threads.
   */
  typedef enum {DEAD, INIT, READY, TERMINATE} status;

  // Flags shared by the main+network threads.
  std::atomic<status> stat = DEAD;      // Terminate all threads
  std::atomic<bool> verbose = false;    // Display verbose information.
  std::atomic<bool> log = false;        // Log information to a file
  std::string logfile = "main.log";     // Where to log information.

  // RNG
  std::random_device dev;
  std::mt19937 rng(dev());

  // A lock to ensure the main/network don't conflict in output.
  std::mutex io_lock;

  // Color coded messages for output.
  typedef enum {STANDARD, INFO, WARN, ERROR, SUCCESS} message_type;
  constexpr char
    END[] = "\e[0m", RED[] = "\e[31m", YELLOW[] = "\e[1;33m",
    GREEN[] = "\e[32m", BLUE[] = "\e[34m", VIOLET[] = "\e[35m";


  /**
   * @brief Sleep.
   * @param milliseconds: The amount of milliseconds to sleep for.
   * @remarks This program doesn't use semaphores or any similar construct to wake a thread up
   * Instead, we just loop and sleep. It's less efficient, but it's simpler.
   */
  void sleep(const size_t& milliseconds=100) {std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));}


  /**
   * @brief Output to STDOUT, thread safe.
   * @param message: The message to print.
   * @param thread: For non-standard output types, the thread where the message is being sent from.
   * @param t: The type of message. Standard gets output without formatting. Others print the thread
   * and color code the output.
   */
  void output(const std::string& message, const std::string& thread="SYS", const message_type& t=STANDARD) {
    std::lock_guard<std::mutex> guard(io_lock);

    // If logging, log non-standard output.
    if (log && t != STANDARD) {
      auto outfile = std::ofstream(logfile, std::ios_base::app);
      outfile << TimeSeconds() << ": ";
      outfile << thread << ": " << message << std::endl;
      outfile.close();
    }

    // Handle our cases.
    if (t == STANDARD) std::cout << message << std::endl;
    else if (t == ERROR) std::cerr << RED << thread << "! " << message << END << std::endl;
    else if (t == SUCCESS) std::cerr << GREEN << thread << ": " << message << END << std::endl;

    // Only display INFO and WARN if verbose logging.
    else if (verbose) {
      if (t == INFO) std::cout << thread << ": " << message << std::endl;
      else if (t == WARN) std::cout << YELLOW << thread << ": " << message << END << std::endl;
    }
  }


  // A macro to prompt, then return from a function.
  #define prompt_return(msg) {prompt(msg); return;}
  // A macro to prompt, then break from a loop/switch
  #define prompt_break(msg) {prompt(msg); break;}
  // A macro to promptly, then continue from a loop
  #define prompt_continue(msg) {prompt(msg); continue;}


  /**
  * @brief Clear the screen.
  * @remarks This works on UNIX/Windows. It's a shell escape sequence.
  */
  inline void clear() {output("\033[2J\033[1;1H");}


  /**
  * @brief std::cin can be a little difficult to use, particularly handling bad input. This sanitized it.
  * @tparam T: The type of input to be returned.
  * @param title: A title to be drawn for the input
  * @param error_ret: If something causes an error, what we should return to let the caller know.
  * @return The user input, or the error return.
  * @remarks This function does not re-prompt upon errors; it is the responsibility of the caller to check for the
  * error return and act accordingly.
  * @warning This function is blocking.
  */
  template <typename T = bool> inline T input(const std::string& title, const T& error_ret = T()) {
    T ret;

    // Print the title, get the input.
    output(title);
    std::cin >> ret;

    // If it failed, clear the buffer and set the error return.
    auto f = std::cin.fail();
    if (f) {
      std::cin.clear();
      ret = error_ret;
    }

    // Skip past whatever garbage the user may have added.
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    // Return.
    return ret;
  }


  /**
  * @brief Prompt the user and wait until they have confirmed it
  * @param message: The message to display.
  * @warning This function is blocking.
  */
  inline void prompt(const std::string& message) {
    output(message);
    output("Press Enter to Continue");
    getchar();
  }


  // If we're going to have a dynamically updating main menu, we might as well have some fun with it ;)
  std::vector<std::vector<std::string>> titles = {
    {
      "UDP-WG",
    },
    {
      "   __  ______  ____      _       ________",
      "  / / / / __ \\/ __ \\    | |     / / ____/",
      " / / / / / / / /_/ /____| | /| / / / __",
      "/ /_/ / /_/ / ____/_____/ |/ |/ / /_/ /",
      "\\____/_____/_/          |__/|__/\\____/"
    },
    {
      "__/\\\\\\________/\\\\\\__/\\\\\\\\\\\\\\\\\\\\\\\\_____/\\\\\\\\\\\\\\\\\\\\\\\\\\__________________/\\\\\\______________/\\\\\\_____/\\\\\\\\\\\\\\\\\\\\\\\\_        ",
      " _\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\////////\\\\\\__\\/\\\\\\/////////\\\\\\_______________\\/\\\\\\_____________\\/\\\\\\___/\\\\\\//////////__       ",
      "  _\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\______\\//\\\\\\_\\/\\\\\\_______\\/\\\\\\_______________\\/\\\\\\_____________\\/\\\\\\__/\\\\\\_____________      ",
      "   _\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\\\\\\\\\\\\\\\\\\\\\/___/\\\\\\\\\\\\\\\\\\\\\\_\\//\\\\\\____/\\\\\\____/\\\\\\__\\/\\\\\\____/\\\\\\\\\\\\\\_     ",
      "    _\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\/////////____\\///////////___\\//\\\\\\__/\\\\\\\\\\__/\\\\\\___\\/\\\\\\___\\/////\\\\\\_    ",
      "     _\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\_____________________________\\//\\\\\\/\\\\\\/\\\\\\/\\\\\\____\\/\\\\\\_______\\/\\\\\\_   ",
      "      _\\//\\\\\\______/\\\\\\__\\/\\\\\\_______/\\\\\\__\\/\\\\\\______________________________\\//\\\\\\\\\\\\//\\\\\\\\\\_____\\/\\\\\\_______\\/\\\\\\_  ",
      "       __\\///\\\\\\\\\\\\\\\\\\/___\\/\\\\\\\\\\\\\\\\\\\\\\\\/___\\/\\\\\\_______________________________\\//\\\\\\__\\//\\\\\\______\\//\\\\\\\\\\\\\\\\\\\\\\\\/__ ",
      "        ____\\/////////_____\\////////////_____\\///_________________________________\\///____\\///________\\////////////____",
    },
    {
      "$$\\   $$\\ $$$$$$$\\  $$$$$$$\\          $$\\      $$\\  $$$$$$\\  ",
      "$$ |  $$ |$$  __$$\\ $$  __$$\\         $$ | $\\  $$ |$$  __$$\\ ",
      "$$ |  $$ |$$ |  $$ |$$ |  $$ |        $$ |$$$\\ $$ |$$ /  \\__|",
      "$$ |  $$ |$$ |  $$ |$$$$$$$  |$$$$$$\\ $$ $$ $$\\$$ |$$ |$$$$\\",
      "$$ |  $$ |$$ |  $$ |$$  ____/ \\______|$$$$  _$$$$ |$$ |\\_$$ |",
      "$$ |  $$ |$$ |  $$ |$$ |              $$$  / \\$$$ |$$ |  $$ |",
      "\\$$$$$$  |$$$$$$$  |$$ |              $$  /   \\$$ |\\$$$$$$  |",
      " \\______/ \\_______/ \\__|              \\__/     \\__| \\______/",
    },
    {
      "888     888 8888888b.  8888888b.       888       888  .d8888b.",
      "888     888 888  \"Y88b 888   Y88b      888   o   888 d88P  Y88b",
      "888     888 888    888 888    888      888  d8b  888 888    888",
      "888     888 888    888 888   d88P      888 d888b 888 888",
      "888     888 888    888 8888888P\"       888d88888b888 888  88888",
      "888     888 888    888 888      888888 88888P Y88888 888    888",
      "Y88b. .d88P 888  .d88P 888             8888P   Y8888 Y88b  d88P",
      " \"Y88888P\"  8888888P\"  888             888P     Y888  \"Y8888P88",
    },
  };

  size_t title = 0, mode = 0;

  // Pick a color cycle.
  void pick_mode() {
    auto old = mode;
    do {

      // Once we have a connection, you don't get boring anymore.
      std::uniform_int_distribution<std::mt19937::result_type> mode_dist(1,6);
      mode = mode_dist(rng);
    } while (mode == old);
  }

  // Pick a title.
  void pick_title() {
    // Otherwise randomly choose one that will fit in the current terminal, but make sure we
    // don't choose the one we already have!
    auto old = title;
    size_t retry = 0;

    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    auto width = w.ws_col;

    do {
      if (retry == 100) title = 0;
      std::uniform_int_distribution<std::mt19937::result_type> title_dist(0,titles.size() - 1);
      title = title_dist(rng);
      ++retry;
    } while (titles[title][0].length() > width || title == old);
  }

  // Print the title.
  std::string print_title(const uint64_t& cycle) {
    std::stringstream ret;
    std::vector<std::string> lookup = {RED, YELLOW, GREEN, BLUE, VIOLET};

    for (size_t x = 0; x < titles[title].size(); ++x) {
      for (size_t y = 0; y < titles[title][x].length(); ++y) {
        size_t h = titles[title][x].length(), v = titles[title].size();
        switch (mode) {
          case 0: break;
          case 1: ret << lookup[(x + y + cycle) % 5]; break;
          case 2: ret << lookup[(x + cycle) % 5]; break;
          case 3: ret << lookup[(y + cycle) % 5]; break;
          case 4: ret << lookup[((v - x) + (h - y) + cycle) % 5]; break;
          case 5: ret << lookup[((v - x) + cycle) % 5]; break;
          case 6: ret << lookup[((h - y) + cycle) % 5]; break;
          default: break;
        }
        ret << titles[title][x][y];
      }
      ret << END << '\n';
    }
    return ret.str();
  }
}
