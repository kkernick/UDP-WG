#pragma once


#include <openssl/pem.h>  // For OpenSSL (HASH,MAC, HMAC)
#include <sodium.h>       // For libsodium (DH, DH_GENERATE, (X)ENCRYPT, (X)DECRYPT)
#include <stdexcept>      // Exceptions
#include <cstring>        // For std::string


/**
 * @brief The cryptographic implementations for WireGuard.
 * @remarks Like the main file at wireguard.h: this implementation was
 * created in reference to the WireGuard Whitepaper
 * (https://www.wireguard.com/papers/wireguard.pdf)
 * herein referred to as the "Reference"
 * @remarks Originally, I intended to implement all the cryptographic
 * algorithms using OpenSSL. This would not only reduce the amount of
 * dependencies, but effectively eliminate them as most Linux systems
 * already have it. However, OpenSSL neither support XChaCha20-Poly1305,
 * and it's Curve25519 was not giving me correct results. Therefore,
 * these parts of the program have been implemented using libsodium,
 * which, rather unfortunately, was also unable to provide all the
 * required functions (It doesn't have BLAKE2s support).
 * @remarks This namespace has the perk of showing both how to work
 * with OpenSSL, and Sodium. The latter is much easier to work with,
 * as OpenSSL's design of leasing dynamically allocated objects,
 * checking the result of every call, and then having to free
 * those objects is usually a pain to work with. Most solutions
 * I've seen pick the lesser of two evils: Free all the resources
 * within each error check, which clogs the code with duplication,
 * or--worse--use goto statements to just jump to the end of the
 * function. The approach I've taken is have each function be
 * a wrapper for a lambda that makes all the OpenSSL calls (Or
 * at least the ones that can give errors). The main function
 * can then allocate everything, run the function, and then free
 * everything afterwards, and the lambda is free to abort at
 * any point back to the caller. This isn't really what lambdas
 * were made for, but it makes the code cleaner, doesn't clutter
 * the namespace with auxiliary functions,and ensures proper memory
 * management and error checking.
 */
namespace crypto {


  /**
   * @brief A cryptographically secure string.
   * @remarks Originally, the reason for this class' existence was because OpenSSL
   * deals with unsigned characters, whereas the std::string deals with signed. Usually
   * C++ is nice and will implicitly cast types, but apparently there are irreconciable
   * differences between how these two datatypes are stored, and as such the ISO forbids
   * implicit casting. Therefore, this object was little more than a std::string imitator
   * that implemented the key functions, but with unsigned characters in the back, and
   * with the ability to easily convert back and forth. However, this object quickly
   * became ubiqutous, to the point that there was no reason to convert back to
   * std::string. This provides an opportunity to make the object more cryptographically secure.
   * In essence, all it does is zero any information that was stored in it during its destruction.
   * I toyed with encrypting the stored data, perhaps using the time or something similar, but
   * also didn't want to over complicated something that isn't the main focus of this project.
   * I bring this up because it's strongly recommended not to use interpereted languages like
   * Python or Shell Scripting Languages like Bash for cryptographic implementations, chiefly
   * because their abstraction of memory makes it difficult to wipe sensitive data.
   */
  class string {
    private:


    // We just use a vector under the hood, because they're wicked fast and manage memory for us.
    std::vector<unsigned char> array;


    public:


    /**
     * @brief Construct a string with a fixed, zeroed size.
     * @param l: The size of the object (It can still grow/shrink, but this
     * allows us to pass it into memcpy where it expects a certain size).
     * @remarks This is the wonderful reason why we can do crypto::string a = 32,
     * and have a 32 byte string.
     */
    string(const size_t& l = 0) {for (size_t x = 0; x < l; ++x) array.emplace_back(0);}


    /**
     * @brief Construct a string from a std::string.
     * @param string: The string.
     */
    string(const std::string& string) {
      for (size_t x = 0; x < string.length(); ++x) array.emplace_back(unsigned(string[x]));
    }


    /**
     * @brief Construct a string from a character array and size.
     * @param string: The input string.
     * @param l: The size of the string.
     * @warning This function does not check if the provided size
     * is bounded by the size of the string!
     */
    string(const unsigned char* string, const size_t& l) {
      for (size_t x = 0; x < l; ++x) array.emplace_back(string[x]);
    }


    /**
     * @brief Construct a string from a character array.
     * @param string: The input string.
     * @remarks This function is used for constructing from string literals
     * IE crypto::string a = "Hello!";
     * @warning This function uses strlen to determine length. If your string
     * is not null terminated, this function will read out of bounds!
     */
    string(const char* string) {
      for (size_t x = 0; x < strlen(string); ++x) array.emplace_back(string[x]);
    }


    /**
     * @brief Destroy the string.
     * @remarks Zeros the content.
     * @remarks A brief aside on memory management, and an interesting feature of the STL
     * (Or, in other words, skip this if you don't want to read a wall of C++ semantics)
     * One utility that I use for every C/C++ program is Valgrind; basically, the dynamic
     * memory allocators like malloc/calloc/realloc are prone to erroneous use, and this
     * program will run underneath the one you've created, hooking those functions and
     * reporting when you use them incorrectly (Failing to free dynamic memory, trying
     * to free it twice, etc). These functions are often pointed to when people claim that
     * C/C++ is a antiquated language, recommending instead the ridiculously slow Python,
     * or the ridiculously convulted ownership/reference system of Rust (I speak from
     * personal experience on both counts). In my, truthfully biased opinion, I don't
     * consider this argument particularly compelling, because the dynamic memory functions
     * work excellently, and errors arise not because of the language, but because of the
     * the programmer using it. All that said, if you run Valgrind with this program,
     * you'll notice some strange "Still Accessible" remarks, which technically aren't errors,
     * or anything to worry about, but they all come from this class. I found this exceptionally
     * confusing, because we don't use any dynamic allocators, we use the std::vector specifically
     * to avoid manual memory handling. Turns out, one reason that the STL classes are so
     * fast is because they pool memory between each other. In essence, the STL will create a
     * a massive pool of memory allocated in one massive block at the start of the program run,
     * and then everything from std::string, std::list, std::queue, and std::any will draw
     * upon this pool, and will "free" it by simply setting it to nullptr. This is brilliant,
     * not only because it could be done by something so prolifically used as the STL, but because
     * it ensures a single allocation and free, effectively eliminating the issue of memory leaking,
     * while improving performance. The only downside of this approach is that Valgrind wasn't
     * built to understand this, so when the std::vector calls its destructor, Valgrind notices
     * that there's still a handle to this pool, which could be indicative of having two pointers
     * to the same dynamic address, freeing one, and then trying to access that freed memory with
     * the second (Exceptionally bad).
     */
    ~string() {for (auto& x : array) x = '\0';}


    /**
     * @brief Return a subset of the string.
     * @param start: The left bound
     * @param count: The amount of characters to read from the left bound. std::string::npos
     * means everything until the end of the string.
     * @returns The substring.
     */
    string substr(const size_t& start, const size_t& count = std::string::npos) const {

      // These one-line if statements might seem a little confusing, but the general structure is:
      // CONDITION ? IF TRUE : IF FALSE
      // So, here we're setting the value ret to either two values, depending on whether
      // count == std::string::npos (Which just means the end of the string, std::string
      // uses it when find() doesn't return anything, for example)
      // If it is, we obviously don't want to make the string SIZE_MAX bytes long,
      // so we instead just set it to the size of the array - where we want to start from.
      // Otherwise, we use count as you expect, setting ret to how many characters we
      // want to draw from.
      string ret = count == std::string::npos ? array.size() - start : count;
      for (size_t x = 0; x < count && x + start < array.size(); ++x) {
        ret.bytes()[x] = array[x + start];
      }
      return ret;
    }


    /**
     * @brief Resize the string.
     * @param n: The new size.
     * @param v: The character to use to fill new spaces
     */
    void resize(const size_t& n, const unsigned char& v=0) {array.resize(n, v);}


    /**
     * @brief Append another string to end of the caller.
     * @param s: The string to append.
     */
    void append(const string& s) {
      for (const auto& x : s.array) array.emplace_back(x);
    }


    /**
     * @brief Return a hexadecimal representation of the crypto::string
     * @returns The hex string.
     */
    std::string str() {
      std::stringstream out;
      for (const auto& byte : array) out << std::hex << int(byte);
      return out.str();
    }


    /**
     * @brief Return the length of the string.
     * @returns The length.
     */
    const size_t length() const {return array.size();}


    /**
     * @brief Return a mutable byte array that can be directly manipulated.
     * @returns The beginning of the string.
     * @remarks This relies on the fact that vector's store their information
     * contiguously: https://en.cppreference.com/w/cpp/container/vector
     */
    unsigned char* bytes() {return &array[0];}


    /**
     * @brief Return a immutable byte array of the internal values.
     * @returns The byte array.
     * @remarks Typically, function overloads (IE two functions with
     * identical names) Cannot be solely distinguished by return type.
     * This makes sense, because if you have two functions A(), and do
     * something like auto ret = A(), the compiler has no way to know
     * which version you wanted. However, constant overloads allow this.
     * In essence, this function just means, if the crypto::string is a
     * constant value (IE const std::crypto my_string), then rather
     * than returning a mutable character array (Which would circumvent
     * the constant qualifier, and thus the compiler would refuse it),
     * we return a constant pointer.
     */
    const unsigned char* bytes() const {return &array[0];}


    /**
     * @brief Return a std::string representation of the string.
     * @returns The string.
     */
    std::string to() const {return std::string(reinterpret_cast<const char*>(bytes()), array.size());}


    /**
     * @brief Index the string.
     * @param pos: The position.
     * @returns The mutable byte at that position.
     * @throws std::out_of_range if the position is out of bounds.
     */
    unsigned char& operator [](const size_t& pos) {
      if (pos >= array.size())
      throw std::out_of_range("Index into crypto::string out of range!");
      return array[pos];
    }


    /**
     * @brief Equivalence operator.
     * @param cmp: The string to compare against.
     * @returns Whether the strings are equal.
     */
    const bool operator == (const string& cmp) const {return array == cmp.array;}


    /**
     * @brief Concatonation operator.
     * @param a: The string to append.
     * @returns The caller concatenated with the input.
     */
    string operator + (const string& a) const {string ret = *this; ret.append(a); return ret;}
  };


  /**
   * @brief A simple private-public keypair.
   * @remarks This can be used in one of two ways: either as an
   * actual keypair, to which pub/priv semantics are used.
   * Or as a set of two strings, like key/nonce, where first/second
   * semantics are used, instead.
   */
  class keypair {
    private:

    // The private and public keys.
    string P, p;

    public:

    keypair() = default;
    keypair(const string& private_key, const string& public_key) : P(private_key), p(public_key) {}

    // Return the private key.
    string& priv() {return P;}
    const string& priv() const {return P;}

    // Return the public key.
    string& pub() {return p;}
    const string& pub() const {return p;}

    // Return the first key
    string& first() {return P;}
    const string& first() const {return P;}

    // Return the second.
    string& second() {return p;}
    const string& second() const {return p;}
  };


  /**
   * Perform a Curve25519 point multiplication on the public and private key.
   * @param keypair: The 32 byte public key and private key
   * @returns The 32 byte product.
   * @remarks See 5.4 of the Reference
   * @remarks Curve25519 Point Multiplication has this really interesting
   * property where if you have a two keypairs A and B, the result of
   * DH(A_priv, B_pub) is equal to DH(B_priv, A_pub). This means, that
   * by solely exchanging public keys, two peers can come to the same
   * value by simply multiplying their private key against the received
   * key. This is akin to how standard DH works (Hence the name),
   * Where we share a public value which is a generator raised to our
   * private key, and by raising this received value by our own private
   * key, we come to the same value.
   * @remarks Why does this work? In essence,
   * the private key is a very large number that gets multiplied.
   * to a generator (In this case the Curve25519 generator on its curve),
   * which returns us a point on that curve that is our public key.
   * The idea is that while multiplying the curve generator against the
   * private number is very quick, trying to derive the original private
   * key from only the public point requires tedious addition and is akin
   * to the discrete logarithm problem. Let's try expanding our values
   * (Note that operations like * and + are performed in GF(2**255 - 19):
   * 1. A_pub = G * A_priv; B_pub = G * B_priv
   * 2. DH(A_priv, B_pub) = DH(A_priv, G * B_priv) = A_priv * G * B_priv
   * 3. DH(B_priv, A_pub) = DH(B_priv, G * A_priv) = B_priv * G * A_priv.
   * And, thanks to the associative property of multiplication, we reach
   * the same value.
   */
  string DH(const string& priv, const string& pub) {
    string product = 32;
    if (crypto_scalarmult(product.bytes(), priv.bytes(), pub.bytes()) != 0)
      throw std::runtime_error("Failed to multiply keys!");
    return product;
  }


  /**
   * @brief Generate a Curve25519 keypair.
   * @returns {public,private} keypair of 32 bytes each.
   * @remarks WireGuard identifies peers and the interface (IE the server)
   * Via a Curve25519, 32-byte public key. This function uses Sodium to
   * generate such a keypair.
   * @remarks See Section 2 of the Reference.
   * @remarks Curve25519 is what is called an "Elliptic Curve," and is the EC
   * in ECC. It is literally a curve, derived from a mathematica functional:
   * such as y = x**2. This curve in particular is: y**2 = x**3 + 486662(x**2) +x.
   * So, how does this curve somehow generate a keypair? In my own personal readings,
   * I found this video: https://www.youtube.com/watch?v=NF1pwjL9-DE to be very helpful,
   * but I'll give you the summary: To generate a keypair, we first take a
   * point on the curve, G which is the generator. Everyone knows this
   * value, and its akin to the public g in Diffie-Hellman (Which is
   * where the DH in these functions come from, if you're interested).
   * Then, we generate a massive random number as our private key, and
   * the idea is that you continually add the generator to itself which,
   * due to the properties of the curve and the way you add (It's not
   * complicated, I just don't want to make this more verbose than it
   * already is), will leave you with a public value which is a point on
   * that curve, which is your private key multiplied by the generator.
   * We can easily calculate our public value from our private value and generator
   * by simply doing pub = priv * gen (Curve Multiplication is very fast), but
   * with only the public and generator values, the only way to find the private
   * is by brute forcing adding the generator over and over again until you
   * get the public value.
   * @remarks The mathematics behind this is very similar to AES's GF(256),
   * in fact, the name Curve25519 is because it's in GF(2**255 -19), and just
   * like GF(256), this field requires special functions for mathematical operations,
   * but is very fast (Hence why we can so quickly calculate pub*gen). I say this
   * because when this used to be implemented in OpenSSL, I had to manually implement
   * these operations. I based it off of another excellent source on the subject:
   * https://martin.kleppmann.com/papers/curve25519.pdf
   * but a combination of misusing OpenSSL's Curve25519 implementation, and trying
   * to implement the operations myself, led to it not working, and I was able to
   * reduce > 200 lines and a custom class into four lines of code with libsodium.
   */
   keypair DH_GENERATE() {

    // Hold our two 32 byte keys.
    string pub = 32, priv = 32;

    // Randomly generate a private key, get the public point on the curve.
    randombytes_buf(priv.bytes(), priv.length());
    crypto_scalarmult_base(pub.bytes(), priv.bytes());

    // Return
    return {priv, pub};
  }


  /**
   * @brief Format the IV array given the WireGuard Counter.
   * @param counter: The current WireGuard counter.
   * @remarks As per Section 5.4 of the Reference:
   * "[The nonce is] composed of 32 bits of zeros followed by the 64-bit little-endian value of
   * counter"
   * @remarks I have a suspicion that the reason for this format of the IV is the same reason
   * as the counter used in AES-GCM. We want a 96 bit nonce as per ChaCha20's requirements,
   * but there isn't exactly a 12 byte register for easily adding such a massive number.
   * Therefore, we use the largest value that can actually be executed on in a modern system,
   * 64 bits. Unlike GCM, however, 2**64 is such a monstrous number that there isn't much of
   * a risk of the WireGuard counter overflowing.
   */
  string IV(uint64_t counter) {

    // 32 bits (4 bytes) of zeros + 64 bits (8 bytes) of the counter = 96 bits (12 bytes).
    string iv = 12;

    // Extract the highest byte of the counter, shifting down to the last.
    for (size_t x = 0; x < 8; ++x) {
      iv[4 + x] = counter >> 56;
      counter << 8;
    }
    return iv;
  }


  /**
   * @brief Encrypt with ChaCha20-Poly1305
   * @param key: The 32 byte key key to use for encryption.
   * @param counter: The WireGuard Counter, for a nonce.
   * @param plain: The plaintext.
   * @param data: The AAD.
   * @returns The ciphertext
   * @remarks This encryption scheme is like AES-CTR + HMAC, in that ChaCha20 is a cipher (stream, not block),
   * and Poly1305 is a MAC that provides authentication. According to: https://en.wikipedia.org/wiki/ChaCha20-Poly1305
   * It's actually faster than AES-GCM. The delightful name of ChaCha is in reference to the scheme that it is based
   * on: Salsa20. They use Pseudo-Random number generators alongside Add-Rotate-XOR operations. Wikipedia
   * provides a sample implementation (https://en.wikipedia.org/wiki/Salsa20) that is a whole 32 lines.
   * @remarks A stream cipher, like ChaCha20, differs from a block cipher, like AES, in that rather than applying
   * a set of operations to blocks, like breaking a message into 16 byte states for AES, we instead generate a
   * "keystream", which we treat as one, massive one-time pad that we can XOR against the entire message. So,
   * rather than working on blocks, we work on each bit of the input, typically just XORing the bit against
   * the corresponding position in the keystream. This lets us stream values, such as incoming packets,
   * with a continuous keystream, which is perfect for network applications, where data is received
   * in such streams.
   * @remarks See https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/original_chacha20-poly1305_construction
   */
  string ENCRYPT(string key, const uint64_t& counter, const string& plain, const string& data) {
    // Ensure the key is of the correct size.
    key.resize(crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    // Initialize the max possible size that the encryption may take
    string cipher = plain.length() + crypto_aead_chacha20poly1305_ietf_ABYTES;
    long long unsigned int length = cipher.length();

    // Generate the Nonce.
    string nonce = IV(counter);

    // Encrypt.
    crypto_aead_chacha20poly1305_ietf_encrypt(
      cipher.bytes(), &length,
      plain.bytes(), plain.length(),
      data.bytes(), data.length(),
      nullptr,
      nonce.bytes(), key.bytes()
    );

    // Shrink based on the amount of bytes that were actually written.
    cipher.resize(length);
    return cipher;
  }


  /**
   * @brief Decrypt with ChaCha20-Poly1305
   * @param key: The 32 byte key.
   * @param counter: The WireGuard counter.
   * @param cipher: The ciphertext.
   * @param data: The AAD
   * @returns the plaintext string
   * @throws std::runtime_error If the key/data are invalid.
   * @remarks See https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/original_chacha20-poly1305_construction
   */
  string DECRYPT(string key, const uint64_t& counter, const string& cipher, const string& data) {
    key.resize(crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    // Reserve the maximum size.
    string plain = cipher.length() - crypto_aead_chacha20poly1305_ietf_ABYTES;
    long long unsigned int length = plain.length();

    auto nonce = IV(counter);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
      plain.bytes(), &length,
      nullptr,
      cipher.bytes(), cipher.length(),
      data.bytes(), data.length(),
      nonce.bytes(), key.bytes()) != 0) {
        throw std::runtime_error("Modified message! Refusing to decrypt!");
    }
    plain.resize(length);
    return plain;
  }


  /**
   * @brief Encrypt with XChaCha20-Poly1305
   * @param key: The 32 byte key key to use for encryption.
   * @param plain: The plaintext.
   * @param data: The AAD.
   * @returns The ciphertext + nonce
   * @remarks As per the reference, the nonce used for the X variants
   * are just randomly generated, and thus carted around with the return.
   * @remarks The X stands for Extended, because the Nonce is 192-bits. When choosing nonces at
   * random, it's got better security than the original ChaCha20-Poly1305, but it isn't technically
   * standardized, so OpenSSL doesn't implement it.
   * @remarks See https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
   */
  keypair XENCRYPT(string key, const string& plain, const string& data) {

    // Ensure the key is of the correct size.
    key.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    // Initialize the max possible size that the encryption may take
    string cipher = plain.length() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    long long unsigned int length = cipher.length();

    // Generate a random nonce.
    string nonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    randombytes_buf(nonce.bytes(), nonce.length());

    // Encrypt.
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      cipher.bytes(), &length,
      plain.bytes(), plain.length(),
      data.bytes(), data.length(),
      nullptr,
      nonce.bytes(), key.bytes()
    );

    // Shrink based on the amount of bytes that were actually written.
    cipher.resize(length);
    return {cipher, nonce};
  }


  /**
   * @brief Decrypt with XChaCha20-Poly1305
   * @param key: The 32 byte key.
   * @param pair: The cipher + nonce
   * @param data: The AAD
   * @returns the plaintext string
   * @remarks See https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
   */
  string XDECRYPT(string key, const keypair& pair, const string& data) {
    key.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    const auto& cipher = pair.first();
    const auto& nonce = pair.second();

    // Reserve the maximum size.
    string plain = cipher.length() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    long long unsigned int length = plain.length();

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
      plain.bytes(), &length,
      nullptr,
      cipher.bytes(), cipher.length(),
      data.bytes(), data.length(),
      nonce.bytes(), key.bytes()) != 0) {
        throw std::runtime_error("Modified message! Refusing to decrypt!");
    }
    plain.resize(length);
    return plain;
  }


  /**
   * @brief Generate a BLAKE2s256 Hash of the input.
   * @param in: The string to hash.
   * @returns the 32 byte hash
   * @remarks See 5.4 of the Reference.
   * @remarks BLAKE2 is neat, because it's a hashing algorithm that's based on the original BLAKE, which is
   * based on an algorithm we've already seen: ChaCha. Wikipedia states what makes BLAKE different:
   * "[A] permuted copy of the input block, XORed with round constants, is added before each ChaCha round."
   * So, WireGuard is almost entirely based on the ChaCha algorithm, with Curve25519 for Key generation.
   * BLAKE2 is also a really impressive algorithm: it's faster than MD5 and provides better security than SHA-2.
   * There are two types: BLAKE2b, and BLAKE2s; Sodium does not implement the latter, but WireGuard requires it
   * and as such we used OpenSSL for the implementation. Blake2s is specifically optimized for 32 bit computers.
   * @remarks Using BLAKE2s is really a baffling decision, and despite my best efforts could not come up with
   * a reason for why it was chosen. For context, BLAKE2b, despite using more rounds, is FASTER than BLAKE2s. The
   * only advantage of BLAKE2s is that it's for 8-32 bit platforms, whereas BLAKE2b is 64 bits. This is the reason
   * that Sodium doesn't have BLAKE2s support: It has no real advantage: https://github.com/jedisct1/libsodium/issues/531
   * "I'm very reluctant [to BLAKE2s], or more generally to adding anything that provides no value over what is already available."
   * Now, perhaps the reason is to provide support for older, 32 bit systems. That's all well and good, except for the
   * fact that we proflifically use 64 bit values, such as the WireGuard counter. Perhaps they did some benchmarking, but
   * I struggle to see how using an algorithm designed for 64 bits on a 32 bit at handshake and rekey would be slower than
   * doubling the needed clock cycles to update a counter that is updated on every message. Given that WireGuard is also
   * touted as a modern VPN, I feel like supporting 32 bit machines is anthesis to that design philosophy. At the end
   * of the day, it doesn't really make that much of a difference, it just means that I can't implement WireGuard exclusively
   * through Sodium, which I was hoping for.
   */
  string HASH(const string& in) {

    // Initialize the context.
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
   	if (mdctx == nullptr) {
      throw std::runtime_error("Failed to initialize context!");
    }

    // Hash the message.We enclose the OpenSSL calls into a DIGEST lambda.
    string hash = 32;
    auto DIGEST = [&in, &hash, &mdctx]() {

      // Initialize
     	if (EVP_DigestInit_ex(mdctx, EVP_blake2s256(), nullptr) != 1) return -1;

      // Add our input to the digest.
     	if (EVP_DigestUpdate(mdctx, in.bytes(), in.length()) != 1) return -2;

      // Handle any padding leftover.
      unsigned int length = 32;
     	if (EVP_DigestFinal_ex(mdctx, hash.bytes(), &length) != 1) return -3;
      if (length != 32) return -3;

      return 0;
		};

		// Get the result code, free the context
		auto result = DIGEST();
		EVP_MD_CTX_free(mdctx);

    // If an error, throw an exception.
    if (result < 0) {
      std::string reason = "BLAKE2s256: Failed to Hash: ";
      switch (result) {
        case -1: reason += "Failed to initiailze!"; break;
        case -2: reason += "Failed to digest!"; break;
        case -3: reason += "Failed to extract hash!"; break;
        default: reason += "Unknown reason!"; break;
      }
      throw std::runtime_error(reason);
    }
    return hash;
  }


  /**
   * @brief Compute an HMAC using BLAKE and a key.
   * @param key: The 32 byte key
   * @param input: The arbitrary sized input to hash.
   * @returns The 32 byte HMAC
   * @remarks See 5.4 of the Reference.
   * @remarks A very neat part of BLAKE2 is that it is a "Keyed-Hash." This means
   * that BLAKE2 directly supports providing a key alongside the data, returning
   * a MAC without needing to use algorithms like HMAC that use a hash under the hood.
   * @remarks This leads to a rather confusing section of the Reference, where it stipulates
   * two functions: HMAC, which uses BLAKE in an HMAC construction, and MAC, which is BLAKE
   * using it's self-keying functionality. OpenSSL's functionality is here:
   * https://docs.openssl.org/3.3/man7/EVP_MAC-BLAKE2/
   * OpenSSL also has an HMAC section:
   * https://docs.openssl.org/master/man3/HMAC
   * Which politely tells you that it's deprecated and to instead use...
   * https://docs.openssl.org/master/man3/EVP_MAC/
   * So we're back at EVP_MAC-BLAKE2. I couldn't figure out why WireGuard stipulates
   * the need for two separate MAC algorithms, especially when both are using the same
   * Hashing algorithm under the hood, and the only thing I could think of is that
   * HMAC returns 32 bytes, whereas MAC returns 16. I had a separate function
   * that actually used the BLAKE2s keyed for MAC, and HMAC-BLAKE2s for HMAC,
   * but I noticed that it returned the exact same thing, just truncated. So, to save
   * myself the redundant code, MAC just returns a truncated HMAC.
   */
  string HMAC(const string& key, const string& input, const size_t& size=32) {
    if (size > 32 || size == 0)
      throw std::out_of_range("HMAC can only output sizes from 1-32 inclusive!");

    // Initialize the BLAKE2sMAC.
    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "BLAKE2SMAC", nullptr);
    if (mac == nullptr) {
      throw std::runtime_error("Failed to fetch MAC!");
    }

    // Initiailze the context.
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == nullptr) {
      EVP_MAC_free(mac);
      throw std::runtime_error("Failed to initialize context!");
    }

    // Generate the hmac into the hmac string.
    string hmac = 32;
    auto GENERATE = [&key, &input, &hmac, &ctx, &size]() {
      if (EVP_MAC_init(ctx, key.bytes(), key.length(), nullptr) != 1) return -1;

      if (EVP_MAC_update(ctx, input.bytes(), input.length()) != 1) return -2;

      size_t length = hmac.length();
      if (EVP_MAC_final(ctx, hmac.bytes(), &length, hmac.length()) != 1) return -3;
      if (length != hmac.length()) return -3;

      return 0;
    };

    auto result = GENERATE();
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    // If an error, throw an exception.
    if (result < 0) {
      std::string reason = "BLAKE2s256-HMAC: Failed to Hash: ";
      switch (result) {
        case -1: reason += "Failed to initiailze!"; break;
        case -2: reason += "Failed to digest input!"; break;
        case -3: reason += "Failed to extract hmac!"; break;
        default: reason += "Unknown reason!"; break;
      }
      throw std::runtime_error(reason);
    }

    // Truncate.
    return hmac.substr(0, size);
  }


  /**
   * @brief OpenSSL makes no difference between HMAC-BLAKE2s256 and Keyed BLAKE2s256
   * Besides setting the size. Therefore, we can reuse the same code, and just return
   * the required 16 bytes, as opposed to the 32 expected from HMAC proper.
   * @param key: The 32-byte key
   * @param input: The arbitrary input
   * @returns THe 16 byte MAC.
   * @remarks My understanding of OpenSSL, and BLAKE2s, was that the 16 byte MAC
   * was a fundamentally different operation than the normal 32 byte HMAC. We can
   * tell OpenSSL the size of the resulting MAC via "size":
   * https://docs.openssl.org/3.0/man7/EVP_MAC-BLAKE2/#supported-parameters
   * But there was two problems with that: first, setting "size" caused a double-free,
   * and second, printing out the MAC's revealed that OpenSSL was just truncating the
   * output. Rather than use OpenSSL's unintuitive functions for setting size,
   * we can do it ourselves and truncate the result to 16.
   */
  string MAC(const string& key, const string& input) {return HMAC(key, input, 16);}


  /**
   * @brief Perform the HKDF scheme on our HMAC function.
   * @param n: The amount of rounds to run
   * @param key: The 32 byte key to use for the HMAC
   * @param input: The arbitrary sized input data for the HMAC.
   * @returns a Vector containing N elements of 32 bytes each.
   * @remarks See 5.4 of the Reference.
   * @remarks This is the nice thing about having all the algorithms implemented.
   * Since these build off each other, we don't even need to interface with OpenSSL
   * to implement this.
   * @remarks You may be concerned about how quickly this could become a monstrous
   * output, but WireGuard never uses KDF with a n greater than 3.
   * @remarks KDF works by taking an initial key and an input to derive a generation,
   * and then subsequently creates new iterations from that initial state (Sort of
   * like how AES' Key Schedule worked). The main idea between the algorithm is to
   * get multiple keys from a single input, but another use I've seen is intentionally
   * slowing down encryption to thwart attackers from repeatedly guessing.
   * For example, the GRUB bootloader uses PBKDF for encrypting the passwords of users
   * which is not to derive 50,000 separate keys, but to require more computation to
   * get the password at the end.
   */
  std::vector<string> KDF(const size_t& n, const string& key, const string& input) {
    std::vector<string> ret;

    // Create the initial generation, and first iteration.
    string g0 = HMAC(key, input);
    ret.emplace_back(g0);
    if (n == 1) return ret;

    // The 0 and 1 generations are the only ones that have unique construction.
    ret.emplace_back(HMAC(g0, 0x1));

    // Until we've added N items, keep adding new generations.
    while (ret.size() != n) {

      // Get the prior generation and add our current generation to the end.
      auto last = ret.back();
      auto size = ret.size();
      last.append({reinterpret_cast<const unsigned char*>(&size), sizeof(size)});

      // Generate.
      ret.emplace_back(HMAC(g0, last));
    }

    // Return the entire list of generations.
    return ret;
  }
}
