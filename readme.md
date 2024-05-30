# ChaCha20 easy implementation
This is an easy and intuitive implementation for ChaCha20 symmetric encryption algorithm. This implementation has been done for educational purposes only. No guarranty to be used at real world scenarios.

## Instructions for running:
* run the chacha20.cpp file using any c++ compiler. (Can also run online: https://www.programiz.com/cpp-programming/online-compiler/)
* In a single run of the program, only one encryption or decryption can be done.
### Encryption:
* example key: ```00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff```
* example plaintext: ```hello world!```
* when prompted, press E and enter to continue encryption. The nonce is unique and randomly generated for every encryption. Copy the nonce and ciphertext for decryption. 

Encryption demo:
```bash:
Choose an option (E for encrypt, D for decrypt): e
Enter a 256-bit key (32 bytes in hexadecimal): 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
Enter plaintext: hello world!
Generated Nonce: b4977c20fb9f18b7162812aa
Ciphertext: 3e28a3d25041cc880996ad00
```

### Decryption:
* run the program again and choose D.
* input the your key, nonce, ciphertext accordingly.

Decryption demo:
```bash
Choose an option (E for encrypt, D for decrypt): d
Enter a 256-bit key (32 bytes in hexadecimal): 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
Enter the nonce you got after encryption: b4977c20fb9f18b7162812aa
Enter your cipher(in hexadecimal format, same as you got after encryption): 3e28a3d25041cc880996ad00
Decrypted plaintext: hello world!
```


-----
## Program Explanation:

### Descriptions of the components:
####`Class ChaCha20`
- **Description:** Contains the core data and functions for a cryptographic operation. Every time the
program wants to encrypt or decrypt, it utilizes an object of this class.

#### `ROTATE_LEFT`
```c++
static constexpr int ROTATE_LEFT(uint32_t value, int shift)
    {
        return (value << shift) | (value >> (32 - shift));
    }
```
- **Description:** Performs a left rotation operation on a 32-bit value.
- **Parameters:** 
  - `value`: The value to be rotated.
  - `shift`: The number of bits to shift.
- **Return:** The result of the left rotation.

#### `quarterRound`
```c++
void quarterRound(int a, int b, int c, int d)
    {
        state[a] += state[b];
        state[d] = ROTATE_LEFT(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = ROTATE_LEFT(state[b] ^ state[c], 12);
        state[a] += state[b];
        state[d] = ROTATE_LEFT(state[d] ^ state[a], 8);
        state[c] += state[d];
        state[b] = ROTATE_LEFT(state[b] ^ state[c], 7);
    }
```
- **Description:** Executes the ChaCha20 quarter round operation on the state array.
- **Parameters:** 
  - `a`, `b`, `c`, `d`: Indices representing the state array elements.
- **Action:** Modifies the state array by applying the quarter round operation.
-----
#### `generateKeystream`
```c++
void generateKeystream()
    {
        array<uint32_t, 16> temp_state = state;

        for (int i = 0; i < rounds; i += 2)
        {
            // Odd rounds
            quarterRound(0, 4, 8, 12);
            quarterRound(1, 5, 9, 13);
            quarterRound(2, 6, 10, 14);
            quarterRound(3, 7, 11, 15);

            // Even rounds
            quarterRound(0, 5, 10, 15);
            quarterRound(1, 6, 11, 12);
            quarterRound(2, 7, 8, 13);
            quarterRound(3, 4, 9, 14);
        }
        // Adding the original state to the current state for counter incrementation
        for (int i = 0; i < 16; ++i)
        {
            state[i] += temp_state[i];
        }
    }
```
- **Description:** Generates the ChaCha20 keystream by performing multiple quarter rounds.
- **Action:** Alters the state array to produce the keystream for encryption/decryption.

#### `ChaCha20 constructor`
```c++
ChaCha20(const vector<uint8_t> &key, const vector<uint8_t> &nonce, uint32_t counter = 0, int rounds = 20)
    {
        // Set initial state constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Set key to inside state
        memcpy(&state[4], key.data(), key.size());

        // Set counter and nonce inside state
        state[12] = counter;
        memcpy(&state[13], nonce.data(), nonce.size());

        this->original_state = state;
        this->rounds = rounds;
    }
```
- **Description:** Constructor for the ChaCha20 class.
- **Parameters:** 
  - `key`: The encryption key provided by the user.
  - `nonce`: Nonce used for encryption/decryption.
  - `counter`: Initial counter value (default: 0).
  - `rounds`: Number of rounds for the ChaCha20 algorithm (default: 20).
- **Action:** Initializes the ChaCha20 state array with constants and user-provided key, nonce, and counter.
-----
#### `encrypt`
```c++
vector<uint8_t> encrypt(const vector<uint8_t> &data)
    {
        vector<uint8_t> encrypted(data.size()); // Initialize vector to store encrypted data
        size_t dataSize = data.size();          // Get the size of the data to be encrypted

        for (size_t i = 0; i < dataSize; i += 64)
        {                        // Process data in 64-byte blocks
            generateKeystream(); // Generate the ChaCha20 keystream for encryption

            size_t blockSize = min<size_t>(64, dataSize - i); // Determine block size for the current iteration

            for (size_t j = 0; j < blockSize; ++j)
            {
                // Encrypt each byte of the block using XOR operation with keystream
                encrypted[i + j] = data[i + j] ^ ((state[j >> 2] >> ((j & 3) << 3)) & 0xFF);
            }

            state[12]++; // Increment the counter in the state
            if (state[12] == 0)
            {
                // Handle counter overflow by adding the original state to the current state
                for (int k = 0; k < 16; ++k)
                {
                    state[k] += original_state[k];
                }
            }
        }

        return encrypted; // Return the encrypted data
    }
```
- **Description:** Encrypts input data using the ChaCha20 cipher.
- **Parameters:** 
  - `data`: Plain text input to be encrypted.
- **Return:** Vector containing the encrypted data.
- **Action:** Generates a keystream and applies XOR operations to produce ciphertext.

#### `decrypt`
```C++
vector<uint8_t> decrypt(const vector<uint8_t> &cipher)
    {
        vector<uint8_t> decrypted(cipher.size()); // Initialize vector to store decrypted cipher
        size_t cipherSize = cipher.size();          // Get the size of the cipher to be decrypted

        for (size_t i = 0; i < cipherSize; i += 64)
        {                        // Process cipher in 64-byte blocks
            generateKeystream(); // Generate the ChaCha20 keystream for decryption

            size_t blockSize = min<size_t>(64, cipherSize - i); // Determine block size for the current iteration

            for (size_t j = 0; j < blockSize; ++j)
            {
                // decrypt each byte of the block using XOR operation with keystream
                decrypted[i + j] = cipher[i + j] ^ ((state[j >> 2] >> ((j & 3) << 3)) & 0xFF);
            }

            state[12]++; // Increment the counter in the state
            if (state[12] == 0)
            {
                // Handle counter overflow by adding the original state to the current state
                for (int k = 0; k < 16; ++k)
                {
                    state[k] += original_state[k];
                }
            }
        }

        return decrypted; // Return the decrypted cipher
    }
```
- **Description:** Decrypts cipher text using the ChaCha20 cipher.
- **Parameters:** 
  - `cipher`: Cipher-text input to be decrypted.
- **Return:** Vector containing the decrypted data.
- **Action:** Utilizes the ChaCha20 encryption process with the same key and nonce to recover the original plaintext.

### Assistive functions:
#### `generateNonce`
```C++
vector<uint8_t> generateNonce()
{
    vector<uint8_t> nonce(12);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint8_t> distrib(0, 255);

    for (int i = 0; i < 12; ++i)
    {
        nonce[i] = distrib(gen);
    }

    cout << "Generated Nonce: ";
    for (int i = 0; i < 12; ++i)
    {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(nonce[i]);
    }
    cout << endl;
    return nonce;
}
```
- **Description:** Generates a random nonce of 12 bytes.
- **Return:** Vector containing the randomly generated nonce.

### Other utility, I/O and conversion functions:
```stringToVector```, ```vectorToString```, ```hexStringToBytes```, 
```getKeyFromUser```, ```getNonceFromUser```, ```getCipherFromUser```,
```printHexVector``` are used for their respective purposes. The main function
handles the program flow according to user's choice.

## Important Note
This program has been written as an academic assignment and for easy understanding of the algorithm. Usage of this code for real world application definitely not recommended by RakinRkz.
