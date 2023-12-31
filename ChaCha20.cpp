#include <bits/stdc++.h>

using namespace std;

class ChaCha20
{
private:
    array<uint32_t, 16> state;          // The state array for ChaCha20
    array<uint32_t, 16> original_state; // The original state for counter overflow handling
    int rounds;                         // Number of rounds in ChaCha20

    // Function to perform a left rotation
    static constexpr int ROTATE_LEFT(uint32_t value, int shift)
    {
        return (value << shift) | (value >> (32 - shift));
    }

    // Function to perform the ChaCha20 quarter round operation
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

    // generates the key stream using quarter rounds
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

public:
    // initializer
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
};

//pseudo-random generator of nonce
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

//converts ascii string to int vector
vector<uint8_t> stringToVector(const string &input)
{
    vector<uint8_t> result;
    result.reserve(input.size());

    for (char c : input)
    {
        result.push_back(static_cast<uint8_t>(c));
    }

    return result;
}

//converts int vector to ascii string(readable)
string vectorToString(const vector<uint8_t> &input)
{
    ostringstream oss;

    for (uint8_t val : input)
    {
        oss << static_cast<char>(val);
    }

    return oss.str();
}

//converts hex string to int vector
vector<uint8_t> hexStringToBytes(const std::string &hexString)
{
    std::vector<uint8_t> bytes;

    if (hexString.length() % 2 != 0)
    {
        throw std::invalid_argument("Hex string must have even length");
    }

    for (int i = 0; i < hexString.length(); i += 2)
    {
        std::string hexByte = hexString.substr(i, 2);
        uint8_t byte = std::stoul(hexByte, nullptr, 16); // Convert hex string to byte
        bytes.push_back(byte);
    }

    return bytes;
}

//prints the int vector as hex string
void printHexVector(std::vector<uint8_t> &data)
{
    for (uint8_t &byte : data)
    {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::endl;
}

//user input for getting the key
vector<uint8_t> getKeyFromUser()
{
    vector<uint8_t> key(32);
    cout << "Enter a 256-bit key (32 bytes in hexadecimal): ";
    string keyInput;
    cin >> keyInput;
    key = hexStringToBytes(keyInput);
    return key;
}

//user input for getting the nonce
vector<uint8_t> getNonceFromUser()
{
    vector<uint8_t> nonce(12);
    cout << "Enter the nonce you got after encryption: ";
    string nonceInput;
    cin >> nonceInput;
    nonce = hexStringToBytes(nonceInput);
    return nonce;
}

//user input for getting the cipher text
vector<uint8_t> getCipherFromUser()
{
    vector<uint8_t> cipherData;
    cout << "Enter your cipher(in hexadecimal format, same as you got after encryption): ";
    string cipherInput;
    cin >> cipherInput;
    cipherData = hexStringToBytes(cipherInput);
    return cipherData;
}

int main()
{
    char choice;
    cout << "Choose an option (E for encrypt, D for decrypt): ";
    cin >> choice;

    if (toupper(choice) == 'E') //goes towards encryption
    {
        vector<uint8_t> key = getKeyFromUser();
        string plaintext;
        cout << "Enter plaintext: ";
        cin.ignore();
        getline(cin, plaintext);

        vector<uint8_t> nonce = generateNonce();
        ChaCha20 cipher(key, nonce);
        vector<uint8_t> plaintext_data = stringToVector(plaintext);     //makes the ciphertext machine readable
        vector<uint8_t> cipherData = cipher.encrypt(plaintext_data);

        cout << "Ciphertext: ";
        printHexVector(cipherData);     //prints the cipher as a hex string so that we can copy easily
    }
    else if (toupper(choice) == 'D')    //goes towards decryption
    {
        vector<uint8_t> key = getKeyFromUser();
        vector<uint8_t> nonce = getNonceFromUser();
        vector<uint8_t> cipherData = getCipherFromUser();

        ChaCha20 cipher(key, nonce);
        string decryptedText = vectorToString(cipher.decrypt(cipherData));  //makes the decrypted data human readable

        cout << "Decrypted plaintext: " << decryptedText << endl;
    }
    else
    {
        cout << "Invalid choice." << endl;  // choice other that D or E won't work
    }

    return 0;
}
