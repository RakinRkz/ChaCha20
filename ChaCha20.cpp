#include <bits/stdc++.h>

using namespace std;

class ChaCha20
{
private:
    array<uint32_t, 16> state;
    array<uint32_t, 16> original_state;
    int rounds;

    static constexpr int ROTATE_LEFT(uint32_t value, int shift)
    {
        return (value << shift) | (value >> (32 - shift));
    }

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

    void generateKeystream()
    {
        array<uint32_t, 16> temp_state = state;

        for (int i = 0; i < rounds; i += 2)
        {
            quarterRound(0, 4, 8, 12);
            quarterRound(1, 5, 9, 13);
            quarterRound(2, 6, 10, 14);
            quarterRound(3, 7, 11, 15);

            quarterRound(0, 5, 10, 15);
            quarterRound(1, 6, 11, 12);
            quarterRound(2, 7, 8, 13);
            quarterRound(3, 4, 9, 14);
        }

        for (int i = 0; i < 16; ++i)
        {
            state[i] += temp_state[i];
        }
    }

public:
    ChaCha20(const vector<uint8_t> &key, const vector<uint8_t> &nonce, uint32_t counter = 0, int rounds = 20)
    {
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        memcpy(&state[4], key.data(), key.size());

        state[12] = counter;
        memcpy(&state[13], nonce.data(), nonce.size());

        this->original_state = state;
        this->rounds = rounds;
    }

    vector<uint8_t> encrypt(const vector<uint8_t> &data)
    {
        vector<uint8_t> encrypted(data.size());
        size_t dataSize = data.size();

        for (size_t i = 0; i < dataSize; i += 64)
        {
            generateKeystream();

            size_t blockSize = min<size_t>(64, dataSize - i);

            for (size_t j = 0; j < blockSize; ++j)
            {
                encrypted[i + j] = data[i + j] ^ ((state[j >> 2] >> ((j & 3) << 3)) & 0xFF);
            }

            state[12]++;
            if (state[12] == 0)
            {
                for (int k = 0; k < 16; ++k)
                {
                    state[k] += original_state[k];
                }
            }
        }

        return encrypted;
    }

    vector<uint8_t> decrypt(const vector<uint8_t> &cipher)
    {
        vector<uint8_t> decrypted(cipher.size());
        size_t cipherSize = cipher.size();

        for (size_t i = 0; i < cipherSize; i += 64)
        {
            generateKeystream();

            size_t blockSize = min<size_t>(64, cipherSize - i);

            for (size_t j = 0; j < blockSize; ++j)
            {
                decrypted[i + j] = cipher[i + j] ^ ((state[j >> 2] >> ((j & 3) << 3)) & 0xFF);
            }

            state[12]++;
            if (state[12] == 0)
            {
                for (int k = 0; k < 16; ++k)
                {
                    state[k] += original_state[k];
                }
            }
        }

        return decrypted;
    }
};

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

string vectorToString(const vector<uint8_t> &input)
{
    ostringstream oss;

    for (uint8_t val : input)
    {
        oss << static_cast<char>(val);
    }

    return oss.str();
}

vector<uint8_t> hexStringToBytes(const std::string &hexString)
{
    std::vector<uint8_t> bytes;

    if (hexString.length() % 2!= 0)
    {
        throw std::invalid_argument("Hex string must have even length");
    }

    for (int i = 0; i < hexString.length(); i += 2)
    {
        std::string hexByte = hexString.substr(i, 2);
        uint8_t byte = std::stoul(hexByte, nullptr, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

void printHexVector(std::vector<uint8_t> &data)
{
    for (uint8_t &byte : data)
    {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::endl;
}

vector<uint8_t> getKeyFromUser()
{
    vector<uint8_t> key(32);
    cout << "Enter a 256-bit key (32 bytes in hexadecimal): ";
    string keyInput;
    cin >> keyInput;
    key = hexStringToBytes(keyInput);
    return key;
}

vector<uint8_t> getNonceFromUser()
{
    vector<uint8_t> nonce(12);
    cout << "Enter the nonce you got after encryption: ";
    string nonceInput;
    cin >> nonceInput;
    nonce = hexStringToBytes(nonceInput);
    return nonce;
}

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

    if (toupper(choice) == 'E')
    {
        vector<uint8_t> key = getKeyFromUser();
        string plaintext;
        cout << "Enter plaintext: ";
        cin.ignore();
        getline(cin, plaintext);

        vector<uint8_t> nonce = generateNonce();
        ChaCha20 cipher(key, nonce);
        vector<uint8_t> plaintext_data = stringToVector(plaintext);
        vector<uint8_t> cipherData = cipher.encrypt(plaintext_data);

        cout << "Ciphertext: ";
        printHexVector(cipherData);
    }
    else if (toupper(choice) == 'D')
    {
        vector<uint8_t> key = getKeyFromUser();
        vector<uint8_t> nonce = getNonceFromUser();
        vector<uint8_t> cipherData = getCipherFromUser();

        ChaCha20 cipher(key, nonce);
        string decryptedText = vectorToString(cipher.decrypt(cipherData));

        cout << "Decrypted plaintext: " << decryptedText << endl;
    }
    else
    {
        cout << "Invalid choice." << endl;
    }

    return 0;
}
