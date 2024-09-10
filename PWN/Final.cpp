#pragma comment(lib, "bcrypt")

// C API headers
#include <Windows.h> // bcrypt.h has a dependency on this header
#include <bcrypt.h> // crypto API

// C++ API headers
#include <iostream> // std::cout
#include <exception> // std::exception
#include <cstring> // memcpy
#include <ctype.h> // isprint

// macros from ntstatus.h
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

void ErrorHandler(NTSTATUS status)
{
    switch (status)
    {
    case STATUS_NOT_FOUND:
        throw std::exception("No provider was found for the specified algorithm ID.");
    case STATUS_NO_MEMORY:
        throw std::exception("A memory allocation failure occurred.");
    case STATUS_INVALID_PARAMETER:
        throw std::exception("One or more parameters are not valid.");
    case STATUS_BUFFER_TOO_SMALL:
        throw std::exception("The size of the key object specified by the cbKeyObject parameter is not large enough to hold the key object.");
    case STATUS_INVALID_HANDLE:
        throw std::exception("The algorithm handle in the hAlgorithm parameter is not valid.");
    case STATUS_SUCCESS: // success
        // no-op
        break;
    default:
        throw std::exception("Unknown failure.");
    }
}

void PrintHexChunk(const BYTE* buffer, size_t size)
{
    std::cout << " | ";
    for (size_t j = 0; j < size; ++j)
    {
        if (isprint(buffer[j]))
        {
            std::cout << buffer[j];
        }
        else
        {
            std::cout << ".";
        }
    }
    std::cout << std::endl;
}

void HexDump(const BYTE* buffer, size_t size)
{
    static const CHAR hexChars[] = "0123456789ABCDEF";
    size_t j = 0;

    for (size_t i = 0; i < size; ++i)
    {
        if (i != 0 && i % 16 == 0)
        {
            PrintHexChunk(buffer + j, 16);
            j = i;
        }

        std::cout << hexChars[(buffer[i] >> 0x04)] << hexChars[(buffer[i] & 0x0F)] << " ";
    }

    // print the remaining bytes
    std::cout << " | ";
    while (j < size)
    {
        if (isprint(buffer[j]))
        {
            std::cout << buffer[j];
        }
        else
        {
            std::cout << ".";
        }
        ++j;
    }
    std::cout << std::endl << std::endl;
}

const BYTE AES256KEYSIZE = 32;
const WCHAR messageToEncrypt[] = L"It is a sunny day today 🌞 but tomorrow it is going to rain 🌧!";
const WCHAR initializationVector[] = L"my initialization vector"; // TODO: Replace with your IV

int main()
{
    BCRYPT_ALG_HANDLE hBcryptAlg = nullptr;
    BCRYPT_KEY_HANDLE hBcryptKey = nullptr;
    BYTE rgAESKey[AES256KEYSIZE] = {}; // TODO: Replace with a random key
    int retVal = 0;

    // Calculate the size of the plaintext
    size_t plainTextSize = sizeof(messageToEncrypt);
    BYTE* vPlainText = new BYTE[plainTextSize];
    memcpy(vPlainText, messageToEncrypt, plainTextSize);

    // Calculate the size of the initialization vector
    size_t ivSize = sizeof(initializationVector);
    BYTE* vInitializationVector = new BYTE[ivSize];
    memcpy(vInitializationVector, initializationVector, ivSize);

    // Allocate space for ciphertext
    ULONG cbCipherText = 0;
    BYTE* vCipherText = nullptr;

    try
    {
        ErrorHandler(BCryptOpenAlgorithmProvider(&hBcryptAlg, BCRYPT_AES_ALGORITHM, nullptr, 0));
        ErrorHandler(BCryptGenerateSymmetricKey(hBcryptAlg, &hBcryptKey, nullptr, 0, rgAESKey, AES256KEYSIZE, 0));

        std::cout << "Plain text:\n";
        HexDump(vPlainText, plainTextSize);

        // Calculate the size of the cipher text
        ErrorHandler(
            BCryptEncrypt(
                hBcryptKey,
                vPlainText,
                plainTextSize,
                nullptr,
                vInitializationVector,
                ivSize,
                nullptr,
                0,
                &cbCipherText,
                0)); // No padding for CFB mode

        // Allocate ciphertext buffer
        vCipherText = new BYTE[cbCipherText];
        ErrorHandler(
            BCryptEncrypt(
                hBcryptKey,
                vPlainText,
                plainTextSize,
                nullptr,
                vInitializationVector,
                ivSize,
                vCipherText,
                cbCipherText,
                &cbCipherText,
                0)); // No padding for CFB mode

        std::cout << "After encryption:\n";
        HexDump(vCipherText, cbCipherText);

        // Clear the plaintext
        memset(vPlainText, 0, plainTextSize);

        ULONG cbPlainText = 0;

        // Reset the initialization vector to the initial value
        memcpy(vInitializationVector, initializationVector, ivSize);

        ErrorHandler(
            BCryptDecrypt(
                hBcryptKey,
                vCipherText,
                cbCipherText,
                nullptr,
                vInitializationVector,
                ivSize,
                vPlainText,
                plainTextSize,
                &cbPlainText,
                0)); // No padding for CFB mode

        std::cout << "After decryption:\n";
        HexDump(vPlainText, cbPlainText);
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
        retVal = -1;
        goto CLEANUP;
    }

CLEANUP:
    if (hBcryptAlg)
    {
        BCryptCloseAlgorithmProvider(hBcryptAlg, 0);
    }

    if (hBcryptKey)
    {
        BCryptDestroyKey(hBcryptKey);
    }

    delete[] vPlainText;
    delete[] vInitializationVector;
    delete[] vCipherText;

    return retVal;
}
