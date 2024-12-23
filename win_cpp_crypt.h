// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <bcrypt.h>

#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>


// TODO list:
/*
    [x] rename vs solution
    [x] lower c++ standard to c++20
    [x] remove print in win_cpp_crypt lib
    [x] make those vars global: const uint32_t key_size = 32; // 256 bit, const uint32_t nonce_size = 12; // 96 bit, const uint32_t tag_size =  auth_tag_lengths.dwMaxLength; // usually 16 byte, 128 bit,
    [x] ByteBuffer -> variable size
    [x] ByteArray -> fixed size
    [x] harmonize sha256 signature
    [x] use pair instead of tuple
    [x] uniform input/output parameters to functions
    [x] returning Salt from encrypt
    [x] return optional Error
    [x] fix all the warnings
    [x] fix const issue while calling win api
    [x] create distinct type for Ciphertext, Plaintext, Tag...
    [x] vs2022 format after saving
    [x] remove internal from base64 function?
    [x] internalBase64Decode need to return error
    [x] base64Encode(), base64Decode(), does not return error! fix that
    [x] create a file format for saving encrypted data
    [x] sha256::generate() does not return error! fix that
    [x] unify Result and Error struct for all functions?
    [x] harmonize return value of all functions
    [x] support utf-8 // we are dealing with bytes and not characters
    [] make ByteBuffer a struct?
        [] make toSv(), toBB(), toHexString() a memeber function?
    [] settings for AES256-GCM are hardcoded, make them configurable
    [] use c++ cast?
    [] get rid of namespace?
    [] fix TODO's in code
*/

namespace WinCppCrypt
{

using std::string_view;
using std::string;
using std::vector;

using byte = uint8_t;
using ByteBuffer = vector<byte>;

template <typename T>
struct Error
{
    string description;
    T code;

    string what() const
    {
        return std::format("{} ({:#x})", description, code);
    }
};

template<typename ResType, typename ErrType>
struct Result
{
    Result(const ResType& res,
           const Error<ErrType>& err) :
        res(res), err(err)
    {
    }

    bool isValid() const
    {
        return err.description.size() == 0;
    }

    bool hasError() const
    {
        return !isValid();
    }

    const ResType& unwrap() const
    {
        return res;
    }

    const Error<ErrType>& error() const
    {
        return err;
    }

private:
    ResType res;
    Error<ErrType> err;
};

class CompressionError : public std::runtime_error
{
public:
    CompressionError(const string& what, DWORD code)
        : std::runtime_error(what),
        code(code)
    {
    }

    DWORD code;
};

class DecompressionError : public std::runtime_error
{
public:
    DecompressionError(const string& what, DWORD code)
        : std::runtime_error(what),
        code(code)
    {
    }

    DWORD code;
};

namespace Util
{

string_view toSv(const ByteBuffer& input);

ByteBuffer toBB(string_view input);

string toHexString(const ByteBuffer& data);

ByteBuffer randomBytes(uint32_t count);

using Base64Result = Result<ByteBuffer, DWORD>;

Base64Result base64Encode(const BYTE* input, DWORD input_size);
Base64Result base64Encode(const ByteBuffer& input);
Base64Result base64Encode(const string& input);
Base64Result base64Encode(const string_view& input);
Base64Result base64Encode(const char* input);

Base64Result base64Decode(LPCSTR input, DWORD input_size);
Base64Result base64Decode(const ByteBuffer& input);
Base64Result base64Decode(const string& input);
Base64Result base64Decode(const string_view& input);
Base64Result base64Decode(const char* input);

ByteBuffer compress(LPCVOID data, SIZE_T data_size);
ByteBuffer decompress(LPCVOID data, SIZE_T data_size);

} // Util namespace

namespace SHA256
{

using SHA256Result = Result<ByteBuffer, NTSTATUS>;

SHA256Result generate(PUCHAR data, ULONG data_size);
SHA256Result generate(const ByteBuffer& input);
SHA256Result generate(const string& input);
SHA256Result generate(string_view input);
SHA256Result generate(const char* input);


} // SHA256 namespace

namespace AES256_GCM
{

using Ciphertext = ByteBuffer;
using Plaintext = ByteBuffer;
using Nonce = ByteBuffer;
using Tag = ByteBuffer;
using Salt = ByteBuffer;

struct Encryption
{
    ByteBuffer ciphertext;
    ByteBuffer nonce;
    ByteBuffer tag;
    ByteBuffer salt;
    ByteBuffer additional_data;
};

using EncryptionResult = Result<Encryption, NTSTATUS>;

EncryptionResult encrypt(
    PUCHAR plaintext, ULONG plaintext_size,
    PUCHAR password, ULONG password_size,
    PUCHAR additional_data, ULONG additional_data_size
);

EncryptionResult encrypt(
    const ByteBuffer& plaintext,
    string_view password,
    string_view additional_data
);

EncryptionResult encrypt(
    void* data, size_t data_size,
    string_view password,
    string_view additional_data
);

EncryptionResult encrypt(
    string_view plaintext,
    string_view password,
    string_view additional_data
);


struct Decryption
{
    ByteBuffer plaintext;

    template<typename T>
    const T as() const
    {
        return reinterpret_cast<T>(plaintext.data());
    }

};

using DecryptionResult = Result<Decryption, NTSTATUS>;

DecryptionResult decrypt(
    PUCHAR ciphertext, ULONG ciphertext_size,
    PUCHAR password, ULONG password_size,
    PUCHAR nonce, ULONG nonce_size,
    PUCHAR tag, ULONG tag_size,
    PUCHAR salt, ULONG salt_size,
    PUCHAR additional_data, ULONG additional_data_size
);

DecryptionResult decrypt(
    const ByteBuffer& ciphertext,
    string_view password,
    const ByteBuffer& nonce,
    const ByteBuffer& tag,
    const ByteBuffer& salt,
    const ByteBuffer& additional_data);

DecryptionResult decrypt(
    const Encryption& enc_res,
    string_view password);

bool writeToFile(const string& filename, const Encryption& data);

} // AES256_GCM namespace

} // WinCppCrypt namespace
