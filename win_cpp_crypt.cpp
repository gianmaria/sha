// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include "win_cpp_crypt.h"

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <ntstatus.h>

#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

#include <compressapi.h>
#pragma comment(lib, "Cabinet.lib")

#include <memory>
#include <fstream>
#include <format>
#include <functional>
#include <iostream>
#include <sstream>

namespace
{

using namespace WinCppCrypt;

class Defer
{
    std::function<void()> cleanup = nullptr;

public:

    Defer(std::function<void()> func)
        : cleanup(std::move(func))
    {
    }

    ~Defer()
    {
        if (cleanup) cleanup();
    }
};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
const char* ntstatusToStr(NTSTATUS status)
{
    switch (status)
    {
        case STATUS_SUCCESS:
            return "STATUS_SUCCESS";

        case STATUS_NOT_FOUND:
            return "STATUS_NOT_FOUND";

        case STATUS_INVALID_PARAMETER:
            return "STATUS_INVALID_PARAMETER";

        case STATUS_NO_MEMORY:
            return "STATUS_NO_MEMORY";

        case STATUS_BUFFER_TOO_SMALL:
            return "STATUS_BUFFER_TOO_SMALL";

        case STATUS_INVALID_HANDLE:
            return "STATUS_INVALID_HANDLE";

        case STATUS_NOT_SUPPORTED:
            return "STATUS_NOT_SUPPORTED";

        case STATUS_AUTH_TAG_MISMATCH:
            return "STATUS_AUTH_TAG_MISMATCH";

        case STATUS_INVALID_BUFFER_SIZE:
            return "STATUS_INVALID_BUFFER_SIZE";

        case STATUS_DATA_ERROR:
            return "STATUS_DATA_ERROR";

        default:
            return "NTSTATUS not yet encountered";
    }
}

string lastErrorToStr(DWORD error_code)
{
    DWORD flags =
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_MAX_WIDTH_MASK; // no new line at the end of the message
    DWORD lang_id = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    LPSTR message_buffer = nullptr;

    DWORD size = FormatMessageA(
        flags,                   // [in]           DWORD   dwFlags,
        NULL,                    // [in, optional] LPCVOID lpSource,
        error_code,              // [in]           DWORD   dwMessageId,
        lang_id,                 // [in]           DWORD   dwLanguageId,
        (LPSTR)&message_buffer,  // [out]          LPSTR   lpBuffer,
        0,                       // [in]           DWORD   nSize,
        NULL                     // [in, optional] va_list *Arguments
    );

    if (size == 0)
    {
        return "lastErrorToStr() has failed!";
    }

    auto message = string(message_buffer, size - 1); // size include \0

    LocalFree(message_buffer);

    return message;
}


} // Anonymous namespace

namespace WinCppCrypt
{

using std::unique_ptr;
using std::make_unique;
using std::format;

using namespace std::string_literals;
using namespace std::string_view_literals;

namespace Util
{

string_view toSv(const ByteBuffer& input)
{
    return {
        reinterpret_cast<const char*>(input.data()),
        input.size()
    };
}

ByteBuffer toBB(string_view input)
{
    ByteBuffer res;
    res.resize(input.size());

    auto pos_it = std::copy(input.begin(), input.end(), res.begin());

    if (pos_it != res.end()) return {};

    return res;
}

string toHexString(const ByteBuffer& data)
{
    auto ss = std::stringstream();

    //ss << "0x";
    for (auto b : data)
    {
        ss << std::hex << (uint32_t)b;
    }
    return ss.str();
}

ByteBuffer randomBytes(uint32_t count)
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,            // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_RNG_ALGORITHM,    // [in] LPCWSTR pszAlgId,
        nullptr,                 // [in] LPCWSTR pszImplementation,
        0                        // [in] ULONG dwFlags
    );

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });

    if (status != STATUS_SUCCESS)
    {
        return {};
    }

    auto random_data = vector<uint8_t>(count, 0);

    status = BCryptGenRandom(
        algo_handle,               // [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        random_data.data(),        // [in, out] PUCHAR            pbBuffer,
        (ULONG)random_data.size(), // [in]      ULONG             cbBuffer,
        0                          // [in]      ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return {};
    }

    return random_data;
}

Base64Result base64Encode(const BYTE* input, DWORD input_size)
{
    DWORD output_size = 0;
    DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;

    BOOL result = CryptBinaryToStringA(
        input,       // [in]            const BYTE *pbBinary,
        input_size,  // [in]            DWORD      cbBinary,
        flags,       // [in]            DWORD      dwFlags,
        nullptr,     // [out, optional] LPSTR      pszString,
        &output_size // [in, out]       DWORD      *pcchString
    );

    if (result == FALSE)
    {
        DWORD last_err = GetLastError();

        return Base64Result(
            {},
            Error<DWORD>{.description = lastErrorToStr(last_err), .code = last_err}
        );
    }

    // NOTE: output_size include the terminating null character
    auto output = ByteBuffer(output_size, 0xba);

    // NOTE:
    // the function converts the binary data
    // into a specified string format
    // __including the terminating null character__
    result = CryptBinaryToStringA(
        input,                // [in]            const BYTE *pbBinary,
        input_size,           // [in]            DWORD      cbBinary,
        flags,                // [in]            DWORD      dwFlags,
        (LPSTR)output.data(), // [out, optional] LPSTR      pszString,
        &output_size          // [in, out]       DWORD      *pcchString
    );

    if (result == FALSE)
    {
        DWORD last_err = GetLastError();
        return Base64Result(
            {},
            Error<DWORD>{.description = lastErrorToStr(last_err), .code = last_err}
        );
    }

    output.pop_back(); // remove terminating null character

    return Base64Result(
        std::move(output),
        {}
    );
}
Base64Result base64Encode(const ByteBuffer& input)
{
    return base64Encode(
        reinterpret_cast<const BYTE*>(input.data()),
        static_cast<DWORD>(input.size())
    );
}
Base64Result base64Encode(const string& input)
{
    return base64Encode(
        reinterpret_cast<const BYTE*>(input.data()),
        static_cast<DWORD>(input.size())
    );
}
Base64Result base64Encode(const string_view& input)
{
    return base64Encode(
        reinterpret_cast<const BYTE*>(input.data()),
        static_cast<DWORD>(input.size())
    );
}
Base64Result base64Encode(const char* input)
{
    return base64Encode(
        reinterpret_cast<const BYTE*>(input),
        static_cast<DWORD>(std::strlen(input))
    );
}

Base64Result base64Decode(LPCSTR input, DWORD input_size)
{
    DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT;

    DWORD output_size = 0;

    BOOL result = CryptStringToBinaryA(
        input, // [in]      LPCSTR pszString,
        input_size,    // [in]      DWORD  cchString,
        flags,         // [in]      DWORD  dwFlags,
        nullptr,       // [in]      BYTE   *pbBinary,
        &output_size,  // [in, out] DWORD  *pcbBinary,
        nullptr,       // [out]     DWORD  *pdwSkip,
        nullptr        // [out]     DWORD  *pdwFlags
    );

    if (result == FALSE)
    {
        DWORD last_err = GetLastError();
        return Base64Result(
            {},
            Error<DWORD>{.description = lastErrorToStr(last_err), .code = last_err}
        );
    }

    auto output = ByteBuffer(output_size, 0xba);

    DWORD used_flags = 0;

    result = CryptStringToBinaryA(
        input,        // [in]      LPCSTR pszString,
        input_size,           // [in]      DWORD  cchString,
        flags,                // [in]      DWORD  dwFlags,
        (BYTE*)output.data(), // [in]      BYTE   *pbBinary,
        &output_size,         // [in, out] DWORD  *pcbBinary,
        nullptr,              // [out]     DWORD  *pdwSkip,
        &used_flags           // [out]     DWORD  *pdwFlags
    );

    if (result == FALSE)
    {
        DWORD last_err = GetLastError();
        return Base64Result(
            {},
            Error<DWORD>{.description = lastErrorToStr(last_err), .code = last_err}
        );
    }

    return Base64Result(
        std::move(output),
        {}
    );
}
Base64Result base64Decode(const ByteBuffer& input)
{
    return base64Decode(
        reinterpret_cast<LPCSTR>(input.data()),
        static_cast<DWORD>(input.size())
    );
}
Base64Result base64Decode(const string& input)
{
    return base64Decode(
        reinterpret_cast<const LPCSTR>(input.data()),
        static_cast<DWORD>(input.size())
    );
}
Base64Result base64Decode(const string_view& input)
{
    return base64Decode(
        reinterpret_cast<const LPCSTR>(input.data()),
        static_cast<DWORD>(input.size())
    );
}
Base64Result base64Decode(const char* input)
{
    return base64Decode(
        reinterpret_cast<const LPCSTR>(input),
        static_cast<DWORD>(std::strlen(input))
    );
}


ByteBuffer compress(LPCVOID data, SIZE_T data_size)
{
    DWORD error_code = 0;
    COMPRESSOR_HANDLE handle = nullptr;
    BOOL res = FALSE;

    res = CreateCompressor(
        COMPRESS_ALGORITHM_LZMS, //     [in]           DWORD                         Algorithm,
        nullptr,                 //     [in, optional] PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
        &handle                  //     [out]          PCOMPRESSOR_HANDLE            CompressorHandle
    );

    if (res == FALSE)
    {
        error_code = GetLastError();
        throw CompressionError{
            format("CreateCompressor failed ({}): {}", error_code, lastErrorToStr(error_code)),
            error_code
        };
    }

    auto close_compressor = Defer([handle]()
    {
        CloseCompressor(handle);
    });

    SIZE_T size_needed = 0;

    res = Compress(
        handle,              // [in]  COMPRESSOR_HANDLE CompressorHandle,
        data, // [in]  LPCVOID           UncompressedData,
        data_size, // [in]  SIZE_T            UncompressedDataSize,
        nullptr,             // [out] PVOID             CompressedBuffer,
        0,                   // [in]  SIZE_T            CompressedBufferSize,
        &size_needed         // [out] PSIZE_T           CompressedDataSize
    );

    // we expect to get ERROR_INSUFFICIENT_BUFFER here
    error_code = GetLastError();
    if (res == FALSE and
        error_code != ERROR_INSUFFICIENT_BUFFER)
    {
        throw CompressionError{
            format("Compress failed ({}): {}", error_code, lastErrorToStr(error_code)),
            error_code
        };
    }

    auto compressed_data = ByteBuffer(size_needed);

    SIZE_T actual_compressed_size = 0;
    res = Compress(
        handle,                      // [in]  COMPRESSOR_HANDLE CompressorHandle,
        data,         // [in]  LPCVOID           UncompressedData,
        data_size,         // [in]  SIZE_T            UncompressedDataSize,
        compressed_data.data(),      // [out] PVOID             CompressedBuffer,
        compressed_data.size(),      // [in]  SIZE_T            CompressedBufferSize,
        &actual_compressed_size // [out] PSIZE_T           CompressedDataSize
    );

    if (res == FALSE)
    {
        error_code = GetLastError();
        throw CompressionError{
            format("Compress failed ({}): {}", error_code, lastErrorToStr(error_code)),
            error_code
        };
    }

    compressed_data.resize(actual_compressed_size);

    return compressed_data;
}

ByteBuffer decompress(LPCVOID data, SIZE_T data_size)
{
    DWORD error_code = 0;
    DECOMPRESSOR_HANDLE handle = nullptr;
    BOOL res = FALSE;

    res = CreateDecompressor(
        COMPRESS_ALGORITHM_LZMS, //     [in]  DWORD                        Algorithm,
        nullptr, //     [in]  PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
        &handle //     [out] PDECOMPRESSOR_HANDLE          DecompressorHandle
    );

    if (res == FALSE)
    {
        error_code = GetLastError();
        throw DecompressionError{
            format("CreateDecompressor failed ({}): {}", error_code, lastErrorToStr(error_code)),
            error_code
        };
    }

    auto close_decompressor = Defer([handle]()
    {
        CloseDecompressor(handle);
    });

    SIZE_T uncompressed_data_size = 0;

    res = Decompress(
        handle,                 // [in]  DECOMPRESSOR_HANDLE DecompressorHandle,
        data,    // [in]  LPCVOID            CompressedData,
        data_size,    // [in]  SIZE_T             CompressedDataSize,
        nullptr,                // [out] PVOID              UncompressedBuffer,
        0,                      // [in]  SIZE_T             UncompressedBufferSize,
        &uncompressed_data_size // [out] PSIZE_T            UncompressedDataSize
    );

    // we expect to get ERROR_INSUFFICIENT_BUFFER here
    error_code = GetLastError();
    if (res == FALSE and
        error_code != ERROR_INSUFFICIENT_BUFFER)
    {
        throw DecompressionError{
            format("Decompress failed ({}): {}", error_code, lastErrorToStr(error_code)),
            error_code
        };
    }

    auto uncompressed_data = ByteBuffer(uncompressed_data_size);

    res = Decompress(
        handle,                   // [in]  DECOMPRESSOR_HANDLE DecompressorHandle,
        data,      // [in]  LPCVOID            CompressedData,
        data_size,      // [in]  SIZE_T             CompressedDataSize,
        uncompressed_data.data(), // [out] PVOID              UncompressedBuffer,
        uncompressed_data.size(), // [in]  SIZE_T             UncompressedBufferSize,
        &uncompressed_data_size   // [out] PSIZE_T            UncompressedDataSize
    );

    if (res == FALSE)
    {
        error_code = GetLastError();
        throw DecompressionError{
            format("Decompress failed ({}): {}", error_code, lastErrorToStr(error_code)),
            error_code
        };
    }

    uncompressed_data.resize(uncompressed_data_size);

    return uncompressed_data;
}

} // Util namespace

namespace SHA256
{

SHA256Result generate(PUCHAR data, ULONG data_size)
{
    NTSTATUS status = 0;

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,            // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_SHA256_ALGORITHM, // [in]  LPCWSTR           pszAlgId,
        nullptr,                 // [in]  LPCWSTR           pszImplementation,
        0                        // [in]  ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return SHA256Result(
            {},
            { .description = ntstatusToStr(status), .code = status }
        );
    }

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });

    ULONG pcbResult = 0; // TODO: not really used at the moment

    // Query the size of the hash
    DWORD hash_size = 0;
    status = BCryptGetProperty(
        algo_handle,         //   [in]  BCRYPT_HANDLE hObject,
        BCRYPT_HASH_LENGTH,  //   [in]  LPCWSTR       pszProperty,
        (PUCHAR)&hash_size,  //   [out] PUCHAR        pbOutput,
        sizeof(hash_size),   //   [in]  ULONG         cbOutput,
        &pcbResult,          //   [out] ULONG         *pcbResult,
        0                    //   [in]  ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return SHA256Result(
            {},
            { .description = ntstatusToStr(status), .code = status }
        );
    }

    auto hash = ByteBuffer(hash_size, 0xba);

    // Query the size of the "Object"
    DWORD object_size = 0;

    status = BCryptGetProperty(
        algo_handle,          // [in]  BCRYPT_HANDLE hObject,
        BCRYPT_OBJECT_LENGTH, // [in]  LPCWSTR       pszProperty,
        (PUCHAR)&object_size, // [out] PUCHAR        pbOutput,
        sizeof(object_size),  // [in]  ULONG         cbOutput,
        &pcbResult,           // [out] ULONG         *pcbResult,
        0                     // [in]  ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return SHA256Result(
            {},
            { .description = ntstatusToStr(status), .code = status }
        );
    }

    auto bcrypt_object = std::make_unique<UCHAR[]>(object_size);

    BCRYPT_HASH_HANDLE hash_handle = nullptr;

    // Create hash
    status = BCryptCreateHash(
        algo_handle,         // [in, out]      BCRYPT_ALG_HANDLE  hAlgorithm,
        &hash_handle,        // [out]          BCRYPT_HASH_HANDLE *phHash,
        bcrypt_object.get(), // [out]          PUCHAR             pbHashObject,
        object_size,         // [in, optional] ULONG              cbHashObject,
        nullptr,             // [in, optional] PUCHAR             pbSecret,
        0,                   // [in]           ULONG              cbSecret,
        0                    // [in]           ULONG              dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return SHA256Result(
            {},
            { .description = ntstatusToStr(status), .code = status }
        );
    }

    auto destroy_hash = Defer([&]()
    {
        BCryptDestroyHash(hash_handle);
    });

    // hashing...
    status = BCryptHashData(
        hash_handle, // [in, out] BCRYPT_HASH_HANDLE hHash,
        data,        // [in] PUCHAR pbInput,
        data_size,   // [in] ULONG cbInput,
        0            // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return SHA256Result(
            {},
            { .description = ntstatusToStr(status), .code = status }
        );
    }

    // Finish hashing
    status = BCryptFinishHash(
        hash_handle,         // [in, out] BCRYPT_HASH_HANDLE hHash,
        (PUCHAR)hash.data(), // [out] PUCHAR pbOutput,
        (ULONG)hash.size(),  // [in] ULONG cbOutput,
        0                    // [in] ULONG dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return SHA256Result(
            {},
            { .description = ntstatusToStr(status), .code = status }
        );
    }

    return SHA256Result(hash, {});
}
SHA256Result generate(const ByteBuffer& input)
{
    auto raw_input = const_cast<byte*>(input.data());

    return generate(
        reinterpret_cast<PUCHAR>(raw_input),
        static_cast<ULONG>(input.size())
    );
}
SHA256Result generate(const char* input)
{
    auto raw_input = const_cast<char*>(input);

    return generate(
        reinterpret_cast<PUCHAR>(raw_input),
        static_cast<ULONG>(std::strlen(input))
    );
}
SHA256Result generate(const string& input)
{
    auto raw_input = const_cast<char*>(input.data());

    return generate(
        reinterpret_cast<PUCHAR>(raw_input),
        static_cast<ULONG>(input.size())
    );
}
SHA256Result generate(string_view input)
{
    auto raw_input = const_cast<char*>(input.data());

    return generate(
        reinterpret_cast<PUCHAR>(raw_input),
        static_cast<ULONG>(input.size())
    );
}


} // SHA256 namespace

namespace AES256_GCM
{

static auto derive_key_with_PBKDF2(
    PUCHAR password,
    ULONG password_size,
    PUCHAR salt,
    ULONG salt_size,
    PUCHAR derived_key, // output
    ULONG derived_key_size,
    ULONGLONG iterations
) -> NTSTATUS
{
    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    NTSTATUS status;

    // Open an algorithm provider for PBKDF2
    // solution found here:
    // https://dev.to/antidisestablishmentarianism/a-bcryptderivekeypbkdf2-example-in-c-4ihh
    status = BCryptOpenAlgorithmProvider(
        &algo_handle,               // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_SHA256_ALGORITHM,    // [in]  LPCWSTR           pszAlgId,
        nullptr,                    // [in]  LPCWSTR           pszImplementation,
        BCRYPT_ALG_HANDLE_HMAC_FLAG // [in]  ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });

    // Derive the key
    status = BCryptDeriveKeyPBKDF2(
        algo_handle,      // [in]           BCRYPT_ALG_HANDLE hPrf,
        password,         // [in, optional] PUCHAR            pbPassword,
        password_size,    // [in]           ULONG             cbPassword,
        salt,             // [in, optional] PUCHAR            pbSalt,
        salt_size,        // [in]           ULONG             cbSalt,
        iterations,       // [in]           ULONGLONG         cIterations,
        derived_key,      // [out]          PUCHAR            pbDerivedKey,
        derived_key_size, // [in]           ULONG             cbDerivedKey,
        0                 // [in]           ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    return STATUS_SUCCESS;
}

static auto common_aes256_gcm(
    PUCHAR key,
    ULONG key_len,
    PUCHAR additional_data,
    ULONG additional_data_len,
    PUCHAR nonce,
    ULONG nonce_len,
    PUCHAR tag,
    ULONG tag_len,
    BCRYPT_ALG_HANDLE* algo_handle, // output
    BCRYPT_KEY_HANDLE* key_handle, // output
    PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info // output
) -> NTSTATUS
{
    NTSTATUS status = 0;

    status = BCryptOpenAlgorithmProvider(
        algo_handle,          // [out] BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_AES_ALGORITHM, // [in]  LPCWSTR           pszAlgId,
        nullptr,              // [in]  LPCWSTR           pszImplementation,
        0                     // [in]  ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    status = BCryptSetProperty(
        *algo_handle,                  // [in, out] BCRYPT_HANDLE hObject,
        BCRYPT_CHAINING_MODE,          // [in]      LPCWSTR       pszProperty,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, // [in]      PUCHAR        pbInput,
        sizeof(BCRYPT_CHAIN_MODE_GCM), // [in]      ULONG         cbInput,
        0                              // [in]      ULONG         dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    BCRYPT_KEY_DATA_BLOB_HEADER key_blob_header = {
        BCRYPT_KEY_DATA_BLOB_MAGIC,
        BCRYPT_KEY_DATA_BLOB_VERSION1,
        key_len
    };

    auto key_blob_header_begin = reinterpret_cast<const char*>(&key_blob_header);
    auto key_blob_header_end = key_blob_header_begin + sizeof(key_blob_header);

    auto key_blob = ByteBuffer();
    key_blob.insert(key_blob.begin(),
                    key_blob_header_begin, key_blob_header_end);
    key_blob.insert(key_blob.begin() + sizeof(key_blob_header),
                    key, key + key_len);

    status = BCryptImportKey(
        *algo_handle,           // [in]            BCRYPT_ALG_HANDLE hAlgorithm,
        nullptr,                // [in, optional]  BCRYPT_KEY_HANDLE hImportKey,
        BCRYPT_KEY_DATA_BLOB,   // [in]            LPCWSTR           pszBlobType,
        key_handle,             // [out]           BCRYPT_KEY_HANDLE *phKey,
        nullptr,                // [out, optional] PUCHAR            pbKeyObject,
        0,                      // [in]            ULONG             cbKeyObject,
        key_blob.data(),        // [in]            PUCHAR            pbInput,
        (ULONG)key_blob.size(), // [in]            ULONG             cbInput,
        0                       // [in]            ULONG             dwFlags
    );

    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(*auth_info);

    auth_info->pbNonce = nonce;
    auth_info->cbNonce = nonce_len;
    auth_info->pbAuthData = additional_data;
    auth_info->cbAuthData = additional_data_len;
    auth_info->pbTag = tag;
    auth_info->cbTag = tag_len;

    return STATUS_SUCCESS;
}

EncryptionResult encrypt(
    PUCHAR plaintext, ULONG plaintext_size,
    PUCHAR password, ULONG password_size,
    PUCHAR additional_data, ULONG additional_data_size)
{
    // Settings for AES256-GCM
    const ULONG key_size = 32;   // 256 bit
    const uint32_t nonce_size = 12; // 96 bit
    const uint32_t salt_size = 12; // 96 bit
    const uint32_t tag_size = 16;   // 128 bit
    const ULONGLONG iterations = 600000;

    const auto salt = Util::randomBytes(salt_size);
    auto derived_key = ByteBuffer(key_size);

    // derive key with PBKDF2
    {
        auto PBKDF2_status = derive_key_with_PBKDF2(
            password,
            password_size,
            (PUCHAR)salt.data(),
            (ULONG)salt.size(),
            (PUCHAR)derived_key.data(), // output
            (ULONG)derived_key.size(),
            iterations
        );

        if (PBKDF2_status != STATUS_SUCCESS)
        {
            return EncryptionResult(
                {},
                { .description = ntstatusToStr(PBKDF2_status), .code = PBKDF2_status }
            );
        }
    }

    auto ciphertext = ByteBuffer(plaintext_size, 0);
    auto tag = ByteBuffer(tag_size, 0);
    const auto nonce = Util::randomBytes(nonce_size);

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info{};

    // common part of AES256-GCM
    {
        NTSTATUS common_status = common_aes256_gcm(
            (PUCHAR)derived_key.data(),
            (ULONG)derived_key.size(),
            additional_data,
            additional_data_size,
            (PUCHAR)nonce.data(),
            (ULONG)nonce.size(),
            tag.data(), // output
            tag_size,
            &algo_handle, // output
            &key_handle, // output
            &auth_info // output
        );

        if (common_status != STATUS_SUCCESS)
        {
            return EncryptionResult(
                {},
                { .description = ntstatusToStr(common_status), .code = common_status }
            );
        }
    }

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });
    auto destroy_key = Defer([&]()
    {
        BCryptDestroyKey(key_handle);
    });

    ULONG bytes_copied = 0;

    // perform actual encryption
    {
        NTSTATUS encrypt_status = BCryptEncrypt(
            key_handle,                // [in, out]           BCRYPT_KEY_HANDLE hKey,
            plaintext,                 // [in]                PUCHAR            pbInput,
            plaintext_size,            // [in]                ULONG             cbInput,
            &auth_info,                // [in, optional]      VOID              *pPaddingInfo,
            nullptr,                   // [in, out, optional] PUCHAR            pbIV,
            0,                         // [in]                ULONG             cbIV,
            (PUCHAR)ciphertext.data(), // [out, optional]     PUCHAR            pbOutput,
            (ULONG)ciphertext.size(),  // [in]                ULONG             cbOutput,
            &bytes_copied,             // [out]               ULONG             *pcbResult,
            0                          // [in]                ULONG             dwFlags
        );

        if (encrypt_status != STATUS_SUCCESS or
            bytes_copied != plaintext_size)
        {
            return EncryptionResult(
                {},
                { .description = ntstatusToStr(encrypt_status), .code = encrypt_status }
            );
        }
    }

    return EncryptionResult(
        {
            .ciphertext = ciphertext,
            .nonce = nonce,
            .tag = tag,
            .salt = salt,
            .additional_data = ByteBuffer(additional_data, additional_data + additional_data_size)
        },
        {}
    );
}

EncryptionResult encrypt(
    const ByteBuffer& plaintext,
    string_view password,
    string_view additional_data
)
{
    return encrypt(
        (PUCHAR)plaintext.data(),
        (ULONG)plaintext.size(),
        (PUCHAR)password.data(),
        (ULONG)password.size(),
        (PUCHAR)additional_data.data(),
        (ULONG)additional_data.size()
    );
}

EncryptionResult encrypt(
    void* data, size_t data_size,
    string_view password,
    string_view additional_data
)
{
    return encrypt(
        (PUCHAR)data,
        (ULONG)data_size,
        (PUCHAR)password.data(),
        (ULONG)password.size(),
        (PUCHAR)additional_data.data(),
        (ULONG)additional_data.size()
    );
}

EncryptionResult encrypt(
    string_view plaintext,
    string_view password,
    string_view additional_data
)
{
    return encrypt(
        (PUCHAR)plaintext.data(),
        (ULONG)plaintext.size(),
        (PUCHAR)password.data(),
        (ULONG)password.size(),
        (PUCHAR)additional_data.data(),
        (ULONG)additional_data.size()
    );
}


DecryptionResult decrypt(
    PUCHAR ciphertext, ULONG ciphertext_size,
    PUCHAR password, ULONG password_size,
    PUCHAR nonce, ULONG nonce_size,
    PUCHAR tag, ULONG tag_size,
    PUCHAR salt, ULONG salt_size,
    PUCHAR additional_data, ULONG additional_data_size
)
{
    // Settings for AES256-GCM
    const ULONG key_size = 32;   // 256 bit
    const ULONGLONG iterations = 600000;

    auto derived_key = ByteBuffer(key_size);

    // derive key with PBKDF2
    {
        auto PBKDF2_status = derive_key_with_PBKDF2(
            password,
            password_size,
            salt,
            salt_size,
            (PUCHAR)derived_key.data(),
            (ULONG)derived_key.size(),
            iterations
        );

        if (PBKDF2_status != STATUS_SUCCESS)
        {
            return DecryptionResult(
                {},
                { .description = ntstatusToStr(PBKDF2_status), .code = PBKDF2_status }
            );
        }
    }

    auto plaintext = ByteBuffer(ciphertext_size, 0);

    BCRYPT_ALG_HANDLE algo_handle = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info{};

    // common part of AES256-GCM
    {
        NTSTATUS common_status = common_aes256_gcm(
            (PUCHAR)derived_key.data(),
            (ULONG)derived_key.size(),
            additional_data,
            additional_data_size,
            nonce,
            nonce_size,
            tag,
            tag_size,
            &algo_handle, // output
            &key_handle, // output
            &auth_info // output
        );

        if (common_status != STATUS_SUCCESS)
        {
            return DecryptionResult(
                {},
                { .description = ntstatusToStr(common_status), .code = common_status }
            );
        }
    }

    auto close_algo = Defer([&]()
    {
        BCryptCloseAlgorithmProvider(algo_handle, 0);
    });
    auto destroy_key = Defer([&]()
    {
        BCryptDestroyKey(key_handle);
    });

    ULONG bytes_copied = 0;

    // peform actual decryption
    {
        NTSTATUS decrypt_status = BCryptDecrypt(
            key_handle,               // [in, out]           BCRYPT_KEY_HANDLE hKey,
            ciphertext,               // [in]                PUCHAR            pbInput,
            ciphertext_size,          // [in]                ULONG             cbInput,
            &auth_info,               // [in, optional]      VOID              *pPaddingInfo,
            nullptr,                  // [in, out, optional] PUCHAR            pbIV,
            0,                        // [in]                ULONG             cbIV,
            (PUCHAR)plaintext.data(), // [out, optional]     PUCHAR            pbOutput,
            (ULONG)plaintext.size(),  // [in]                ULONG             cbOutput,
            &bytes_copied,            // [out]               ULONG             *pcbResult,
            0                         // [in]                ULONG             dwFlags
        );

        if (decrypt_status != STATUS_SUCCESS or
            bytes_copied != plaintext.size())
        {
            return DecryptionResult(
                {},
                { .description = ntstatusToStr(decrypt_status), .code = decrypt_status }
            );
        }
    }

    return DecryptionResult(
        { .plaintext = plaintext },
        {}
    );
}

DecryptionResult decrypt(
    const ByteBuffer& ciphertext,
    string_view password,
    const ByteBuffer& nonce,
    const ByteBuffer& tag,
    const ByteBuffer& salt,
    const ByteBuffer& additional_data
)
{
    return decrypt(
        (PUCHAR)ciphertext.data(),
        (ULONG)ciphertext.size(),
        (PUCHAR)password.data(),
        (ULONG)password.size(),
        (PUCHAR)nonce.data(),
        (ULONG)nonce.size(),
        (PUCHAR)tag.data(),
        (ULONG)tag.size(),
        (PUCHAR)salt.data(),
        (ULONG)salt.size(),
        (PUCHAR)additional_data.data(),
        (ULONG)additional_data.size()
    );
}

DecryptionResult decrypt(
    const Encryption& enc_res,
    string_view password
)
{
    return decrypt(
        (PUCHAR)enc_res.ciphertext.data(),
        (ULONG)enc_res.ciphertext.size(),
        (PUCHAR)password.data(),
        (ULONG)password.size(),
        (PUCHAR)enc_res.nonce.data(),
        (ULONG)enc_res.nonce.size(),
        (PUCHAR)enc_res.tag.data(),
        (ULONG)enc_res.tag.size(),
        (PUCHAR)enc_res.salt.data(),
        (ULONG)enc_res.salt.size(),
        (PUCHAR)enc_res.additional_data.data(),
        (ULONG)enc_res.additional_data.size()
    );
}


bool writeToFile(const string& filename, const Encryption& data)
{
    using namespace WinCppCrypt::Util;

    auto ofs = std::ofstream(filename, std::ios::binary);

    if (not ofs.is_open())
    {
        return false;
    }

    // cout << "[encrypt] ciphertext: " << toHexString(enc.ciphertext) << endl;
    // cout << "[encrypt] nonce     : " << toHexString(enc.nonce) << endl;
    // cout << "[encrypt] salt      : " << toHexString(enc.salt) << endl;
    // cout << "[encrypt] tag       : " << toHexString(enc.tag) << endl;

    ofs << toSv(base64Encode(data.ciphertext).unwrap()) << "\n"
        << toSv(base64Encode(data.nonce).unwrap()) << "\n"
        << toSv(base64Encode(data.salt).unwrap()) << "\n"
        << toSv(base64Encode(data.tag).unwrap()) << "\n"
        << toSv(base64Encode(data.additional_data).unwrap()) << "\n";

    if (not ofs.good()) return false;

    ofs.flush(), ofs.close();

    return true;
}

} // AES256_GCM namespace

} // WinCppCrypt namespace
