#include "crypto.h"
#include <QCryptographicHash>

// AES-128-CBC backend per platform, all system libraries except on Linux:
//   Windows: BCrypt
//   macOS:   CommonCrypto (part of libSystem, nothing to link)
//   Linux:   OpenSSL libcrypto (EVP)
// macOS backend from ozgunawesome's Jupsi/OpenCubic#6.
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")
#elif defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>
#else
#include <openssl/evp.h>
#endif

namespace aceflash {

QString md5Hex(const QByteArray& data)
{
    return QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex());
}

QString ctrlSign(const QString& token, const QString& ts, const QString& nonce)
{
    return md5Hex((md5Hex(token.left(16).toLatin1()) + ts + nonce).toLatin1());
}

#if defined(__APPLE__)

QByteArray aes128CbcDecrypt(const QByteArray& cipher,
                            const QByteArray& key,
                            const QByteArray& iv)
{
    if (cipher.isEmpty() || cipher.size() % 16 != 0) return {};
    const QByteArray ivCopy  = iv.left(16).leftJustified(16, '\0');
    const QByteArray keyCopy = key.left(16).leftJustified(16, '\0');

    QByteArray plain(cipher.size() + 16, '\0');
    size_t plainLen = 0;
    const CCCryptorStatus status = CCCrypt(
        kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,   // PKCS#7, same as BCRYPT_BLOCK_PADDING
        keyCopy.constData(), kCCKeySizeAES128,
        ivCopy.constData(),
        cipher.constData(), static_cast<size_t>(cipher.size()),
        plain.data(), static_cast<size_t>(plain.size()), &plainLen);
    if (status != kCCSuccess) return {};
    plain.resize(static_cast<int>(plainLen));
    return plain;
}

#elif !defined(_WIN32)

QByteArray aes128CbcDecrypt(const QByteArray& cipher,
                            const QByteArray& key,
                            const QByteArray& iv)
{
    if (cipher.isEmpty() || cipher.size() % 16 != 0) return {};
    const QByteArray ivCopy  = iv.left(16).leftJustified(16, '\0');
    const QByteArray keyCopy = key.left(16).leftJustified(16, '\0');

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    QByteArray plain(cipher.size() + 16, '\0');
    int len1 = 0, len2 = 0;
    const bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(keyCopy.constData()),
                           reinterpret_cast<const unsigned char*>(ivCopy.constData())) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 1) == 1   // PKCS#7, same as BCRYPT_BLOCK_PADDING
        && EVP_DecryptUpdate(ctx,
                             reinterpret_cast<unsigned char*>(plain.data()), &len1,
                             reinterpret_cast<const unsigned char*>(cipher.constData()),
                             static_cast<int>(cipher.size())) == 1
        && EVP_DecryptFinal_ex(ctx,
                               reinterpret_cast<unsigned char*>(plain.data()) + len1,
                               &len2) == 1;
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    plain.resize(len1 + len2);
    return plain;
}

#else

QByteArray aes128CbcDecrypt(const QByteArray& cipher,
                            const QByteArray& key,
                            const QByteArray& iv)
{
    if (cipher.isEmpty() || cipher.size() % 16 != 0) return {};
    // We need a writable IV copy (BCrypt modifies it)
    QByteArray ivCopy = iv.left(16).leftJustified(16, '\0');
    QByteArray keyCopy = key.left(16).leftJustified(16, '\0');

    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_KEY_HANDLE  hKey  = nullptr;
    NTSTATUS           status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return {};

    // Set CBC chaining mode
    const wchar_t* cbcMode = BCRYPT_CHAIN_MODE_CBC;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)cbcMode,
                      (ULONG)((wcslen(cbcMode) + 1) * sizeof(wchar_t)), 0);

    // Import the key
    ULONG   keyObjLen = 0;
    ULONG   cbResult  = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      (PUCHAR)&keyObjLen, sizeof(ULONG), &cbResult, 0);

    QByteArray keyObj(keyObjLen, '\0');
    status = BCryptGenerateSymmetricKey(
        hAlg, &hKey,
        (PUCHAR)keyObj.data(), keyObjLen,
        (PUCHAR)keyCopy.data(), 16, 0);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    // Decrypt
    QByteArray plain(cipher.size(), '\0');
    ULONG plainLen = 0;
    status = BCryptDecrypt(
        hKey,
        (PUCHAR)cipher.constData(), (ULONG)cipher.size(),
        nullptr,
        (PUCHAR)ivCopy.data(), 16,
        (PUCHAR)plain.data(), (ULONG)plain.size(),
        &plainLen, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return {};
    plain.resize(plainLen);
    return plain;
}

#endif // platform backend

} // namespace aceflash
