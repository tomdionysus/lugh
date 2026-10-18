#pragma once

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <functional>
#include <string>

// A fresh self-signed certificate and its key, as PEM, for a server under test. Made here
// rather than kept as a fixture: a certificate committed to the repository would expire.
struct TestCertificate {
  std::string certificate_pem;
  std::string key_pem;

  // Another key, matching no certificate here, for the tests about a pair that does not fit.
  std::string other_key_pem;

  TestCertificate() {
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    EVP_PKEY* other = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");

    X509* certificate = X509_new();
    X509_set_version(certificate, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
    X509_gmtime_adj(X509_getm_notBefore(certificate), -60);
    X509_gmtime_adj(X509_getm_notAfter(certificate), 3600);

    X509_NAME* name = X509_get_subject_name(certificate);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(certificate, name);
    X509_set_pubkey(certificate, key);
    X509_sign(certificate, key, EVP_sha256());

    certificate_pem = _pem([&](BIO* bio) { PEM_write_bio_X509(bio, certificate); });
    key_pem = _pem([&](BIO* bio) { PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr); });
    other_key_pem = _pem([&](BIO* bio) { PEM_write_bio_PrivateKey(bio, other, nullptr, nullptr, 0, nullptr, nullptr); });

    X509_free(certificate);
    EVP_PKEY_free(key);
    EVP_PKEY_free(other);
  }

 private:
  static std::string _pem(const std::function<void(BIO*)>& write) {
    BIO* bio = BIO_new(BIO_s_mem());
    write(bio);
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio, &data);
    std::string out(data, static_cast<std::size_t>(length));
    BIO_free(bio);
    return out;
  }
};
