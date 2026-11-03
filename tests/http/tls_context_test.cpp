//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "http/tls_context.h"

#include <gtest/gtest.h>

#include "helpers/temp_directory.h"
#include "helpers/test_certificate.h"

using lugh::http::TlsContext;

TEST(TlsContext, LoadsAMatchingPair) {
  TempDirectory dir;
  TestCertificate pair;
  const auto certificate = dir.write("cert.pem", pair.certificate_pem).string();
  const auto key = dir.write("key.pem", pair.key_pem).string();

  const auto result = TlsContext::server(certificate, key);
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_TRUE(result.value);
}

TEST(TlsContext, BothPathsAreRequired) {
  const auto result = TlsContext::server("", "/k.pem");
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("no plaintext"), std::string::npos);
  EXPECT_FALSE(TlsContext::server("/c.pem", "").ok);
}

TEST(TlsContext, AMissingFileIsNamed) {
  TempDirectory dir;
  TestCertificate pair;
  const auto certificate = dir.write("cert.pem", pair.certificate_pem).string();

  const auto result = TlsContext::server(certificate, (dir.path() / "nowhere.pem").string());
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("nowhere.pem"), std::string::npos);

  const auto no_cert = TlsContext::server((dir.path() / "missing.pem").string(), certificate);
  EXPECT_FALSE(no_cert.ok);
  EXPECT_NE(no_cert.error.find("missing.pem"), std::string::npos);
}

TEST(TlsContext, AKeyThatDoesNotMatchTheCertificateIsRefusedAtStart) {
  TempDirectory dir;
  TestCertificate pair;
  const auto certificate = dir.write("cert.pem", pair.certificate_pem).string();
  const auto wrong_key = dir.write("other.pem", pair.other_key_pem).string();

  const auto result = TlsContext::server(certificate, wrong_key);
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("other.pem"), std::string::npos) << result.error;
  EXPECT_NE(result.error.find("cert.pem"), std::string::npos) << result.error;
}

TEST(TlsContext, SomethingThatIsNotAPemIsRefused) {
  TempDirectory dir;
  const auto junk = dir.write("junk.pem", "not a certificate\n").string();
  EXPECT_FALSE(TlsContext::server(junk, junk).ok);
}
