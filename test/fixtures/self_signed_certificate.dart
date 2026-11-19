// Selbstsigniertes Test-Zertifikat für lokale HTTPS-Test-Server.
//
// NUR FÜR TESTS: Schlüssel und Zertifikat sind öffentlich und schützen
// nichts. Ausgestellt für CN=localhost, SAN IP:127.0.0.1 und DNS:localhost,
// EC P-256, gültig bis 2126. Erzeugt mit:
//
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
//     -nodes -days 36500 -subj "/CN=localhost" \
//     -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
//     -keyout key.pem -out cert.pem
//
// Da keine vertrauenswürdige CA das Zertifikat ausgestellt hat, lehnt ein
// Standard-HttpClient es mit `CERTIFICATE_VERIFY_FAILED` ab - genau wie das
// interne Zertifikat eines Kundenservers, dem das Gerät nicht vertraut.

import 'dart:convert';
import 'dart:io';

const String selfSignedCertificatePem = '''
-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIUFQVf8tR0v6QXiArxN7QjQv1VzwcwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAyMDEwNTEzOFoYDzIxMjYwOTI2
MTA1MTM4WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATi2EBeJtcBBvicqgENP/W/eG9bUcTf/LueAgQohdCwKB4aOpRXjwkD
a3p64KorZMHG7ariRzmNP30TIjeCY8/Zo28wbTAdBgNVHQ4EFgQUpu+Y3jU3GpV5
LwbZbaVHe0eZ+scwHwYDVR0jBBgwFoAUpu+Y3jU3GpV5LwbZbaVHe0eZ+scwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2NhbGhvc3QwCgYIKoZI
zj0EAwIDRwAwRAIgZcUaUIinoEbfIpQvd5s7OctN1Mxd2ZMQUSB2ssPSSk8CIAWh
dXv8BKCYcyzrjnQTgHIjttFIPcAALyeOfL9tsKWq
-----END CERTIFICATE-----
''';

const String selfSignedPrivateKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAn+0cS6SlUnMBjfQ
LHjR9gnra0wFYtOF72U8HguV8GOhRANCAATi2EBeJtcBBvicqgENP/W/eG9bUcTf
/LueAgQohdCwKB4aOpRXjwkDa3p64KorZMHG7ariRzmNP30TIjeCY8/Z
-----END PRIVATE KEY-----
''';

/// Server-seitiger [SecurityContext] mit dem selbstsignierten Zertifikat.
SecurityContext selfSignedServerContext() {
  return SecurityContext()
    ..useCertificateChainBytes(utf8.encode(selfSignedCertificatePem))
    ..usePrivateKeyBytes(utf8.encode(selfSignedPrivateKeyPem));
}
