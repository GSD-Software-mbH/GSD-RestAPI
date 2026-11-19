# Krypto-Testvektoren

`gsd_encryption_vectors.json` stammt aus `gsd_encryption` 0.1.28 mit `encrypter_plus` 5.1.0,
aufgezeichnet am 2026-10-26, bevor `gsd_restapi` beide Abhängigkeiten entfernte. Ein einmaliger
Test-Generator (nicht eingecheckt) hat die Werte mit `EncryptionManager` erzeugt:

| Schlüssel | Inhalt |
|---|---|
| `clientKeyPair`, `serverKeyPair` | zwei RSA-Schlüsselpaare (2048 Bit) aus `generateRandomRSAKey`, als Dezimalzahlen |
| `aes` | AES-256-CBC-PKCS7 mit festem Schlüssel (`00…1f`) und IV (`a0…af`); Klartext UTF-8 |
| `rsa` | 32 Bytes, mit `encryptRSA` (OAEP, SHA-256) an `clientKeyPair` verschlüsselt |
| `encryptedResponse` | eine Antwort in der Server-Form `<Base64 RSA(AES-Schlüssel)>\|<Base64 IV ‖ Ciphertext>` an `clientKeyPair` |
| `pem.clientPublicKeyEncoded` | `encodeToPem()` des öffentlichen Client-Schlüssels |
| `pem.serverPublicKeyClean` | der öffentliche Server-Schlüssel als sauberes PEM; `parsePublicKeyFromPem()` liest ihn |

Die Tests unter `test/src/crypto/` prüfen die interne Krypto (`lib/src/crypto/`) dagegen: Sie
entschlüsselt die alten Chiffrate und erzeugt AES und PEM byte-gleich. Die verschlüsselte
Antwort läuft in `test/src/runtime/response/response_decryptor_test.dart` durch den
`ResponseDecryptor`.

Die privaten Schlüssel sind reine Testschlüssel und schützen nichts; der Ordner steht deshalb
unter `false_secrets` in der `pubspec.yaml`.
