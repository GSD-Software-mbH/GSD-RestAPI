import 'dart:convert';
import 'dart:math';

import 'package:encryption/encryptionmanager.dart';
import 'package:encryption/encryptionoptions.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:encrypt/encrypt.dart' as encrypt;

void main() {
  late EncryptionManager encryptionManager;
  late encrypt.Key aesKey;

  setUp(() {
    WidgetsFlutterBinding.ensureInitialized();
    encryptionManager = EncryptionManager();

    final secureRandom = Random.secure();
    final keyBytes = List<int>.generate(32, (_) => secureRandom.nextInt(256)); // 256-Bit-Schlüssel für AES
    final storedKey = base64UrlEncode(keyBytes);

    // Setze den abgerufenen oder neu generierten Schlüssel
    aesKey = encrypt.Key.fromBase64(storedKey);
  });

  group('AES Encryption and Decryption', () {
    test('Encrypt and decrypt AES should return original text', () async {
      const plainText = 'Hello AES Encryption';
      
      final encryptedText = await encryptionManager.encryptAES(plainText, key: aesKey);
      final decryptedText = await encryptionManager.decryptAES(encryptedText, key: aesKey);
      
      expect(decryptedText, equals(plainText));
    });
  });

  group('RSA Encryption and Decryption', () {
    test('Encrypt and decrypt RSA should return original text', () async {
      const plainText = 'Hello RSA Encryption';
      
      await encryptionManager.initializeRSAKeyPair();
      final encryptedText = await encryptionManager.encryptRSA(plainText);
      final decryptedText = await encryptionManager.decryptRSA(encryptedText);
      
      expect(decryptedText, equals(plainText));
    });
  });

  group('RSA Key Initialization', () {
    test('RSA key pair should be initialized', () async {
      await encryptionManager.initializeRSAKeyPair();
      expect(encryptionManager.keyRSA, isNotNull);
      expect(encryptionManager.keyRSA!.publicKey, isNotNull);
      expect(encryptionManager.keyRSA!.privateKey, isNotNull);
    });
  });

  group('RSA Key initialization from Filepaths', () {
    test('RSA key pair should be initialized from Filepaths', () async {
      EncryptionManager privateEncryptionManager = EncryptionManager.init(EncryptionOptions(rsaPrivateKeyFilePath: "cert\\encryption.pem", rsaPublicKeyFilePath: "cert\\encryption-pub.pem"));
      expect(privateEncryptionManager.keyRSA, isNotNull);
      expect(privateEncryptionManager.keyRSA!.publicKey, isNotNull);
      expect(privateEncryptionManager.keyRSA!.privateKey, isNotNull);
    });
  });
}
