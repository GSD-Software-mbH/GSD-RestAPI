library encryption;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';

/// The `EncryptionManager` class handles AES and RSA encryption/decryption.
class EncryptionManager {
  static const String _aesKeyStorageKey = 'encryption_key';
  static EncryptionManager? _instance;

  /// Getter for RSA key pair
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? get keyRSA {
    return _keyRSA;
  }

  /// Getter for AES key
  Key? get keyAES {
    return _keyAES;
  }

  late FlutterSecureStorage _secureStorage;
  Key? _keyAES;
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? _keyRSA;

  /// Factory constructor to return singleton instance
  factory EncryptionManager() {
    _instance ??= EncryptionManager._init();
    return _instance!;
  }

  /// Private constructor to initialize secure storage
  EncryptionManager._init() {
    _secureStorage = const FlutterSecureStorage();
  }

  /// Encrypts a given plain text using AES encryption.
  /// If a key is not provided, the stored AES key is used.
  Future<String> encryptAES(String plainText, {Key? key}) async {
    // Initialize AES key if not provided
    if (key == null) await initializeAESKey();

    // Check if the AES key is available
    if (_keyAES == null && key == null) {
      throw Exception('Key is null');
    }

    key ??= _keyAES;

    final iv = _generateRandomIV(); // Generate a random IV
    final encrypter = Encrypter(AES(key!, mode: AESMode.cbc)); // Use AES CBC mode
    final encrypted = encrypter.encrypt(plainText, iv: iv);

    // Combine IV with encrypted data
    final result = {
      'iv': iv.base64,
      'data': encrypted.base64,
    };
    return jsonEncode(result);
  }

  /// Decrypts AES-encrypted text.
  /// If a key is not provided, the stored AES key is used.
  Future<String> decryptAES(String encryptedText, {Key? key}) async {
    // Initialize AES key if not provided
    if (key == null) await initializeAESKey();

    // Check if the AES key is available
    if (_keyAES == null && key == null) {
      throw Exception('Key is null');
    }

    key ??= _keyAES;

    try {
      final Map<String, dynamic> decoded = jsonDecode(encryptedText);
      final iv = IV.fromBase64(decoded['iv']);
      final encrypter = Encrypter(AES(key!, mode: AESMode.cbc)); // Use AES CBC mode
      final decrypted = encrypter.decrypt(Encrypted.fromBase64(decoded['data']), iv: iv);

      return decrypted;
    } catch (e) {
      // Error handling and logging
      throw Exception('Encryption error: \$e');
    }
  }

  /// Decrypts RSA-encrypted text.
  /// If a private key is not provided, the stored RSA private key is used.
  Future<String> decryptRSA(String encryptedText, {RSAPrivateKey? privateKey}) async {
    // Initialize RSA key pair if not provided
    if (privateKey == null) await initializeRSAKeyPair();

    // Check if the RSA private key is available
    if (_keyRSA == null && privateKey == null) {
      throw Exception('Key is null');
    }

    privateKey ??= _keyRSA!.privateKey;

    final encryptedBytes = base64Decode(encryptedText);

    final decryptor = OAEPEncoding(RSAEngine())..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final decryptedBytes = _processInBlocks(decryptor, encryptedBytes);

    final decryptedString = utf8.decode(decryptedBytes);

    return decryptedString;
  }

  /// Encrypts plain text using RSA encryption.
  /// If a public key is not provided, the stored RSA public key is used.
  Future<String> encryptRSA(String plainText, {RSAPublicKey? publicKey}) async {
    // Initialize RSA key pair if not provided
    if (publicKey == null) await initializeRSAKeyPair();

    // Check if the RSA public key is available
    if (_keyRSA == null && publicKey == null) {
      throw Exception('Key is null');
    }

    publicKey ??= _keyRSA!.publicKey;

    final encryptor = OAEPEncoding(RSAEngine())..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final encryptedData = _processInBlocks(encryptor, Uint8List.fromList(utf8.encode(plainText)));

    return base64.encode(encryptedData);
  }

  /// Initializes RSA key pair with a given bit length (default is 2048).
  Future<void> initializeRSAKeyPair({int bitLength = 2048}) async {
    if (_keyRSA != null) {
      return;
    }

    final secureRandom = FortunaRandom();

    // Seed the random number generator
    final seedSource = Random.secure();
    final seeds = List<int>.generate(32, (_) => seedSource.nextInt(255));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    final rsaParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64);
    final params = ParametersWithRandom(rsaParams, secureRandom);
    final keyGenerator = RSAKeyGenerator()..init(params);

    final pair = keyGenerator.generateKeyPair();
    final publicKey = pair.publicKey as RSAPublicKey;
    final privateKey = pair.privateKey as RSAPrivateKey;

    _keyRSA = AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(publicKey, privateKey);
  }

  /// Initializes AES key by generating a new one or retrieving from storage.
  Future<void> initializeAESKey() async {
    if (_keyAES != null) {
      return;
    }

    String? storedKey = await _secureStorage.read(key: _aesKeyStorageKey);

    if (storedKey == null) {
      // Generate a new key if not stored
      final secureRandom = Random.secure();
      final keyBytes = List<int>.generate(32, (_) => secureRandom.nextInt(256)); // 256-bit AES key
      storedKey = base64UrlEncode(keyBytes);

      await _secureStorage.write(key: _aesKeyStorageKey, value: storedKey);
    }

    // Set the retrieved or newly generated key
    _keyAES = Key.fromBase64(storedKey);
  }

  /// Generates a secure, random IV for each encryption.
  IV _generateRandomIV() {
    final secureRandom = Random.secure();
    final ivBytes = List<int>.generate(16, (_) => secureRandom.nextInt(256));
    return IV(Uint8List.fromList(ivBytes));
  }

  /// Helper function to process data in blocks (for RSA encryption/decryption).
  Uint8List _processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
    final numBlocks = (input.length / engine.inputBlockSize).ceil();
    final output = BytesBuilder();

    for (var i = 0; i < numBlocks; i++) {
      final start = i * engine.inputBlockSize;
      final end = start + engine.inputBlockSize;
      final chunk = input.sublist(start, end > input.length ? input.length : end);
      output.add(engine.process(chunk));
    }

    return output.toBytes();
  }
}
