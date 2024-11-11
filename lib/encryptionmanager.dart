library encryption;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';

class EncryptionManager {
  static const String _aesKeyStorageKey = 'encryption_key';
  static EncryptionManager? _instance;

  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? get keyRSA {
    return _keyRSA;
  }

  Key? get keyAES {
    return _keyAES;
  }

  late FlutterSecureStorage _secureStorage;
  Key? _keyAES;
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? _keyRSA;

  factory EncryptionManager() {
    _instance ??= EncryptionManager._init();

    return _instance!;
  }

  EncryptionManager._init() {
    _secureStorage = const FlutterSecureStorage();
  }

  Future<String> encryptAES(String plainText, {Key? key}) async {

    if(key == null) await initializeAESKey();

    if (_keyAES == null && key == null) {
      throw Exception('Key is null');
    }

    key ??= _keyAES;

    final iv = _generateRandomIV(); // Verwende einen dynamischen IV
    final encrypter = Encrypter(AES(key!, mode: AESMode.cbc)); // Verwende AES CBC Mode
    final encrypted = encrypter.encrypt(plainText, iv: iv);

    // Speichere den IV zusammen mit den verschlüsselten Daten
    final result = {
      'iv': iv.base64,
      'data': encrypted.base64,
    };
    return jsonEncode(result);
  }

  Future<String> decryptAES(String encryptedText, {Key? key}) async {

    if(key == null) await initializeAESKey();

    if (_keyAES == null && key == null) {
      throw Exception('Key is null');
    }

    key ??= _keyAES;

    try {
      final Map<String, dynamic> decoded = jsonDecode(encryptedText);
      final iv = IV.fromBase64(decoded['iv']);
      final encrypter = Encrypter(AES(key!, mode: AESMode.cbc)); // Verwende AES CBC Mode
      final decrypted = encrypter.decrypt(Encrypted.fromBase64(decoded['data']), iv: iv);

      return decrypted;
    } catch (e) {
      // Fehlerbehandlung und Logging
      throw Exception('Encryption error: \$e');
    }
  }

  Future<String> decryptRSA(String encryptedText, {RSAPrivateKey? privateKey}) async {

    if(privateKey == null) await initializeRSAKeyPair();

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

  Future<String> encryptRSA(String plainText, {RSAPublicKey? publicKey}) async {
    
    if(publicKey == null) await initializeRSAKeyPair();

    if (_keyRSA == null && publicKey == null) {
      throw Exception('Key is null');
    }

    publicKey ??= _keyRSA!.publicKey;

    final encryptor = OAEPEncoding(RSAEngine())..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final encryptedData = _processInBlocks(encryptor, Uint8List.fromList(utf8.encode(plainText)));

    return base64.encode(encryptedData);
  }

  Future<void> initializeRSAKeyPair({int bitLength = 2048}) async {
    if (_keyRSA != null) {
      return;
    }

    final secureRandom = FortunaRandom();

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

  // Initialisierung: Generiere oder lade den Schlüssel
  Future<void> initializeAESKey() async {
    if (_keyAES != null) {
      return;
    }

    String? storedKey = await _secureStorage.read(key: _aesKeyStorageKey);

    if (storedKey == null) {
      // Falls kein Schlüssel gespeichert ist, generiere einen neuen
      final secureRandom = Random.secure();
      final keyBytes = List<int>.generate(32, (_) => secureRandom.nextInt(256)); // 256-Bit-Schlüssel für AES
      storedKey = base64UrlEncode(keyBytes);

      await _secureStorage.write(key: _aesKeyStorageKey, value: storedKey);
    }

    // Setze den abgerufenen oder neu generierten Schlüssel
    _keyAES = Key.fromBase64(storedKey);
  }

  // Generiere einen sicheren, zufälligen Initialisierungsvektor (IV) für jede Verschlüsselung
  IV _generateRandomIV() {
    final secureRandom = Random.secure();
    final ivBytes = List<int>.generate(16, (_) => secureRandom.nextInt(256));
    return IV(Uint8List.fromList(ivBytes));
  }

  // Hilfsfunktion zum Blockweise Entschlüsseln
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
