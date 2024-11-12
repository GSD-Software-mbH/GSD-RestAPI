library encryption;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';

/// Die `EncryptionManager`-Klasse verwaltet AES- und RSA-Verschlüsselung und -Entschlüsselung.
class EncryptionManager {
  static const String _aesKeyStorageKey = 'encryption_key';
  static EncryptionManager? _instance;

  /// Getter für das RSA-Schlüsselpaar
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? get keyRSA {
    return _keyRSA;
  }

  /// Getter für den AES-Schlüssel
  Key? get keyAES {
    return _keyAES;
  }

  late FlutterSecureStorage _secureStorage;
  Key? _keyAES;
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? _keyRSA;

  /// Factory-Konstruktor für die Singleton-Instanz
  factory EncryptionManager() {
    _instance ??= EncryptionManager._init();
    return _instance!;
  }

  /// Privater Konstruktor zur Initialisierung des sicheren Speichers
  EncryptionManager._init() {
    _secureStorage = const FlutterSecureStorage();
  }

  /// Verschlüsselt den angegebenen Klartext mit AES-Verschlüsselung.
  /// Falls kein Schlüssel angegeben wird, wird der gespeicherte AES-Schlüssel verwendet.
  Future<String> encryptAES(String plainText, {Key? key}) async {
    // Initialisiert den AES-Schlüssel, falls nicht vorhanden
    if (key == null) await initializeAESKey();

    // Überprüft, ob der AES-Schlüssel verfügbar ist
    if (_keyAES == null && key == null) {
      throw Exception('Key is null');
    }

    key ??= _keyAES;

    final iv = _generateRandomIV(); // Generiert einen zufälligen IV
    final encrypter = Encrypter(AES(key!, mode: AESMode.cbc)); // Verwendet AES im CBC-Modus
    final encrypted = encrypter.encrypt(plainText, iv: iv);

    // Kombiniert den IV mit den verschlüsselten Daten
    final result = {
      'iv': iv.base64,
      'data': encrypted.base64,
    };
    return jsonEncode(result);
  }

  /// Entschlüsselt einen mit AES verschlüsselten Text.
  /// Falls kein Schlüssel angegeben wird, wird der gespeicherte AES-Schlüssel verwendet.
  Future<String> decryptAES(String encryptedText, {Key? key}) async {
    // Initialisiert den AES-Schlüssel, falls nicht vorhanden
    if (key == null) await initializeAESKey();

    // Überprüft, ob der AES-Schlüssel verfügbar ist
    if (_keyAES == null && key == null) {
      throw Exception('Key is null');
    }

    key ??= _keyAES;

    try {
      final Map<String, dynamic> decoded = jsonDecode(encryptedText);
      final iv = IV.fromBase64(decoded['iv']);
      final encrypter = Encrypter(AES(key!, mode: AESMode.cbc)); // Verwendet AES im CBC-Modus
      final decrypted = encrypter.decrypt(Encrypted.fromBase64(decoded['data']), iv: iv);

      return decrypted;
    } catch (e) {
      // Fehlerbehandlung und Logging
      throw Exception('Encryption error: \$e');
    }
  }

  /// Entschlüsselt einen mit RSA verschlüsselten Text.
  /// Falls kein privater Schlüssel angegeben wird, wird der gespeicherte RSA-Schlüssel verwendet.
  Future<String> decryptRSA(String encryptedText, {RSAPrivateKey? privateKey}) async {
    // Initialisiert das RSA-Schlüsselpaar, falls nicht vorhanden
    if (privateKey == null) await initializeRSAKeyPair();

    // Überprüft, ob der RSA-Schlüssel verfügbar ist
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

  /// Verschlüsselt einen Klartext mit RSA-Verschlüsselung.
  /// Falls kein öffentlicher Schlüssel angegeben wird, wird der gespeicherte RSA-Schlüssel verwendet.
  Future<String> encryptRSA(String plainText, {RSAPublicKey? publicKey}) async {
    // Initialisiert das RSA-Schlüsselpaar, falls nicht vorhanden
    if (publicKey == null) await initializeRSAKeyPair();

    // Überprüft, ob der RSA-Schlüssel verfügbar ist
    if (_keyRSA == null && publicKey == null) {
      throw Exception('Key is null');
    }

    publicKey ??= _keyRSA!.publicKey;

    final encryptor = OAEPEncoding(RSAEngine())..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final encryptedData = _processInBlocks(encryptor, Uint8List.fromList(utf8.encode(plainText)));

    return base64.encode(encryptedData);
  }

  /// Initialisiert das RSA-Schlüsselpaar mit einer angegebenen Bit-Länge (Standard ist 2048).
  Future<void> initializeRSAKeyPair({int bitLength = 2048}) async {
    if (_keyRSA != null) {
      return;
    }

    final secureRandom = FortunaRandom();

    // Initialisiert den Zufallszahlengenerator
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

  /// Initialisiert den AES-Schlüssel durch Erzeugen eines neuen Schlüssels oder durch Abrufen aus dem Speicher.
  Future<void> initializeAESKey() async {
    // Überprüft, ob der Schlüssel bereits existiert
    if (_keyAES != null) {
      return; // Beendet die Methode, wenn der Schlüssel bereits gesetzt ist
    }

    // Liest den gespeicherten Schlüssel aus dem sicheren Speicher
    String? storedKey = await _secureStorage.read(key: _aesKeyStorageKey);

    // Überprüft, ob ein Schlüssel im Speicher vorhanden ist
    if (storedKey == null) {
      // Generiert einen neuen Schlüssel, falls keiner gespeichert ist
      Key key = await generateRandomAESKey();

      // Kodiert den Schlüssel als Base64-String
      storedKey = key.base64;

      // Speichert den neuen Schlüssel im sicheren Speicher
      await _secureStorage.write(key: _aesKeyStorageKey, value: storedKey);
    }

    // Setzt den abgerufenen oder neu generierten Schlüssel
    _keyAES = Key.fromBase64(storedKey);
  }

  /// Generiert einen zufälligen AES-Schlüssel
  Future<Key> generateRandomAESKey() async {
    // Erstellt einen sicheren Zufallszahlengenerator
    final secureRandom = Random.secure();

    // Generiert ein Byte-Array der Länge 32 für den AES-256-Schlüssel
    final keyBytes = List<int>.generate(32, (_) => secureRandom.nextInt(256));

    // Erzeugt den Schlüssel auf Basis der generierten Bytes
    return generateAESKey(keyBytes);
  }

  /// Wandelt das Byte-Array in einen Base64-kodierten AES-Schlüssel um und erstellt das Key-Objekt
  Key generateAESKey(List<int> bytes) {
    // Kodiert die Bytes als Base64-String
    final base64Key = base64UrlEncode(bytes);

    // Erstellt und gibt ein Key-Objekt auf Basis des Base64-Strings zurück
    return Key.fromBase64(base64Key);
  }


  /// Generiert einen sicheren, zufälligen IV für jede Verschlüsselung.
  IV _generateRandomIV() {
    final secureRandom = Random.secure();
    final ivBytes = List<int>.generate(16, (_) => secureRandom.nextInt(256));
    return IV(Uint8List.fromList(ivBytes));
  }

  /// Hilfsfunktion zur Blockweise-Verarbeitung von Daten (für RSA-Verschlüsselung/Entschlüsselung).
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
