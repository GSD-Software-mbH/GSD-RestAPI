part of 'gsd_encryption.dart';

/// Die `EncryptionManager`-Klasse verwaltet AES- und RSA-Verschlüsselung und -Entschlüsselung.
/// 
/// Diese Klasse implementiert das Singleton-Pattern und bietet eine einheitliche Schnittstelle
/// für verschiedene Verschlüsselungsoperationen:
/// 
/// **AES-Verschlüsselung:**
/// - AES-256 im CBC-Modus mit PKCS7-Padding
/// - Automatische IV-Generierung für jede Verschlüsselung
/// - Sichere Schlüsselspeicherung mit FlutterSecureStorage
/// - Persistente Schlüssel, die zwischen App-Starts erhalten bleiben
/// 
/// **RSA-Verschlüsselung:**
/// - OAEP-Padding mit SHA-256 Digest für maximale Sicherheit
/// - Unterstützung für blockweise Verarbeitung großer Daten
/// - Plattformübergreifende Implementierung (Web und Native)
/// - Schlüsselgenerierung oder Laden aus PEM-Dateien
/// 
/// **Hauptfunktionen:**
/// - Sichere Schlüsselgenerierung und -verwaltung
/// - Symmetrische und asymmetrische Verschlüsselung
/// - Automatische Initialisierung bei Bedarf
/// - Fehlerbehandlung und Validierung
/// 
/// **Verwendung:**
/// ```dart
/// // Einfache Verwendung mit automatischer Schlüsselgenerierung
/// final encManager = EncryptionManager();
/// String encrypted = await encManager.encryptAES("Geheimer Text");
/// String decrypted = await encManager.decryptAES(encrypted);
/// 
/// // Verwendung mit vordefinierten Schlüsseln
/// final options = EncryptionOptions(
///   rsaPublicKeyFilePath: "assets/public.pem",
///   rsaPrivateKeyFilePath: "assets/private.pem"
/// );
/// final encManager = EncryptionManager.init(options);
/// ```
class EncryptionManager {
  static const String _aesKeyStorageKey = 'encryption_key';
  static EncryptionManager? _instance;

  /// Getter für das aktuell gespeicherte RSA-Schlüsselpaar.
  /// 
  /// Rückgabe: Das RSA-Schlüsselpaar (öffentlicher und privater Schlüssel) oder null, falls noch nicht initialisiert
  /// 
  /// Verwenden Sie initializeRSAKeyPair() um ein Schlüsselpaar zu generieren oder
  /// EncryptionManager.init() um Schlüssel aus Dateien zu laden, bevor Sie diesen Getter verwenden.
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? get keyRSA {
    return _keyRSA;
  }

  /// Getter für den aktuell gespeicherten AES-Schlüssel.
  /// 
  /// Rückgabe: Der AES-Schlüssel als Key-Objekt oder null, falls noch nicht initialisiert
  /// 
  /// Verwenden Sie initializeAESKey() um einen Schlüssel zu generieren oder zu laden,
  /// bevor Sie diesen Getter verwenden.
  Key? get keyAES {
    return _keyAES;
  }

  late FlutterSecureStorage _secureStorage;
  Key? _keyAES;
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? _keyRSA;

  /// Factory-Konstruktor für die Singleton-Instanz des EncryptionManagers.
  /// 
  /// Dieser Factory-Konstruktor implementiert das Singleton-Pattern und stellt sicher,
  /// dass nur eine Instanz des EncryptionManagers existiert. Beim ersten Aufruf wird
  /// eine neue Instanz erstellt, bei nachfolgenden Aufrufen wird die bestehende
  /// Instanz zurückgegeben.
  /// 
  /// Rückgabe: Die Singleton-Instanz des EncryptionManagers
  /// 
  /// Verwenden Sie diesen Konstruktor für die normale Nutzung ohne spezielle
  /// Konfiguration. Schlüssel können später über die entsprechenden Methoden
  /// initialisiert werden.
  factory EncryptionManager() {
    _instance ??= EncryptionManager._init();
    return _instance!;
  }

  /// Factory-Konstruktor zur Erstellung einer EncryptionManager-Instanz mit Konfiguration.
  /// 
  /// Dieser Factory-Konstruktor erstellt eine neue Singleton-Instanz des EncryptionManagers
  /// und initialisiert sie mit den bereitgestellten EncryptionOptions. Falls bereits
  /// eine Instanz existiert, wird sie durch die neue ersetzt.
  /// 
  /// Parameter:
  /// - [encryptionOptions]: Konfigurationsobjekt mit Schlüsselpfaden und -daten
  /// 
  /// Rückgabe: Die konfigurierte EncryptionManager-Instanz
  /// 
  /// Verwenden Sie diesen Konstruktor, wenn Sie spezifische Schlüssel oder
  /// Konfigurationen für die Verschlüsselung benötigen.
  factory EncryptionManager.init(EncryptionOptions encryptionOptions) {
    _instance = EncryptionManager._init(encryptionOptions: encryptionOptions);
    return _instance!;
  }

  /// Privater Konstruktor zur Initialisierung des EncryptionManagers.
  /// 
  /// Dieser Konstruktor initialisiert den sicheren Speicher (FlutterSecureStorage)
  /// und führt optional eine Initialisierung mit bereitgestellten EncryptionOptions durch.
  /// Er wird nur intern von den Factory-Konstruktoren aufgerufen, um das Singleton-Pattern
  /// zu gewährleisten.
  /// 
  /// Parameter:
  /// - [encryptionOptions]: Optionale Konfiguration für die Initialisierung von Schlüsseln
  /// 
  /// Der sichere Speicher wird für die persistente und sichere Aufbewahrung von
  /// AES-Schlüsseln verwendet. RSA-Schlüssel werden normalerweise aus Dateien oder
  /// Assets geladen und nicht im sicheren Speicher gespeichert.
  EncryptionManager._init({EncryptionOptions? encryptionOptions}) {
    _secureStorage = const FlutterSecureStorage();

    if (encryptionOptions != null) {
      _init(encryptionOptions);
    }
  }

  /// Private Initialisierungsmethode für Verschlüsselungsoptionen.
  /// 
  /// Diese asynchrone Methode verarbeitet die bereitgestellten EncryptionOptions
  /// und initialisiert die entsprechenden Schlüssel. Sie behandelt sowohl AES-
  /// als auch RSA-Schlüssel und berücksichtigt dabei die Plattform (Web vs. Native).
  /// 
  /// Für RSA-Schlüssel:
  /// - Auf nativen Plattformen werden die Schlüssel aus Dateien gelesen
  /// - Auf Web-Plattformen werden sie aus Assets geladen
  /// - Die Schlüssel werden aus PEM-Format geparst
  /// 
  /// Für AES-Schlüssel:
  /// - Werden aus den bereitgestellten Bytes generiert
  /// 
  /// Parameter:
  /// - [encryptionOptions]: Konfigurationsobjekt mit Schlüsselpfaden und -daten
  void _init(EncryptionOptions encryptionOptions) async {
    if (encryptionOptions.aesKeyBytes.isNotEmpty) {
      _keyAES = generateAESKey(encryptionOptions.aesKeyBytes);
    }

    File rsaPublicKeyFile = File(encryptionOptions.rsaPublicKeyFilePath);
    File rsaPrivateKeyFile = File(encryptionOptions.rsaPrivateKeyFilePath);
    String rsaPublicKeyPEM = "";
    String rsaPrivateKeyPEM = "";

    if (!foundation.kIsWeb &&
        rsaPublicKeyFile.existsSync() &&
        rsaPrivateKeyFile.existsSync()) {
      rsaPublicKeyPEM = rsaPublicKeyFile.readAsStringSync();
      rsaPrivateKeyPEM = rsaPrivateKeyFile.readAsStringSync();
    } else {
      rsaPublicKeyPEM =
          await rootBundle.loadString(encryptionOptions.rsaPublicKeyFilePath);
      rsaPrivateKeyPEM =
          await rootBundle.loadString(encryptionOptions.rsaPrivateKeyFilePath);
    }

    if (rsaPublicKeyPEM.isNotEmpty && rsaPrivateKeyPEM.isNotEmpty) {
      RSAPublicKey rsaPublicKey = rsaPublicKeyPEM.parsePublicKeyFromPem();
      RSAPrivateKey rsaPrivateKey = rsaPrivateKeyPEM.parsePrivateKeyFromPem();

      _keyRSA = AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
          rsaPublicKey, rsaPrivateKey);
    }
  }

  /// Verschlüsselt den angegebenen Klartext mit AES-Verschlüsselung im CBC-Modus.
  /// 
  /// Diese Methode verwendet AES-256 Verschlüsselung mit einem zufällig generierten
  /// Initialisierungsvektor (IV) für jede Verschlüsselung. Der IV wird zusammen
  /// mit den verschlüsselten Daten im JSON-Format zurückgegeben.
  /// 
  /// Parameter:
  /// - [plainText]: Der zu verschlüsselnde Klartext
  /// - [key]: Optionaler AES-Schlüssel. Falls nicht angegeben, wird der gespeicherte Schlüssel verwendet
  /// - [padding]: Padding-Verfahren (Standard: "PKCS7")
  /// 
  /// Rückgabe: JSON-String mit IV und verschlüsselten Daten im Base64-Format
  /// 
  /// Wirft eine Exception, wenn kein Schlüssel verfügbar ist.
  Future<String> encryptAES(String plainText, {Key? key, String? padding = "PKCS7"}) async {
    // Initialisiert den AES-Schlüssel, falls nicht vorhanden
    if (key == null) await initializeAESKey();

    // Überprüft, ob der AES-Schlüssel verfügbar ist
    if (_keyAES == null && key == null) {
      throw Exception('Key is null');
    }

    key ??= _keyAES;

    final iv = _generateRandomIV(); // Generiert einen zufälligen IV
    final encrypter =
        Encrypter(AES(key!, mode: AESMode.cbc, padding: padding)); // Verwendet AES im CBC-Modus
    final encrypted = encrypter.encrypt(plainText, iv: iv);

    // Kombiniert den IV mit den verschlüsselten Daten
    final result = {
      'iv': iv.base64,
      'data': encrypted.base64,
    };
    return jsonEncode(result);
  }

  /// Entschlüsselt einen mit AES verschlüsselten Text im CBC-Modus.
  /// 
  /// Diese Methode erwartet einen JSON-String mit dem IV und den verschlüsselten Daten
  /// im Base64-Format. Der Text wird mit dem angegebenen oder gespeicherten AES-Schlüssel
  /// entschlüsselt.
  /// 
  /// Parameter:
  /// - [encryptedText]: JSON-String mit IV und verschlüsselten Daten (von encryptAES erstellt)
  /// - [key]: Optionaler AES-Schlüssel. Falls nicht angegeben, wird der gespeicherte Schlüssel verwendet
  /// - [padding]: Padding-Verfahren (Standard: "PKCS7")
  /// 
  /// Rückgabe: Der entschlüsselte Klartext
  /// 
  /// Wirft eine Exception bei Entschlüsselungsfehlern oder wenn kein Schlüssel verfügbar ist.
  Future<String> decryptAES(String encryptedText, {Key? key, String? padding = "PKCS7"}) async {
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
      final encrypter =
          Encrypter(AES(key!, mode: AESMode.cbc, padding: padding)); // Verwendet AES im CBC-Modus
      final decrypted =
          encrypter.decrypt(Encrypted.fromBase64(decoded['data']), iv: iv);

      return decrypted;
    } catch (e) {
      // Fehlerbehandlung und Logging
      throw Exception('Encryption error: $e');
    }
  }

  /// Entschlüsselt Daten, die mit RSA-Verschlüsselung verschlüsselt wurden.
  /// 
  /// Diese Methode verwendet OAEP-Padding mit SHA-256 Digest für sichere RSA-Entschlüsselung.
  /// Sie ist für kleinere Datenmengen gedacht (maximal RSA-Schlüssellänge minus Padding).
  /// 
  /// Parameter:
  /// - [encryptedBytes]: Die verschlüsselten Bytes
  /// - [privateKey]: Optionaler RSA-Privatschlüssel. Falls nicht angegeben, wird der gespeicherte Schlüssel verwendet
  /// 
  /// Rückgabe: Die entschlüsselten Bytes als Uint8List
  /// 
  /// Wirft eine Exception, wenn kein Schlüssel verfügbar ist oder die Entschlüsselung fehlschlägt.
  Future<Uint8List> decryptRSA(Uint8List encryptedBytes,
      {RSAPrivateKey? privateKey}) async {
    // Initialisiert das RSA-Schlüsselpaar, falls nicht vorhanden
    if (privateKey == null) await initializeRSAKeyPair();

    // Überprüft, ob der RSA-Schlüssel verfügbar ist
    if (_keyRSA == null && privateKey == null) {
      throw Exception('Key is null');
    }

    privateKey ??= _keyRSA!.privateKey;

    final rsaEncrypter = Encrypter(RSA(privateKey: privateKey, encoding: RSAEncoding.OAEP, digest: RSADigest.SHA256));
    final decryptedBytes = Uint8List.fromList(rsaEncrypter.decryptBytes(Encrypted(encryptedBytes)));

    return decryptedBytes;
  }

  /// Entschlüsselt längere Texte, die blockweise mit RSA verschlüsselt wurden.
  /// 
  /// Diese Methode ermöglicht die Entschlüsselung von Texten, die länger sind als die
  /// maximale RSA-Blockgröße. Die Daten werden in Blöcken verarbeitet und dann
  /// zusammengefügt. Verwendet OAEP-Encoding für sichere Entschlüsselung.
  /// 
  /// Parameter:
  /// - [encryptedText]: Base64-kodierter verschlüsselter Text
  /// - [privateKey]: Optionaler RSA-Privatschlüssel. Falls nicht angegeben, wird der gespeicherte Schlüssel verwendet
  /// 
  /// Rückgabe: Der entschlüsselte Klartext als String
  /// 
  /// Wirft eine Exception, wenn kein Schlüssel verfügbar ist oder die Entschlüsselung fehlschlägt.
  Future<String> decryptRSAInBlocks(String encryptedText,
      {RSAPrivateKey? privateKey}) async {
    // Initialisiert das RSA-Schlüsselpaar, falls nicht vorhanden
    if (privateKey == null) await initializeRSAKeyPair();

    // Überprüft, ob der RSA-Schlüssel verfügbar ist
    if (_keyRSA == null && privateKey == null) {
      throw Exception('Key is null');
    }

    privateKey ??= _keyRSA!.privateKey;

    final encryptedBytes = base64Decode(encryptedText);

    final decryptor = OAEPEncoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final decryptedBytes = _processInBlocks(decryptor, encryptedBytes);

    final decryptedString = utf8.decode(decryptedBytes);

    return decryptedString;
  }

  /// Verschlüsselt Daten mit RSA-Verschlüsselung für kleinere Datenmengen.
  /// 
  /// Diese Methode verwendet OAEP-Padding mit SHA-256 Digest für sichere RSA-Verschlüsselung.
  /// Sie ist für kleinere Datenmengen gedacht (maximal RSA-Schlüssellänge minus Padding).
  /// Für größere Daten sollte encryptRSAInBlocks verwendet werden.
  /// 
  /// Parameter:
  /// - [plainBytes]: Die zu verschlüsselnden Bytes
  /// - [publicKey]: Optionaler RSA-Öffentlicher Schlüssel. Falls nicht angegeben, wird der gespeicherte Schlüssel verwendet
  /// 
  /// Rückgabe: Die verschlüsselten Bytes als Uint8List
  /// 
  /// Wirft eine Exception, wenn kein Schlüssel verfügbar ist oder die Verschlüsselung fehlschlägt.
  Future<Uint8List> encryptRSA(Uint8List plainBytes, {RSAPublicKey? publicKey}) async {
    // Initialisiert das RSA-Schlüsselpaar, falls nicht vorhanden
    if (publicKey == null) await initializeRSAKeyPair();

    // Überprüft, ob der RSA-Schlüssel verfügbar ist
    if (_keyRSA == null && publicKey == null) {
      throw Exception('Key is null');
    }

    publicKey ??= _keyRSA!.publicKey;

    
    final rsaEncrypter = Encrypter(RSA(publicKey: publicKey, encoding: RSAEncoding.OAEP, digest: RSADigest.SHA256));
    final encryptedBytes = rsaEncrypter.encryptBytes(plainBytes).bytes;

    return encryptedBytes;
  }

    /// Verschlüsselt längere Texte blockweise mit RSA-Verschlüsselung.
  /// 
  /// Diese Methode ermöglicht die Verschlüsselung von Texten, die länger sind als die
  /// maximale RSA-Blockgröße. Der Text wird in UTF-8 Bytes konvertiert, in Blöcken
  /// verarbeitet und als Base64-String zurückgegeben. Verwendet OAEP-Encoding für
  /// sichere Verschlüsselung.
  /// 
  /// Parameter:
  /// - [plainText]: Der zu verschlüsselnde Klartext
  /// - [publicKey]: Optionaler RSA-Öffentlicher Schlüssel. Falls nicht angegeben, wird der gespeicherte Schlüssel verwendet
  /// 
  /// Rückgabe: Base64-kodierter verschlüsselter Text
  /// 
  /// Wirft eine Exception, wenn kein Schlüssel verfügbar ist oder die Verschlüsselung fehlschlägt.
  Future<String> encryptRSAInBlocks(String plainText, {RSAPublicKey? publicKey}) async {
    // Initialisiert das RSA-Schlüsselpaar, falls nicht vorhanden
    if (publicKey == null) await initializeRSAKeyPair();

    // Überprüft, ob der RSA-Schlüssel verfügbar ist
    if (_keyRSA == null && publicKey == null) {
      throw Exception('Key is null');
    }

    publicKey ??= _keyRSA!.publicKey;

    final encryptor = OAEPEncoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final encryptedData =
        _processInBlocks(encryptor, Uint8List.fromList(utf8.encode(plainText)));

    return base64.encode(encryptedData);
  }

  /// Initialisiert das RSA-Schlüsselpaar durch Generierung neuer Schlüssel.
  /// 
  /// Diese Methode generiert ein neues RSA-Schlüsselpaar mit der angegebenen Bit-Länge,
  /// falls noch keines vorhanden ist. Auf Web-Plattformen wird die Web Crypto API verwendet,
  /// auf anderen Plattformen wird die pointycastle-Bibliothek verwendet.
  /// 
  /// Parameter:
  /// - [bitLength]: Die Bit-Länge des zu generierenden Schlüssels (Standard: 2048)
  /// 
  /// Die Methode beendet sich frühzeitig, wenn bereits ein Schlüsselpaar vorhanden ist.
  Future<void> initializeRSAKeyPair({int bitLength = 2048}) async {
    if (_keyRSA != null) {
      return;
    }

    _keyRSA = await generateRandomRSAKey(bitLength: bitLength);
  }

  /// Generiert ein neues zufälliges RSA-Schlüsselpaar.
  /// 
  /// Diese Methode erstellt ein neues RSA-Schlüsselpaar mit kryptographisch sicherem
  /// Zufallszahlengenerator. Auf Web-Plattformen wird die Web Crypto API verwendet,
  /// auf anderen Plattformen wird Fortuna Random mit pointycastle verwendet.
  /// 
  /// Parameter:
  /// - [bitLength]: Die Bit-Länge des zu generierenden Schlüssels (Standard: 2048)
  /// 
  /// Rückgabe: Ein AsymmetricKeyPair mit RSA-Öffentlichem und -Privatem Schlüssel
  /// 
  /// Der generierte Schlüssel verwendet den Standard-Exponenten 65537.
  Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generateRandomRSAKey({int bitLength = 2048}) async {

    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;

    if (foundation.kIsWeb) {
      return await WebRSAEncryptionManager.generateRSAKeys(bitLength: bitLength);
    }

    final secureRandom = FortunaRandom();

    // Initialisiert den Zufallszahlengenerator
    final seedSource = Random.secure();
    final seeds = List<int>.generate(32, (_) => seedSource.nextInt(255));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    final rsaParams =
        RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64);
    final params = ParametersWithRandom(rsaParams, secureRandom);
    final keyGenerator = RSAKeyGenerator()..init(params);

    final pair = keyGenerator.generateKeyPair();
    publicKey = pair.publicKey as RSAPublicKey;
    privateKey = pair.privateKey as RSAPrivateKey;

    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(publicKey, privateKey);
  }

  /// Initialisiert den AES-Schlüssel durch Laden aus dem Speicher oder Generierung eines neuen Schlüssels.
  /// 
  /// Diese Methode überprüft zunächst, ob bereits ein AES-Schlüssel im Speicher vorhanden ist.
  /// Falls nicht, wird ein neuer 256-Bit AES-Schlüssel generiert und im sicheren Speicher
  /// (FlutterSecureStorage) gespeichert. Bei nachfolgenden Aufrufen wird der gespeicherte
  /// Schlüssel wiederverwendet.
  /// 
  /// Der Schlüssel wird als Base64-String im sicheren Speicher abgelegt und bei Bedarf
  /// wieder geladen. Die Methode beendet sich frühzeitig, wenn bereits ein Schlüssel
  /// im Speicher vorhanden ist.
  /// 
  /// Wirft eine Exception, wenn der Zugriff auf den sicheren Speicher fehlschlägt.
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

  /// Generiert einen kryptographisch sicheren, zufälligen AES-256-Schlüssel.
  /// 
  /// Diese Methode verwendet einen sicheren Zufallszahlengenerator (Random.secure())
  /// um 32 zufällige Bytes zu generieren, die für einen AES-256-Schlüssel benötigt werden.
  /// Die generierten Bytes werden dann über generateAESKey() in ein Key-Objekt umgewandelt.
  /// 
  /// Rückgabe: Ein neuer AES-256-Schlüssel als Key-Objekt
  /// 
  /// Diese Methode sollte nur verwendet werden, wenn ein völlig neuer Schlüssel benötigt wird.
  /// Für die normale Initialisierung sollte initializeAESKey() verwendet werden.
  Future<Key> generateRandomAESKey() async {
    // Erstellt einen sicheren Zufallszahlengenerator
    final secureRandom = Random.secure();

    // Generiert ein Byte-Array der Länge 32 für den AES-256-Schlüssel
    final keyBytes = List<int>.generate(32, (_) => secureRandom.nextInt(256));

    // Erzeugt den Schlüssel auf Basis der generierten Bytes
    return generateAESKey(keyBytes);
  }

  /// Konvertiert ein Byte-Array in einen AES-Schlüssel.
  /// 
  /// Diese Hilfsmethode nimmt ein Array von Bytes entgegen und konvertiert sie
  /// in einen Base64-kodierten String, der dann als AES-Schlüssel verwendet wird.
  /// Die Methode verwendet base64UrlEncode für die Kodierung.
  /// 
  /// Parameter:
  /// - [bytes]: Die Schlüssel-Bytes (sollten 32 Bytes für AES-256 sein)
  /// 
  /// Rückgabe: Ein Key-Objekt, das für AES-Verschlüsselung verwendet werden kann
  /// 
  /// Diese Methode wird sowohl von generateRandomAESKey() als auch bei der
  /// Initialisierung mit vorgegebenen Schlüssel-Bytes verwendet.
  Key generateAESKey(List<int> bytes) {
    // Kodiert die Bytes als Base64-String
    final base64Key = base64UrlEncode(bytes);

    // Erstellt und gibt ein Key-Objekt auf Basis des Base64-Strings zurück
    return Key.fromBase64(base64Key);
  }

  /// Generiert einen kryptographisch sicheren, zufälligen Initialisierungsvektor (IV).
  /// 
  /// Diese private Methode erstellt einen 16-Byte (128-Bit) IV, der für jede
  /// AES-Verschlüsselung benötigt wird. Der IV stellt sicher, dass identische
  /// Klartexte unterschiedliche Chiffretexte erzeugen und verhindert damit
  /// Mustererkennungsangriffe.
  /// 
  /// Rückgabe: Ein IV-Objekt mit 16 zufälligen Bytes
  /// 
  /// Der IV muss nicht geheim gehalten werden und wird zusammen mit den
  /// verschlüsselten Daten gespeichert, damit sie später entschlüsselt werden können.
  IV _generateRandomIV() {
    final secureRandom = Random.secure();
    final ivBytes = List<int>.generate(16, (_) => secureRandom.nextInt(256));
    return IV(Uint8List.fromList(ivBytes));
  }

  /// Verarbeitet Daten blockweise mit einem asymmetrischen Verschlüsselungsalgorithmus.
  /// 
  /// Diese private Hilfsmethode ermöglicht die Verarbeitung von Daten, die größer sind
  /// als die maximale Blockgröße des verwendeten asymmetrischen Algorithmus (z.B. RSA).
  /// Die Eingabedaten werden in Blöcke aufgeteilt, einzeln verarbeitet und dann
  /// wieder zusammengefügt.
  /// 
  /// Parameter:
  /// - [engine]: Der asymmetrische Verschlüsselungsalgorithmus (z.B. RSA mit OAEP)
  /// - [input]: Die zu verarbeitenden Eingabedaten
  /// 
  /// Rückgabe: Die verarbeiteten Daten als Uint8List
  /// 
  /// Diese Methode wird sowohl für RSA-Verschlüsselung als auch -Entschlüsselung
  /// in den Methoden encryptRSAInBlocks() und decryptRSAInBlocks() verwendet.
  Uint8List _processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
    final numBlocks = (input.length / engine.inputBlockSize).ceil();
    final output = BytesBuilder();

    for (var i = 0; i < numBlocks; i++) {
      final start = i * engine.inputBlockSize;
      final end = start + engine.inputBlockSize;
      final chunk =
          input.sublist(start, end > input.length ? input.length : end);
      output.add(engine.process(chunk));
    }

    return output.toBytes();
  }
}
