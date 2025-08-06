part of 'gsd_encryption.dart';

/// Erweiterung für `String` zur Verarbeitung von RSA-Schlüsseln im PEM-Format.
/// 
/// Diese Extension erweitert die String-Klasse um Funktionen zum Parsen von
/// RSA-Schlüsseln aus dem PEM-Format. Sie unterstützt sowohl öffentliche als
/// auch private Schlüssel und konvertiert sie in die entsprechenden
/// pointycastle-Objekte.
/// 
/// **Unterstützte Formate:**
/// - **Öffentliche Schlüssel**: SPKI (Subject Public Key Info) Format
/// - **Private Schlüssel**: PKCS#8 Format
/// - **Encoding**: Base64 mit PEM-Headern und -Footern
/// 
/// **Verwendung:**
/// ```dart
/// String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n...";
/// RSAPublicKey publicKey = publicKeyPem.parsePublicKeyFromPem();
/// 
/// String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n...";
/// RSAPrivateKey privateKey = privateKeyPem.parsePrivateKeyFromPem();
/// ```
/// 
/// **Interne Verarbeitung:**
/// - Entfernung der PEM-Header und -Footer
/// - Base64-Dekodierung des Schlüsselmaterials
/// - ASN.1-Parsing der binären Daten
/// - Extraktion der mathematischen Parameter (Modulus, Exponenten)
extension StringExtensions on String {
  /// Parst einen öffentlichen RSA-Schlüssel aus dem PEM-Format (SPKI).
  /// 
  /// Diese Methode dekodiert einen PEM-formatierten öffentlichen Schlüssel und
  /// extrahiert die mathematischen Parameter (Modulus und Exponent) durch
  /// ASN.1-Parsing. Das resultierende RSAPublicKey-Objekt kann für
  /// Verschlüsselungsoperationen verwendet werden.
  /// 
  /// Rückgabe: RSAPublicKey-Objekt mit Modulus und öffentlichem Exponenten
  /// 
  /// Wirft eine Exception, wenn das PEM-Format ungültig ist oder die
  /// ASN.1-Struktur nicht den Erwartungen entspricht.
  RSAPublicKey parsePublicKeyFromPem() {
    // Entferne die PEM-Header und -Footer und dekodiere den Base64-PEM-Block
    final pemLines = split('\n');
    final base64String = pemLines
        .where((line) => line.isNotEmpty && !line.startsWith('---'))
        .join().replaceAll(RegExp(r'\s'), '');
    final bytes = base64.decode(base64String);

    // Parsen der ASN.1-Struktur
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    // Die oberste Sequenz enthält den Algorithmus-Identifier und den öffentlichen Schlüssel
    final publicKeyBitString = topLevelSeq.elements![1] as ASN1BitString;

    // Extrahiere den Inhalt des BitStrings (dies ist der tatsächliche öffentliche Schlüssel)
    final publicKeyBytes = publicKeyBitString.stringValues;

    // Parsen der Struktur des öffentlichen Schlüssels innerhalb der BitString-Daten
    final publicKeyAsn1Parser = ASN1Parser(Uint8List.fromList(publicKeyBytes!));
    final publicKeySeq = publicKeyAsn1Parser.nextObject() as ASN1Sequence;

    // Extrahiere Modulus (n) und Exponent (e) aus der Sequenz
    final ASN1Integer modulusASN1 = publicKeySeq.elements![0] as ASN1Integer;
    final ASN1Integer exponentASN1 = publicKeySeq.elements![1] as ASN1Integer;

    // Konvertiere Modulus und Exponent in BigInt
    final modulusBigInt =
        BigInt.parse(modulusASN1.valueBytes!.bytesToHex(), radix: 16);
    final exponentBigInt =
        BigInt.parse(exponentASN1.valueBytes!.bytesToHex(), radix: 16);

    // Erstelle den `RSAPublicKey`
    return RSAPublicKey(modulusBigInt, exponentBigInt);
  }

  /// Parst einen privaten RSA-Schlüssel aus dem PEM-Format (PKCS#8).
  /// 
  /// Diese Methode dekodiert einen PEM-formatierten privaten Schlüssel und
  /// extrahiert alle notwendigen mathematischen Parameter (Modulus, private und
  /// öffentliche Exponenten, Primfaktoren) durch ASN.1-Parsing. Das resultierende
  /// RSAPrivateKey-Objekt kann für Entschlüsselungsoperationen verwendet werden.
  /// 
  /// Rückgabe: RSAPrivateKey-Objekt mit allen notwendigen Parametern
  /// 
  /// Wirft eine Exception, wenn das PEM-Format ungültig ist oder die
  /// ASN.1-Struktur nicht den PKCS#8-Erwartungen entspricht.
  RSAPrivateKey parsePrivateKeyFromPem() {
    // Entferne die PEM-Header und -Footer und dekodiere den Base64-PEM-Block
    final pemLines = split('\n');
    final base64String = pemLines
        .where((line) => line.isNotEmpty && !line.startsWith('---'))
        .join().replaceAll(RegExp(r'\s'), '');
    final bytes = base64.decode(base64String);

    // Parsen der ASN.1-Struktur
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    // PKCS#8-Struktur: Extrahiere den privaten Schlüssel aus dem OctetString
    final privateKeyOctetString = topLevelSeq.elements!.last as ASN1OctetString;
    final privateKeyBytes = privateKeyOctetString.octets;
    final privateKeyParser = ASN1Parser(privateKeyBytes);
    final privateKeySeq = privateKeyParser.nextObject() as ASN1Sequence;

    // Extrahiere die PKCS#1-Schlüsselparameter
    final modulusASN1 = privateKeySeq.elements![1] as ASN1Integer; // n
    final privateExponentASN1 = privateKeySeq.elements![3] as ASN1Integer; // d
    final prime1ASN1 = privateKeySeq.elements![4] as ASN1Integer; // p
    final prime2ASN1 = privateKeySeq.elements![5] as ASN1Integer; // q

    // Konvertiere die Werte in BigInt
    final modulus = _bytesToBigInt(modulusASN1.valueBytes!);
    final privateExponent = _bytesToBigInt(privateExponentASN1.valueBytes!);
    final prime1 = _bytesToBigInt(prime1ASN1.valueBytes!);
    final prime2 = _bytesToBigInt(prime2ASN1.valueBytes!);

    // Erstelle den `RSAPrivateKey`
    return RSAPrivateKey(modulus, privateExponent, prime1, prime2);
  }

  /// Konvertiert ein Byte-Array in ein BigInt-Objekt.
  /// 
  /// Diese private Hilfsmethode konvertiert die Bytes eines ASN.1-Integer-Werts
  /// in ein BigInt-Objekt, das für RSA-Berechnungen verwendet werden kann.
  /// Die Konvertierung erfolgt über Hexadezimal-Darstellung.
  /// 
  /// Parameter:
  /// - [bytes]: Die zu konvertierenden Bytes
  /// 
  /// Rückgabe: BigInt-Darstellung der Bytes
  BigInt _bytesToBigInt(Uint8List bytes) {
    return BigInt.parse(bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(), radix: 16);
  }
}

/// Erweiterung für `RSAPublicKey` zur Konvertierung in das PEM-Format.
/// 
/// Diese Extension erweitert die RSAPublicKey-Klasse um die Funktionalität,
/// einen RSA-öffentlichen Schlüssel in das standardisierte PEM-Format zu
/// konvertieren. Dies ist nützlich für den Austausch von Schlüsseln oder
/// die Speicherung in Dateien.
/// 
/// **Ausgabeformat:**
/// - SPKI (Subject Public Key Info) Struktur
/// - Base64-Kodierung mit PEM-Headern und -Footern
/// - 64-Zeichen-Zeilenlänge für bessere Lesbarkeit
/// 
/// **Verwendung:**
/// ```dart
/// RSAPublicKey publicKey = ...;
/// String pemString = publicKey.encodeToPem();
/// print(pemString); // -----BEGIN PUBLIC KEY-----\n...
/// ```
extension RSAPublicKeyExtention on RSAPublicKey {
  /// Konvertiert den RSA-öffentlichen Schlüssel in das PEM-Format.
  /// 
  /// Diese Methode erstellt eine ASN.1-Struktur entsprechend dem SPKI-Standard
  /// und konvertiert sie in das PEM-Format mit entsprechenden Headern und Footern.
  /// Das resultierende Format ist kompatibel mit OpenSSL und anderen
  /// kryptographischen Bibliotheken.
  /// 
  /// Rückgabe: PEM-formatierter String des öffentlichen Schlüssels
  /// 
  /// Die Ausgabe enthält die standard PEM-Header "-----BEGIN PUBLIC KEY-----"
  /// und "-----END PUBLIC KEY-----" mit dem Base64-kodierten Schlüsselmaterial
  /// dazwischen, aufgeteilt in 64-Zeichen-Zeilen.
  String encodeToPem() {
    // Erstelle ASN.1-Objekte für Modulus und Exponent
    final asn1Modulus = ASN1Integer(modulus!);
    final asn1Exponent = ASN1Integer(exponent!);

    // Erstelle die ASN.1-Sequenz, die Modulus und Exponent enthält
    final asn1Seq = ASN1Sequence();
    asn1Seq.add(asn1Modulus);
    asn1Seq.add(asn1Exponent);

    // Kodieren der `publicKey`-Bytes in einen BitString
    final publicKeyBytes = asn1Seq.encode();

    // Verpacke die `publicKeyBytes` in einen BitString
    final publicKeyBitString = ASN1BitString(stringValues: publicKeyBytes);

    // Erstelle die Algorithmen-Sequenz
    final algorithmSeq = ASN1Sequence();
    algorithmSeq.add(ASN1ObjectIdentifier.fromName("rsaEncryption"));
    algorithmSeq.add(ASN1Null());

    // Erstelle die oberste ASN.1-Sequenz, die den Algorithmus und den Schlüssel enthält
    final topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeyBitString);

    // Kodierung der Top-Level-Sequenz in Base64
    final base64Key = base64Encode(topLevelSeq.encode());

    // Erstelle das PEM-Format
    final pemString = """
    -----BEGIN PUBLIC KEY-----
    ${_chunked(base64Key, 64)}
    -----END PUBLIC KEY-----
    """;

    return pemString;
  }

  /// Teilt einen Base64-String in Zeilen mit einer bestimmten maximalen Länge auf.
  /// 
  /// Diese private Hilfsmethode formatiert den Base64-String so, dass er den
  /// PEM-Konventionen entspricht, bei denen jede Zeile maximal 64 Zeichen lang ist.
  /// 
  /// Parameter:
  /// - [str]: Der zu formatierende Base64-String
  /// - [chunkSize]: Die maximale Zeilenlänge (Standard: 64)
  /// 
  /// Rückgabe: Formatierter String mit Zeilenumbrüchen
  String _chunked(String str, int chunkSize) {
    final RegExp pattern = RegExp('.{1,$chunkSize}');
    return pattern.allMatches(str).map((m) => m.group(0)).join('\r\n');
  }
}

/// Erweiterung für `Uint8List` zur Hexadezimal-Konvertierung.
/// 
/// Diese Extension erweitert die Uint8List-Klasse um eine praktische Methode
/// zur Konvertierung von Byte-Arrays in Hexadezimal-Strings. Dies ist besonders
/// nützlich für Debugging, Logging und die Darstellung von kryptographischen
/// Daten in lesbarer Form.
/// 
/// **Verwendung:**
/// ```dart
/// Uint8List bytes = Uint8List.fromList([0x41, 0x42, 0x43]);
/// String hex = bytes.bytesToHex(); // "414243"
/// ```
extension Uint8ListExtention on Uint8List {
  /// Konvertiert die Bytes in einen Hexadezimal-String.
  /// 
  /// Diese Methode durchläuft alle Bytes im Array und konvertiert jeden Byte-Wert
  /// in seine zweistellige Hexadezimal-Darstellung. Führende Nullen werden
  /// beibehalten, um eine einheitliche Formatierung zu gewährleisten.
  /// 
  /// Rückgabe: Hexadezimal-String ohne Trennzeichen (z.B. "41424344" für [0x41, 0x42, 0x43, 0x44])
  /// 
  /// Die Ausgabe enthält nur die Hexadezimal-Zeichen 0-9 und a-f ohne Präfix
  /// oder Trennzeichen. Jeder Byte wird als genau zwei Zeichen dargestellt.
  String bytesToHex() {
    return map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
}
