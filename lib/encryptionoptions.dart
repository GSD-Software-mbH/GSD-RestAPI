part of 'gsd_encryption.dart';

/// Konfigurationsklasse für die Initialisierung des EncryptionManagers.
/// 
/// Diese Klasse kapselt alle notwendigen Konfigurationsdaten, die für die
/// Initialisierung des EncryptionManagers benötigt werden. Sie ermöglicht es,
/// sowohl AES- als auch RSA-Schlüssel aus verschiedenen Quellen zu laden.
/// 
/// **Unterstützte Konfigurationen:**
/// - **RSA-Schlüssel**: Pfade zu PEM-Dateien (öffentlicher und privater Schlüssel)
/// - **AES-Schlüssel**: Direkte Übergabe von Schlüssel-Bytes
/// - **Plattformübergreifend**: Unterstützung für Web- und Native-Plattformen
/// 
/// **Verwendungsbeispiele:**
/// ```dart
/// // RSA-Schlüssel aus Assets laden
/// final options = EncryptionOptions(
///   rsaPublicKeyFilePath: "assets/keys/public.pem",
///   rsaPrivateKeyFilePath: "assets/keys/private.pem"
/// );
/// 
/// // Vordefinierten AES-Schlüssel verwenden
/// final aesBytes = List<int>.generate(32, (i) => i); // Beispiel-Bytes
/// final options = EncryptionOptions(aesKeyBytes: aesBytes);
/// 
/// // Kombination von RSA- und AES-Schlüsseln
/// final options = EncryptionOptions(
///   rsaPublicKeyFilePath: "cert/public.pem",
///   rsaPrivateKeyFilePath: "cert/private.pem",
///   aesKeyBytes: mySecretKeyBytes
/// );
/// ```
/// 
/// **Hinweise:**
/// - Auf nativen Plattformen werden RSA-Schlüssel aus Dateien gelesen
/// - Auf Web-Plattformen werden sie aus Flutter-Assets geladen
/// - Leere Pfade führen zur automatischen Schlüsselgenerierung
/// - AES-Schlüssel sollten 32 Bytes (256-Bit) für maximale Sicherheit haben
class EncryptionOptions {

  /// Getter für den Pfad zur RSA-Privatschlüssel-Datei.
  /// 
  /// Rückgabe: Der Dateipfad zum privaten RSA-Schlüssel im PEM-Format
  /// 
  /// Auf nativen Plattformen sollte dies ein absoluter oder relativer Dateipfad sein.
  /// Auf Web-Plattformen sollte dies ein Asset-Pfad sein (z.B. "assets/private.pem").
  String get rsaPrivateKeyFilePath {
    return _rsaPrivateKeyFilePath;
  }

  /// Getter für den Pfad zur RSA-Öffentlichschlüssel-Datei.
  /// 
  /// Rückgabe: Der Dateipfad zum öffentlichen RSA-Schlüssel im PEM-Format
  /// 
  /// Auf nativen Plattformen sollte dies ein absoluter oder relativer Dateipfad sein.
  /// Auf Web-Plattformen sollte dies ein Asset-Pfad sein (z.B. "assets/public.pem").
  String get rsaPublicKeyFilePath {
    return _rsaPublicKeyFilePath;
  }

  /// Getter für die AES-Schlüssel-Bytes.
  /// 
  /// Rückgabe: Liste der Bytes, die als AES-Schlüssel verwendet werden sollen
  /// 
  /// Für AES-256 sollten dies 32 Bytes sein. Wenn die Liste leer ist,
  /// wird ein neuer Schlüssel automatisch generiert und im sicheren Speicher abgelegt.
  List<int> get aesKeyBytes {
    return _aesKeyBytes;
  }

  String _rsaPublicKeyFilePath = "";
  String _rsaPrivateKeyFilePath = "";
  List<int> _aesKeyBytes = [];

  /// Konstruktor für EncryptionOptions.
  /// 
  /// Ermöglicht die Konfiguration von RSA- und AES-Schlüsseln für den EncryptionManager.
  /// Alle Parameter sind optional und haben sinnvolle Standardwerte.
  /// 
  /// Parameter:
  /// - [rsaPrivateKeyFilePath]: Pfad zur privaten RSA-Schlüssel-Datei (PEM-Format)
  /// - [rsaPublicKeyFilePath]: Pfad zur öffentlichen RSA-Schlüssel-Datei (PEM-Format)
  /// - [aesKeyBytes]: Bytes für den AES-Schlüssel (sollten 32 Bytes für AES-256 sein)
  /// 
  /// **Beispiele:**
  /// ```dart
  /// // Nur RSA-Schlüssel konfigurieren
  /// EncryptionOptions(
  ///   rsaPublicKeyFilePath: "assets/public.pem",
  ///   rsaPrivateKeyFilePath: "assets/private.pem"
  /// )
  /// 
  /// // Nur AES-Schlüssel konfigurieren
  /// EncryptionOptions(aesKeyBytes: myKeyBytes)
  /// 
  /// // Beide Schlüsseltypen konfigurieren
  /// EncryptionOptions(
  ///   rsaPublicKeyFilePath: "cert/public.pem",
  ///   rsaPrivateKeyFilePath: "cert/private.pem",
  ///   aesKeyBytes: myKeyBytes
  /// )
  /// ```
  EncryptionOptions({String rsaPrivateKeyFilePath = "", String rsaPublicKeyFilePath = "", List<int> aesKeyBytes = const []}) {
    _rsaPrivateKeyFilePath = rsaPrivateKeyFilePath;
    _rsaPublicKeyFilePath = rsaPublicKeyFilePath;
    _aesKeyBytes = aesKeyBytes;
  }
}