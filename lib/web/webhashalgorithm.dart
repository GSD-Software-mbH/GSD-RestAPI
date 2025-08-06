import 'dart:js_interop';

/// Extension Type für Hash-Algorithmus-Konfiguration der Web Crypto API.
/// 
/// Diese Klasse stellt eine typisierte Schnittstelle zu den Hash-Algorithmus-Optionen
/// dar, die von der Web Crypto API für verschiedene kryptographische Operationen
/// verwendet werden. Sie ist speziell für die Konfiguration von OAEP-Padding
/// bei RSA-Verschlüsselung konzipiert.
/// 
/// **Unterstützte Hash-Algorithmen:**
/// - **SHA-1**: Weniger sicher, nur für Legacy-Kompatibilität
/// - **SHA-256**: Empfohlener Standard für die meisten Anwendungen
/// - **SHA-384**: Höhere Sicherheit für kritische Anwendungen
/// - **SHA-512**: Maximale Sicherheit mit höherem Overhead
/// 
/// **Verwendung:**
/// Diese Klasse wird intern von WebRSAEncryptionManager und GenerateKeyOptions
/// verwendet, um den Hash-Algorithmus für RSA-OAEP-Operationen zu spezifizieren.
/// 
/// **Beispiel:**
/// ```dart
/// final hashAlgorithm = HashAlgorithm(name: 'SHA-256');
/// ```
@JS()
@anonymous
extension type HashAlgorithm._(JSObject _) implements JSObject {
  external factory HashAlgorithm({String name});
}