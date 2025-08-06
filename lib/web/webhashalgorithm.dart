import 'dart:js_interop';

// Hash-Algorithmus konfigurieren
@JS()
@anonymous
extension type HashAlgorithm._(JSObject _) implements JSObject {
  external factory HashAlgorithm({String name});
}