import 'package:meta/meta.dart';

/// Platzhalter für Plattformen ohne `dart.library.io` und ohne
/// `dart.library.js_interop`.
@internal
abstract final class UploadPlatform {
  /// Ohne `dart.library.io` gibt es keinen Dateipfad zum Lesen.
  static const bool readsFilePaths = false;
}
