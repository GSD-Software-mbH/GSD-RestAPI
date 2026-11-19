import 'dart:typed_data';

import 'package:gsd_restapi/src/runtime/transport/upload_platform.dart';

/// Eine Datei für den Upload, entweder als Pfad oder als Bytes.
class GsdUploadFile {
  /// Erstellt eine Upload-Datei; genau eins von [path] und [bytes] ist gesetzt.
  ///
  /// Wirft [UnsupportedError] für einen [path] im Web.
  GsdUploadFile({required this.name, this.path, this.bytes})
    : assert(
        (path != null && bytes == null) || (path == null && bytes != null),
        'Either path or bytes must be provided, but not both',
      ) {
    if (path != null) _requireFilePaths();
  }

  /// Erstellt eine Upload-Datei aus einem Dateipfad (Mobile, Desktop).
  ///
  /// Der Name ist der letzte Pfadbestandteil. Wirft [UnsupportedError] im
  /// Web; dort [GsdUploadFile.fromBytes] verwenden.
  GsdUploadFile.fromPath({required String this.path})
    : bytes = null,
      name = path.split(RegExp(r'[/\\]')).last {
    _requireFilePaths();
  }

  /// Erstellt eine Upload-Datei aus Bytes (Web).
  GsdUploadFile.fromBytes({
    required this.name,
    required Uint8List this.bytes,
  }) : path = null;

  /// Dateiname.
  String name;

  /// Pfad der Datei; `null` bei einer Datei aus Bytes.
  final String? path;

  /// Inhalt der Datei; `null` bei einer Datei aus einem Pfad.
  final Uint8List? bytes;

  /// Ob die Datei über einen Pfad angegeben ist.
  bool get isPath => path != null;

  /// Ob die Datei als Bytes angegeben ist.
  bool get isBytes => bytes != null;

  static void _requireFilePaths() {
    if (!UploadPlatform.readsFilePaths) {
      throw UnsupportedError(
        'GsdUploadFile with a path is not supported on this platform; '
        'use GsdUploadFile.fromBytes.',
      );
    }
  }
}
