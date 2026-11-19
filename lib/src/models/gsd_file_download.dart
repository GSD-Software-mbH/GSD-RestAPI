import 'dart:typed_data';

import 'package:equatable/equatable.dart';

/// Eine heruntergeladene Datei: die unveränderten Bytes und die Header der
/// Antwort.
///
/// Die Header tragen etwa `content-type` und `content-disposition`
/// (Dateiname); ihre Namen sind kleingeschrieben.
class GsdFileDownload extends Equatable {
  /// Erstellt einen Download aus [bytes] und [headers].
  const GsdFileDownload({required this.bytes, this.headers = const {}});

  /// Inhalt der Datei.
  final Uint8List bytes;

  /// Header der Antwort, Namen kleingeschrieben.
  final Map<String, String> headers;

  @override
  List<Object?> get props => [bytes, headers];
}
