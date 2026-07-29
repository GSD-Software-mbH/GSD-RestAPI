import 'dart:async';

import 'package:meta/meta.dart';

import '../transport_response.dart';

/// Übersetzt eine transport-nahe [TransportResponse] in das Ergebnis eines
/// Requests.
///
/// Diese Schnittstelle ist die Naht für die späteren versionsspezifischen
/// Response-Pipelines (`V1ResponsePipeline`/`V2ResponsePipeline` inkl.
/// Fehler-Mapping, PR 4/5). In dieser Ausbaustufe existiert nur die
/// Durchreich-Implementierung `RawResponsePolicy`.
@internal
abstract interface class ResponsePolicy<T> {
  /// Dekodiert die Antwort. Darf bei fachlichen Fehlern eine Exception
  /// werfen (versionsabhängig, ab PR 4/5).
  FutureOr<T> decode(TransportResponse response);
}
