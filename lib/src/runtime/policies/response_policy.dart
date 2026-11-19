import 'dart:async';

import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Übersetzt eine transport-nahe [TransportResponse] in das Ergebnis eines
/// Requests.
///
/// Policies mit Umschlag werten ihn über `ResponseEnvelope` aus
/// (`DataResponsePolicy`, `ModelResponsePolicy`);
/// `RawSessionAwareResponsePolicy` reicht die Antwort durch.
@internal
// Bewusst eine Schnittstelle: Implementierungen werden als Policy-Objekte
// übergeben und per Identität verglichen.
// ignore: one_member_abstracts
abstract interface class IResponsePolicy<T> {
  /// Dekodiert die Antwort. Darf bei fachlichen Fehlern eine Exception
  /// werfen. [operationId] kennzeichnet den Endpunkt in einer
  /// `GsdParseException`.
  FutureOr<T> decode(TransportResponse response, {required String operationId});
}
