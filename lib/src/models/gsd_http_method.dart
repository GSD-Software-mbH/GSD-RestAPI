import 'package:gsd_restapi/src/raw/gsd_raw_api.dart';

/// HTTP-Methode für einen [GsdRawApi]-Request oder eine interne `ApiRequest`.
///
/// Bildet die von der DOCUframe-API unterstützten Methoden ab. Der
/// Enum-Name entspricht (in Großschreibung) direkt der HTTP-Methode und wird
/// intern zur Transport-Konstruktion verwendet.
enum GsdHttpMethod {
  /// GET-Anfrage zum Abrufen von Daten.
  get,

  /// POST-Anfrage zum Erstellen neuer Ressourcen.
  post,

  /// PUT-Anfrage zum vollständigen Ersetzen einer Ressource.
  put,

  /// PATCH-Anfrage zum teilweisen Aktualisieren einer Ressource.
  patch,

  /// DELETE-Anfrage zum Löschen einer Ressource.
  delete,

  /// HEAD-Anfrage zum Abrufen von Headern ohne Response-Body.
  head,
}
