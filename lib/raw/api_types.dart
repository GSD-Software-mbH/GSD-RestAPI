/// HTTP-Methode für einen [RawApi]-Request oder eine interne `ApiRequest`.
///
/// Bildet die von der DOCUframe-API unterstützten Methoden ab. Der
/// Enum-Name entspricht (in Großschreibung) direkt der HTTP-Methode und wird
/// intern zur Transport-Konstruktion verwendet.
enum ApiHttpMethod {
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

/// Version der nativen DOCUframe-REST-API.
///
/// Wählt das URL-Präfix (`v1`/`v2`) und - in den künftigen
/// Response-Pipelines (Task 4/5) - die versionsspezifische
/// Deserialisierung und Fehlerbehandlung.
enum ApiVersion {
  /// Bestehende, dokumentierte V1-API.
  v1,

  /// Neue, native V2-API.
  v2,
}
