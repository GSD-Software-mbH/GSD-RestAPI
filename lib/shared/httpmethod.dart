part of '../gsd_restapi.dart';

/// Enum für unterstützte HTTP-Methoden.
///
/// Wird sowohl vom Legacy-Manager als auch von den weiterhin öffentlichen
/// HTTP-Metriken des neuen Runtime verwendet.
enum HttpMethod {
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
}
