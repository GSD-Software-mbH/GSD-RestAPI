part of 'gsd_restapi.dart';

/// Wrapper-Klasse für HTTP-Anfragen an die REST-API
/// 
/// Diese Klasse kapselt eine HTTP-Response und verwaltet zusätzliche Metadaten
/// über die Anfrage, wie z.B. ob es sich um einen Login-Request handelt.
class RestApiRequest {
  /// Das Future, das die HTTP-Response enthält
  /// 
  /// Dieses Future wird aufgelöst, wenn die HTTP-Anfrage abgeschlossen ist.
  Future<http.Response> response;
  
  /// Kennzeichnet, ob es sich um eine Login-Anfrage handelt
  /// 
  /// Login-Anfragen werden speziell behandelt, um Duplikate zu vermeiden.
  bool login;

  /// Erstellt eine neue RestApiRequest-Instanz
  /// 
  /// [response] - Das Future mit der HTTP-Response
  /// [login] - Optional: Kennzeichnet Login-Anfragen (Standard: false)
  RestApiRequest(this.response, {this.login = false});
}
