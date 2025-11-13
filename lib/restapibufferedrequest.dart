part of 'gsd_restapi.dart';

/// Gepufferte Anfrage für Multi-Request-Verarbeitung
///
/// Diese Klasse repräsentiert eine HTTP-Anfrage, die in einem Buffer
/// zwischengespeichert wird, um später als Teil eines Multi-Requests
/// verarbeitet zu werden. Sie enthält alle notwendigen Informationen
/// zur Wiederherstellung der ursprünglichen Anfrage.
///
/// Multi-Request-Verarbeitung ermöglicht es, mehrere API-Aufrufe
/// zu bündeln und in einer einzigen HTTP-Anfrage an den Server zu senden,
/// was die Performance und Netzwerkeffizienz verbessert.
class RestAPIBufferedRequest {
  /// Statischer Zähler für eindeutige Request-IDs
  ///
  /// Wird für jede neue Request-Instanz inkrementiert, um
  /// eindeutige Identifikatoren zu generieren.
  static int _idCounter = 0;

  /// Eindeutige Request-ID
  ///
  /// Kombiniert Zeitstempel und Zähler für eindeutige Identifikation.
  /// Format: 'req_{milliseconds}_{counter}'
  final String id =
      'req_${DateTime.now().millisecondsSinceEpoch}_${++_idCounter}';

  /// Vollständige URI der ursprünglichen Anfrage
  ///
  /// Enthält Schema, Host, Port, Pfad und Query-Parameter
  /// der ursprünglichen HTTP-Anfrage.
  final Uri requestUri;

  /// HTTP-Header der ursprünglichen Anfrage
  ///
  /// Kann null sein, wenn keine spezifischen Header gesetzt wurden.
  /// Standardheader werden vom RestApiManager automatisch hinzugefügt.
  final Map<String, String>? requestHeader;

  /// Request-Body der ursprünglichen Anfrage
  ///
  /// Kann verschiedene Typen enthalten (String, Map, etc.).
  /// Wird für POST/PUT-Anfragen verwendet.
  final dynamic body;

  /// HTTP-Methode der Anfrage
  ///
  /// Unterstützte Methoden: GET, POST, PUT, DELETE, etc.
  final HttpMethod method;

  /// API-Funktionsname
  ///
  /// Der spezifische Endpunkt-Name (z.B. 'v1/users', 'v2/documents').
  /// Wird zur Identifikation und Pfad-Rekonstruktion verwendet.
  final String function;

  /// Completer für die asynchrone Response-Behandlung
  ///
  /// Ermöglicht es, die ursprüngliche async-Anfrage zu vervollständigen,
  /// nachdem der Multi-Request verarbeitet wurde.
  final Completer<http.Response> completer;

  /// Zeitstempel der Request-Erstellung
  ///
  /// Wird für Debugging, Logging und potentielle Timeout-Behandlung verwendet.
  final DateTime timestamp;

  /// Erstellt eine neue gepufferte Anfrage
  ///
  /// Alle Parameter außer [requestHeader] sind erforderlich.
  /// Der Zeitstempel wird automatisch auf die aktuelle Zeit gesetzt.
  ///
  /// [requestUri] - Vollständige URI der ursprünglichen Anfrage
  /// [requestHeader] - Optionale HTTP-Header (kann null sein)
  /// [body] - Request-Body für POST/PUT-Anfragen
  /// [method] - HTTP-Methode der Anfrage
  /// [function] - API-Funktionsname/Endpunkt
  /// [completer] - Completer für die asynchrone Response-Behandlung
  RestAPIBufferedRequest({
    required this.requestUri,
    required this.requestHeader,
    required this.body,
    required this.method,
    required this.function,
    required this.completer,
  }) : timestamp = DateTime.now();

  /// Konvertiert die Anfrage zu Multi-Request-Format
  ///
  /// Transformiert die gepufferte Anfrage in das JSON-Format,
  /// das vom Multi-Request-Endpunkt erwartet wird.
  ///
  /// Das resultierende JSON-Objekt enthält:
  /// - 'method': HTTP-Methode in Großbuchstaben (GET, POST, etc.)
  /// - 'path': Relativer Pfad ab dem Funktionsnamen
  /// - 'data': Request-Body als JSON (nur wenn body nicht null ist)
  ///
  /// Der Pfad wird aus der vollständigen URI extrahiert, beginnend
  /// mit dem Funktionsnamen, um Redundanz zu vermeiden.
  ///
  /// Returns: Map mit Multi-Request-konformem JSON-Format
  ///
  /// Beispiel-Output:
  /// ```json
  /// {
  ///   "method": "POST",
  ///   "path": "/v1/users",
  ///   "data": {"name": "John", "email": "john@example.com"}
  /// }
  /// ```
  Map<String, dynamic> toMultiRequestJson() {
    // Vollständige URI in String umwandeln
    String path = requestUri.toString();

    // Pfad ab dem Funktionsnamen extrahieren
    // Entfernt Schema, Host, Port und behält nur den relevanten API-Pfad
    path = path.substring(path.indexOf("/$function"));

    // Basis-Request-Objekt erstellen
    Map<String, dynamic> request = {
      'method': method.name.toUpperCase(),
      'path': path,
    };

    // Request-Body hinzufügen, falls vorhanden
    // Body wird von String zu JSON-Objekt dekodiert
    if (body != null) {
      request['data'] = jsonDecode(body);
    }

    return request;
  }
}
