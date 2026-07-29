import 'package:meta/meta.dart';

/// Priorität eines Requests gegenüber dem Multi-Request-Buffering des
/// `BatchCoordinator`.
///
/// Heißt bewusst NICHT `RequestPriority`: Das (öffentliche) Legacy-`gsd_
/// restapi.dart` definiert bereits ein gleichnamiges `RequestPriority`-Enum
/// für die Zone-basierte Priorität des `RestApiDOCUframeManager`. Da der
/// neue Runtime `gsd_restapi.dart` weiterhin für bestehende Response-/
/// Exception-Typen importiert, würde ein zweites `RequestPriority` in
/// derselben Datei zu einer Namenskollision führen.
///
/// Anders als der Legacy-Manager - der PRO Priorität einen eigenen
/// Buffer führte und beim Flush einer `high`-Priority-Buffer-Runde nur
/// `requestsToProcess.first` erneut sendete, während alle weiteren in
/// derselben Runde gepufferten High-Priority-Requests unbeantwortet
/// blieben (siehe `RestApiDOCUframeManager._flushPriorityRequestBuffer`) -
/// kennt der neue `BatchCoordinator` GAR KEINEN High-Priority-Buffer:
/// [high] wird immer sofort als Einzelanfrage gesendet und nie gepuffert.
/// Es kann daher auch kein High-Priority-Request beim Flush verloren
/// gehen. [low] und [normal] besitzen jeweils einen eigenen Buffer und einen
/// eigenen Flush-Timer.
@internal
enum ApiRequestPriority {
  /// Niedrige Priorität; eigener Buffer und eigener Flush-Timer.
  low,

  /// Normale Priorität (Standard); eigener Buffer und eigener Flush-Timer.
  normal,

  /// Hohe Priorität: wird NIE gepuffert (auch nicht bei einem ansonsten
  /// Multi-Request-fähigen Endpunkt) - immer sofortige Einzelanfrage.
  high,
}
