import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/gsd_sync_data_class.dart';
import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_sync_container.g.dart';

/// Ein Sync-Container aus der Antwort eines Synchronisations-Endpunkts.
///
/// Zahlen dürfen auch als String kommen; fehlende Werte ergeben `0`, `''`,
/// `false` bzw. eine leere Liste.
@JsonSerializable()
class GsdSyncContainer extends Equatable {
  /// Erstellt einen Sync-Container.
  const GsdSyncContainer({
    required this.containerId,
    required this.revision,
    required this.nextMarker,
    this.contentId = '',
    this.readOnly = false,
    this.count = 0,
    this.startMarker = 0,
    this.endMarker = 0,
    this.hasMoreData = false,
    this.classes = const [],
    this.excluded = const [],
    this.deleted = const [],
  });

  /// Erstellt einen Sync-Container aus dem JSON der API-Antwort.
  factory GsdSyncContainer.fromJson(Map<String, Object?> json) =>
      _$GsdSyncContainerFromJson(json);

  /// ID des Containers.
  @JsonKey(defaultValue: '')
  final String containerId;

  /// Inhalts-ID des Containers.
  @JsonKey(defaultValue: '')
  final String contentId;

  /// Ob der Container nur lesbar ist.
  @JsonKey(defaultValue: false)
  final bool readOnly;

  /// Anzahl der Datensätze im Container.
  @JsonKey(fromJson: ModelJson.intValue)
  final int count;

  /// Revision des Containers.
  @JsonKey(fromJson: ModelJson.intValue)
  final int revision;

  /// Marker, ab dem diese Antwort Daten enthält.
  @JsonKey(fromJson: ModelJson.intValue)
  final int startMarker;

  /// Marker, bis zu dem diese Antwort Daten enthält.
  @JsonKey(fromJson: ModelJson.intValue)
  final int endMarker;

  /// Marker für die nächste Abfrage.
  @JsonKey(fromJson: ModelJson.intValue)
  final int nextMarker;

  /// Ob der Server weitere Daten bereithält.
  @JsonKey(defaultValue: false)
  final bool hasMoreData;

  /// Die Datenklassen des Containers.
  @JsonKey(fromJson: _classesFromJson)
  final List<GsdSyncDataClass> classes;

  /// Ausgeschlossene Einträge, wie vom Server geliefert.
  final List<dynamic> excluded;

  /// Gelöschte Einträge, wie vom Server geliefert.
  final List<dynamic> deleted;

  /// Wandelt den Container in JSON um.
  Map<String, dynamic> toJson() => _$GsdSyncContainerToJson(this);

  @override
  List<Object?> get props => [
    containerId,
    contentId,
    readOnly,
    count,
    revision,
    startMarker,
    endMarker,
    nextMarker,
    hasMoreData,
    classes,
    excluded,
    deleted,
  ];

  static List<GsdSyncDataClass> _classesFromJson(Object? json) =>
      ModelJson.list(json, 'classes', GsdSyncDataClass.fromJson);
}
