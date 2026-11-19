import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/gsd_sync_container.dart';
import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_sync_objects_result.g.dart';

/// Das Ergebnis von `v1.xSync.getSyncObjectsOfClass`.
///
/// `data` der Antwort nennt in `allContainers` die Container-IDs und trägt
/// je ID einen Container unter dieser ID.
@JsonSerializable(createToJson: false)
class GsdSyncObjectsResult extends Equatable {
  /// Erstellt ein Ergebnis.
  const GsdSyncObjectsResult({
    this.allContainers = const [],
    this.containers = const {},
    this.data = const {},
  });

  /// Liest das Ergebnis aus `data`.
  factory GsdSyncObjectsResult.fromJson(Map<String, Object?> json) =>
      _$GsdSyncObjectsResultFromJson(json);

  /// IDs aller Container der Klasse.
  final List<String> allContainers;

  /// Die Container aus [allContainers], die die Antwort enthält, je ID.
  @JsonKey(readValue: _readContainers, fromJson: _containersFromJson)
  final Map<String, GsdSyncContainer> containers;

  /// `data` der Antwort, unverändert.
  @JsonKey(readValue: _readData)
  final Map<String, Object?> data;

  @override
  List<Object?> get props => [allContainers, containers, data];

  static Object? _readContainers(Map<dynamic, dynamic> json, String key) =>
      <String, Object?>{
        for (final id in (json['allContainers'] as List<Object?>?) ?? const [])
          if (id is String && json.containsKey(id)) id: json[id],
      };

  static Map<String, GsdSyncContainer> _containersFromJson(Object? json) =>
      (json! as Map<String, Object?>).map(
        (id, container) => MapEntry(
          id,
          ModelJson.object(container, id, GsdSyncContainer.fromJson),
        ),
      );

  static Object? _readData(Map<dynamic, dynamic> json, String key) => json;
}
