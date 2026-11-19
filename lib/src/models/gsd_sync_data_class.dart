import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_sync_data_class.g.dart';

/// Daten einer Klasse innerhalb eines Sync-Containers.
@JsonSerializable()
class GsdSyncDataClass extends Equatable {
  /// Erstellt eine Sync-Datenklasse.
  const GsdSyncDataClass({
    required this.className,
    required this.count,
    required this.header,
    required this.data,
  });

  /// Erstellt eine Sync-Datenklasse aus dem JSON der API-Antwort.
  factory GsdSyncDataClass.fromJson(Map<String, Object?> json) =>
      _$GsdSyncDataClassFromJson(json);

  /// Name der Klasse.
  @JsonKey(defaultValue: '')
  final String className;

  /// Anzahl der Datensätze.
  @JsonKey(fromJson: ModelJson.intValue)
  final int count;

  /// Spaltennamen der Datensätze.
  @JsonKey(defaultValue: <String>[])
  final List<String> header;

  /// Die Datensätze, je Zeile eine Liste von Werten passend zu [header].
  @JsonKey(defaultValue: <List<dynamic>>[])
  final List<List<dynamic>> data;

  /// Wandelt die Datenklasse in JSON um.
  Map<String, dynamic> toJson() => _$GsdSyncDataClassToJson(this);

  @override
  List<Object?> get props => [className, count, header, data];
}
