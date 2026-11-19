import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/gsd_docuframe_database.dart';
import 'package:gsd_restapi/src/models/gsd_docuframe_module.dart';
import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_check_service_result.g.dart';

/// Das Ergebnis von `v1.service.checkService` und `checkServiceWithUri`:
/// Anwendung, Version und Datenbanken des Service.
@JsonSerializable(createToJson: false)
class GsdCheckServiceResult extends Equatable {
  /// Erstellt ein Ergebnis.
  const GsdCheckServiceResult({
    this.applicationName = '',
    this.applicationVersion = '',
    this.databases = const [],
  });

  /// Liest das Ergebnis aus `data`; fehlende Werte ergeben `''` bzw. eine
  /// leere Liste.
  factory GsdCheckServiceResult.fromJson(Map<String, Object?> json) =>
      _$GsdCheckServiceResultFromJson(json);

  /// Name der Anwendung, etwa `GSD-RestApi`.
  @JsonKey(defaultValue: '')
  final String applicationName;

  /// Version des Webservice (`webservice.version`); ohne `webservice` die
  /// `applicationVersion` der Antwort.
  @JsonKey(readValue: _readApplicationVersion, defaultValue: '')
  final String applicationVersion;

  /// Die Datenbanken mit ihren Modulen, aus `webservice.moduleVersion`.
  @JsonKey(name: 'webservice', fromJson: _databasesFromWebservice)
  final List<GsdDocuframeDatabase> databases;

  @override
  List<Object?> get props => [applicationName, applicationVersion, databases];

  static Object? _readApplicationVersion(
    Map<dynamic, dynamic> json,
    String key,
  ) => switch (json['webservice']) {
    final Map<dynamic, dynamic> webservice => webservice['version'],
    _ => json[key],
  };

  static List<GsdDocuframeDatabase> _databasesFromWebservice(
    Object? webservice,
  ) {
    if (webservice == null) {
      return const [];
    }
    return ModelJson.object(webservice, 'webservice', (json) {
      final moduleVersion = json['moduleVersion'];
      if (moduleVersion == null) {
        return const <GsdDocuframeDatabase>[];
      }
      return ModelJson.object(moduleVersion, 'moduleVersion', (databases) {
        return <GsdDocuframeDatabase>[
          for (final MapEntry(:key, :value) in databases.entries)
            GsdDocuframeDatabase(
              key,
              ModelJson.list(value, key, GsdDocuframeModule.fromJson),
            ),
        ];
      });
    });
  }
}
