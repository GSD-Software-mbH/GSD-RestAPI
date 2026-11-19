import 'package:json_annotation/json_annotation.dart';
import 'package:meta/meta.dart';

/// Konverter für die Antwortmodelle (`json_serializable` mit `checked: true`).
///
/// Verschachtelte Modelle melden einen Fehler als [CheckedFromJsonException]
/// mit dem Schlüssel des inneren Felds. [object] und [list] setzen den
/// Schlüssel des äußeren Felds und den Listenindex davor, etwa
/// `acls.~Elements[1].Oid`; `ModelResponsePolicy` macht daraus den `path`
/// der `GsdParseException`.
@internal
abstract final class ModelJson {
  /// Baut aus [json] ein Modell über [fromJson]. [key] ist die Stelle von
  /// [json] im umgebenden Objekt.
  static T object<T>(
    Object? json,
    String key,
    T Function(Map<String, Object?> json) fromJson,
  ) {
    if (json is! Map<String, Object?>) {
      throw CheckedFromJsonException(
        const <String, Object?>{},
        key,
        '$T',
        'kein Objekt',
      );
    }
    try {
      return fromJson(json);
    } on CheckedFromJsonException catch (error) {
      final inner = error.key;
      throw CheckedFromJsonException(
        error.map,
        inner == null ? key : '$key.$inner',
        error.className ?? '$T',
        error.message,
      );
    }
  }

  /// Baut je Element von [json] ein Modell über [fromJson]; `null` ergibt
  /// eine leere Liste. [key] ist die Stelle der Liste im umgebenden Objekt.
  ///
  /// Mit [skipNulls] fallen `null`-Elemente weg, sonst wirft eines.
  static List<T> list<T>(
    Object? json,
    String key,
    T Function(Map<String, Object?> json) fromJson, {
    bool skipNulls = false,
  }) {
    if (json == null) {
      return <T>[];
    }
    if (json is! List<Object?>) {
      throw CheckedFromJsonException(
        const <String, Object?>{},
        key,
        '$T',
        'keine Liste',
      );
    }
    return <T>[
      for (var i = 0; i < json.length; i++)
        if (!skipNulls || json[i] != null)
          object(json[i], '$key[$i]', fromJson),
    ];
  }

  /// Eine Zahl, auch als String (`"12"`); `null` und ein unlesbarer String
  /// ergeben `0`.
  static int intValue(Object? json) => switch (json) {
    null => 0,
    final String text => int.tryParse(text) ?? 0,
    _ => json as int,
  };

  /// Ein Zeitpunkt nach ISO 8601; `null` und `""` ergeben `null`.
  static DateTime? dateTimeOrNull(Object? json) => switch (json) {
    null || '' => null,
    _ => DateTime.parse(json as String),
  };
}
