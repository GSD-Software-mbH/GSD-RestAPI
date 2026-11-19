import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:json_annotation/json_annotation.dart';
import 'package:test/test.dart';

/// Modell wie aus `json_serializable` mit `checked: true`: Ein fehlendes
/// `Oid` meldet sich als [CheckedFromJsonException] mit dem Schlüssel.
class _Entry {
  const _Entry(this.oid);

  factory _Entry.fromJson(Map<String, Object?> json) {
    final oid = json['Oid'];
    if (oid is! String) {
      throw CheckedFromJsonException(json, 'Oid', '_Entry', 'Oid fehlt');
    }
    return _Entry(oid);
  }

  final String oid;
}

Matcher _throwsChecked({
  required String? key,
  required String className,
  required String message,
}) => throwsA(
  isA<CheckedFromJsonException>()
      .having((e) => e.key, 'key', key)
      .having((e) => e.className, 'className', className)
      .having((e) => e.message, 'message', message),
);

void main() {
  group('ModelJson.object', () {
    test('baut das Modell über fromJson', () {
      final entry = ModelJson.object({'Oid': '1'}, 'acl', _Entry.fromJson);

      expect(entry.oid, '1');
    });

    for (final json in <Object?>[null, 'text', 42, <Object?>[]]) {
      test('$json ist kein Objekt: Fehler am äußeren Schlüssel', () {
        expect(
          () => ModelJson.object(json, 'acl', _Entry.fromJson),
          _throwsChecked(
            key: 'acl',
            className: '_Entry',
            message: 'kein Objekt',
          ),
        );
      });
    }

    test('setzt den äußeren Schlüssel vor den des inneren Felds', () {
      expect(
        () => ModelJson.object(
          <String, Object?>{'Oid': 7},
          'acl',
          _Entry.fromJson,
        ),
        _throwsChecked(
          key: 'acl.Oid',
          className: '_Entry',
          message: 'Oid fehlt',
        ),
      );
    });

    test('ohne inneren Schlüssel bleibt der äußere', () {
      expect(
        () => ModelJson.object<_Entry>(
          <String, Object?>{},
          'acl',
          (json) => throw CheckedFromJsonException(json, null, 'Inner', 'x'),
        ),
        _throwsChecked(key: 'acl', className: 'Inner', message: 'x'),
      );
    });

    test('andere Fehler aus fromJson laufen unverändert durch', () {
      expect(
        () => ModelJson.object<_Entry>(
          <String, Object?>{},
          'acl',
          (_) => throw StateError('kaputt'),
        ),
        throwsStateError,
      );
    });
  });

  group('ModelJson.list', () {
    test('null ergibt eine leere Liste', () {
      expect(ModelJson.list(null, 'acls', _Entry.fromJson), isEmpty);
    });

    test('baut jedes Element über fromJson', () {
      final entries = ModelJson.list(
        <Object?>[
          {'Oid': '1'},
          {'Oid': '2'},
        ],
        'acls',
        _Entry.fromJson,
      );

      expect(entries.map((e) => e.oid), ['1', '2']);
    });

    for (final json in <Object?>['text', 42, <String, Object?>{}]) {
      test('$json ist keine Liste: Fehler am Schlüssel der Liste', () {
        expect(
          () => ModelJson.list(json, 'acls', _Entry.fromJson),
          _throwsChecked(
            key: 'acls',
            className: '_Entry',
            message: 'keine Liste',
          ),
        );
      });
    }

    test('ein fehlerhaftes Element meldet Index und inneren Schlüssel', () {
      expect(
        () => ModelJson.list(
          <Object?>[
            {'Oid': '1'},
            {'Oid': 2},
          ],
          'acls',
          _Entry.fromJson,
        ),
        _throwsChecked(
          key: 'acls[1].Oid',
          className: '_Entry',
          message: 'Oid fehlt',
        ),
      );
    });

    test('ein null-Element wirft ohne skipNulls', () {
      expect(
        () => ModelJson.list(
          <Object?>[
            {'Oid': '1'},
            null,
          ],
          'acls',
          _Entry.fromJson,
        ),
        _throwsChecked(
          key: 'acls[1]',
          className: '_Entry',
          message: 'kein Objekt',
        ),
      );
    });

    test('mit skipNulls fallen null-Elemente weg', () {
      final entries = ModelJson.list(
        <Object?>[
          null,
          {'Oid': '1'},
          null,
          {'Oid': '2'},
        ],
        'acls',
        _Entry.fromJson,
        skipNulls: true,
      );

      expect(entries.map((e) => e.oid), ['1', '2']);
    });

    test('mit skipNulls behält ein Fehler den ursprünglichen Index', () {
      expect(
        () => ModelJson.list(
          <Object?>[null, 'kein Objekt'],
          'acls',
          _Entry.fromJson,
          skipNulls: true,
        ),
        _throwsChecked(
          key: 'acls[1]',
          className: '_Entry',
          message: 'kein Objekt',
        ),
      );
    });
  });

  group('ModelJson.intValue', () {
    final cases = <String, (Object?, int)>{
      'null': (null, 0),
      'int': (7, 7),
      'Zahl als String': ('12', 12),
      'negative Zahl als String': ('-3', -3),
      'unlesbarer String': ('zwölf', 0),
      'leerer String': ('', 0),
    };
    for (final MapEntry(key: name, value: (json, expected)) in cases.entries) {
      test('$name ergibt $expected', () {
        expect(ModelJson.intValue(json), expected);
      });
    }

    test('ein anderer Typ wirft', () {
      expect(() => ModelJson.intValue(true), throwsA(isA<TypeError>()));
    });
  });

  group('ModelJson.dateTimeOrNull', () {
    test('null und "" ergeben null', () {
      expect(ModelJson.dateTimeOrNull(null), isNull);
      expect(ModelJson.dateTimeOrNull(''), isNull);
    });

    test('liest ISO 8601', () {
      expect(
        ModelJson.dateTimeOrNull('2026-10-26T12:30:00Z'),
        DateTime.utc(2026, 10, 26, 12, 30),
      );
    });

    test('ein unlesbarer String wirft FormatException', () {
      expect(
        () => ModelJson.dateTimeOrNull('gestern'),
        throwsFormatException,
      );
    });
  });
}
