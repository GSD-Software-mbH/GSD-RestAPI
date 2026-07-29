// Unit-Tests für UriBuilder: Alias, Versions-Präfix, Pfad-Normalisierung,
// Query-Kodierung, qb64-Modus und "kein trailing ?" bei leerer Query.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/uri/uri_builder.dart';

import 'runtime_test_helpers.dart';

void main() {
  group('UriBuilder', () {
    test('builds an unversioned check route below the configured alias', () {
      final builder = UriBuilder(buildRuntimeConfiguration(alias: 'dfapp'));

      final uri = builder.buildTarget(
        target: const ApiRequestTarget.unversioned('/_CheckSession'),
      );

      expect(uri.toString(), 'https://server.example:8443/dfapp/_CheckSession');
    });

    test('keeps an absolute direct target byte-for-byte', () {
      final builder = UriBuilder(buildRuntimeConfiguration());
      final target = Uri.parse(
        'https://status.example:9443/root/_CheckService?probe=1',
      );

      final uri = builder.buildTarget(
        target: ApiRequestTarget.absolute(target),
      );

      expect(uri, target);
    });

    test('baut v1-URI mit Alias-Segment', () {
      final builder = UriBuilder(buildRuntimeConfiguration(alias: 'dfapp'));

      final uri = builder.build(version: ApiVersion.v1, path: '/object/OID1');

      expect(
        uri.toString(),
        equals('https://server.example:8443/dfapp/v1/object/OID1'),
      );
    });

    test('baut v2-URI mit Alias-Segment', () {
      final builder = UriBuilder(buildRuntimeConfiguration(alias: 'dfapp'));

      final uri = builder.build(
        version: ApiVersion.v2,
        path: '/model/structure',
      );

      expect(
        uri.toString(),
        equals('https://server.example:8443/dfapp/v2/model/structure'),
      );
    });

    test('leerer Alias entfernt das Alias-Segment vollständig', () {
      final builder = UriBuilder(buildRuntimeConfiguration(alias: ''));

      final uri = builder.build(version: ApiVersion.v1, path: '/object/OID1');

      expect(
        uri.toString(),
        equals('https://server.example:8443/v1/object/OID1'),
      );
    });

    test('Pfad ohne führenden Slash liefert dieselbe URI wie mit', () {
      final builder = UriBuilder(buildRuntimeConfiguration());

      final withSlash = builder.build(
        version: ApiVersion.v1,
        path: '/object/OID1',
      );
      final withoutSlash = builder.build(
        version: ApiVersion.v1,
        path: 'object/OID1',
      );

      expect(withoutSlash, equals(withSlash));
    });

    test('Server-URL mit Basis-Pfad wird vorangestellt', () {
      final builder = UriBuilder(
        buildRuntimeConfiguration(
          serverUrl: 'https://server.example:8443/gateway',
        ),
      );

      final uri = builder.build(version: ApiVersion.v1, path: '/ping');

      expect(
        uri.toString(),
        equals('https://server.example:8443/gateway/dfapp/v1/ping'),
      );
    });

    test('Server-URL mit trailing Slash erzeugt KEINE doppelten Slashes '
        '(identisch zur Variante ohne trailing Slash)', () {
      final withSlash = UriBuilder(
        buildRuntimeConfiguration(
          serverUrl: 'https://server.example:8443/gateway/',
        ),
      ).build(version: ApiVersion.v1, path: '/ping');
      final withoutSlash = UriBuilder(
        buildRuntimeConfiguration(
          serverUrl: 'https://server.example:8443/gateway',
        ),
      ).build(version: ApiVersion.v1, path: '/ping');

      expect(withSlash, equals(withoutSlash));
      expect(withSlash.toString(), isNot(contains('//dfapp')));
      expect(
        withSlash.toString(),
        equals('https://server.example:8443/gateway/dfapp/v1/ping'),
      );
    });

    test('Host-Root-URL mit trailing Slash erzeugt saubere Pfade', () {
      final builder = UriBuilder(
        buildRuntimeConfiguration(serverUrl: 'https://server.example/'),
      );

      final uri = builder.build(version: ApiVersion.v1, path: '/ping');

      expect(uri.toString(), equals('https://server.example/dfapp/v1/ping'));
    });

    test('Query-Parameter werden übernommen und kodiert', () {
      final builder = UriBuilder(buildRuntimeConfiguration());

      final uri = builder.build(
        version: ApiVersion.v1,
        path: '/objects/Vorgang',
        queryParameters: {'query': 'a b', 'serialization': '{"type":"full"}'},
      );

      expect(
        uri.queryParameters,
        equals({'query': 'a b', 'serialization': '{"type":"full"}'}),
      );
      // Uri.replace(queryParameters:) kodiert form-encoded (Leerzeichen als
      // "+"), identisch zum Legacy-Manager, der ebenfalls über
      // Uri.replace(queryParameters:) geht.
      expect(uri.toString(), contains('query=a+b'));
      expect(
        uri.toString(),
        contains('serialization=%7B%22type%22%3A%22full%22%7D'),
      );
    });

    test('leere Query-Map erzeugt KEIN trailing "?"', () {
      final builder = UriBuilder(buildRuntimeConfiguration());

      final uri = builder.build(
        version: ApiVersion.v1,
        path: '/object/OID1',
        queryParameters: {},
      );

      expect(uri.hasQuery, isFalse);
      expect(uri.toString(), isNot(contains('?')));
    });

    test('null-Query erzeugt kein "?"', () {
      final builder = UriBuilder(buildRuntimeConfiguration());

      final uri = builder.build(version: ApiVersion.v1, path: '/object/OID1');

      expect(uri.toString(), isNot(contains('?')));
    });

    group('qb64-Modus', () {
      test('kollabiert alle Parameter in einen einzelnen qb64-Parameter '
          'im Legacy-Kodierungsschema', () {
        final builder = UriBuilder(
          buildRuntimeConfiguration(useBase64UrlParameter: true),
        );
        final params = {'class': 'Vorgang', 'serialization': '{"type":"full"}'};

        final uri = builder.build(
          version: ApiVersion.v1,
          path: '/object/OID1',
          queryParameters: params,
        );

        // Legacy-Schema: k=Uri.encodeComponent(v), mit "&" verbunden,
        // dann UTF-8 + Base64Url (siehe RestApiDOCUframeManager._getUri).
        final expectedPayload = params.entries
            .map((e) => '${e.key}=${Uri.encodeComponent(e.value)}')
            .join('&');
        final expectedQb64 = base64Url.encode(utf8.encode(expectedPayload));

        expect(uri.queryParameters.keys, equals(['qb64']));
        expect(uri.queryParameters['qb64'], equals(expectedQb64));
        expect(
          utf8.decode(base64Url.decode(uri.queryParameters['qb64']!)),
          equals('class=Vorgang&serialization=%7B%22type%22%3A%22full%22%7D'),
        );
      });

      test('leere Query-Map erzeugt auch im qb64-Modus kein "?"', () {
        final builder = UriBuilder(
          buildRuntimeConfiguration(useBase64UrlParameter: true),
        );

        final uri = builder.build(
          version: ApiVersion.v1,
          path: '/object/OID1',
          queryParameters: {},
        );

        expect(uri.toString(), isNot(contains('?')));
      });
    });
  });
}
