// Unit-Tests für RestApiResponsePolicy: Übergangs-Dekodierung für V1 UND V2
// über den Legacy-Envelope und das Exception-Mapping aus RestApiResponse.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/binary_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/legacy_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/rest_api_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:http/http.dart' as http;

void main() {
  const policy = RestApiResponsePolicy();

  TransportResponse buildEnvelopeResponse({
    String internalStatus = '0',
    String statusMessage = 'OK',
    Object? data,
    int statusCode = 200,
    Map<String, String>? headers,
  }) {
    final String body = jsonEncode({
      'status': {
        'internalStatus': internalStatus,
        'statusMessage': statusMessage,
      },
      'data': data ?? {},
    });
    final Uint8List bodyBytes = Uint8List.fromList(utf8.encode(body));

    return TransportResponse(
      statusCode: statusCode,
      headers:
          headers ?? const {'content-type': 'application/json; charset=utf-8'},
      bodyBytes: bodyBytes,
      body: body,
    );
  }

  group('RestApiResponsePolicy Erfolg', () {
    test('internalStatus "0" ergibt isOk', () {
      final response = policy.decode(buildEnvelopeResponse());

      expect(response.isOk, isTrue);
      expect(response.internalStatus, equals('0'));
      expect(response.statusMessage, equals('OK'));
    });

    test('internalStatus "200" ergibt ebenfalls isOk', () {
      final response = policy.decode(
        buildEnvelopeResponse(internalStatus: '200'),
      );

      expect(response.isOk, isTrue);
      expect(response.internalStatus, equals('200'));
    });

    test('Body, Status und Header bleiben auf httpResponse erhalten', () {
      final transport = buildEnvelopeResponse(
        data: {'oid': 'OID1'},
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'x-custom': 'yes',
        },
      );

      final response = policy.decode(transport);

      expect(response.httpResponse.statusCode, equals(200));
      expect(response.httpResponse.body, equals(transport.body));
      expect(response.httpResponse.headers['x-custom'], equals('yes'));
      expect(
        jsonDecode(response.httpResponse.body)['data'],
        equals({'oid': 'OID1'}),
      );
    });

    test('UTF-8-Kodierung überlebt den Adapter (Bytes, nicht String)', () {
      final response = policy.decode(
        buildEnvelopeResponse(statusMessage: 'Änderung erfolgreich - äöüß'),
      );

      expect(response.statusMessage, equals('Änderung erfolgreich - äöüß'));
    });
  });

  group('RestApiResponsePolicy Exception-Mapping (Legacy-Vertrag)', () {
    void expectMapping<T>(String internalStatus) {
      expect(
        () => policy.decode(
          buildEnvelopeResponse(
            internalStatus: internalStatus,
            statusMessage: 'fehler $internalStatus',
          ),
        ),
        throwsA(isA<T>()),
        reason: 'internalStatus "$internalStatus" muss $T werfen',
      );
    }

    test('201 wirft SessionInvalidException', () {
      expectMapping<SessionInvalidException>('201');
    });

    test('204 wirft TokenOrSessionIsMissingException', () {
      expectMapping<TokenOrSessionIsMissingException>('204');
    });

    test('302 wirft UserAndPassWrongException', () {
      expectMapping<UserAndPassWrongException>('302');
    });

    test('306 wirft LicenseException', () {
      expectMapping<LicenseException>('306');
    });

    test('101 wirft ebenfalls LicenseException', () {
      expectMapping<LicenseException>('101');
    });

    test('340 wirft Require2FALoginException', () {
      expectMapping<Require2FALoginException>('340');
    });

    test('341 wirft Missing2FATokenException', () {
      expectMapping<Missing2FATokenException>('341');
    });

    test('342 wirft Invalid2FATokenException', () {
      expectMapping<Invalid2FATokenException>('342');
    });

    test('unbekannter Status (z.B. "999") wirft WebServiceException', () {
      expectMapping<WebServiceException>('999');
    });
  });

  group('specialized legacy response policies', () {
    test('generic legacy policy preserves status, headers, and bytes', () {
      final transport = buildEnvelopeResponse(
        statusCode: 207,
        headers: const {
          'content-type': 'application/json; charset=utf-8',
          'x-test': 'kept',
        },
      );
      final generic = LegacyResponsePolicy<http.Response>(
        (response) => response,
      );

      final response = generic.decode(transport);

      expect(response.statusCode, 207);
      expect(response.headers['x-test'], 'kept');
      expect(response.bodyBytes, transport.bodyBytes);
    });

    test('validated HTTP policy returns the exact validated response', () {
      const validated = ValidatedHttpResponsePolicy();
      final transport = buildEnvelopeResponse(data: {'value': 1});

      final response = validated.decode(transport);

      expect(response.statusCode, 200);
      expect(response.bodyBytes, transport.bodyBytes);
    });

    test('validated HTTP policy keeps RestApiResponse exception mapping', () {
      const validated = ValidatedHttpResponsePolicy();

      expect(
        () => validated.decode(
          buildEnvelopeResponse(
            internalStatus: '201',
            statusMessage: 'expired',
          ),
        ),
        throwsA(isA<SessionInvalidException>()),
      );
    });

    test('binary legacy policy keeps arbitrary non-JSON bytes exact', () {
      final bytes = Uint8List.fromList(<int>[0, 255, 124, 1, 2]);
      final transport = TransportResponse(
        statusCode: 200,
        headers: const {'content-type': 'application/octet-stream'},
        bodyBytes: bytes,
        body: String.fromCharCodes(bytes),
      );
      final binary = BinaryLegacyResponsePolicy<http.Response>(
        (response) => response,
      );

      final response = binary.decode(transport);

      expect(response.bodyBytes, bytes);
      expect(response.headers['content-type'], 'application/octet-stream');
    });

    test('nullable binary bytes policy returns null for non-200 status', () {
      const binary = NullableBinaryBytesResponsePolicy();
      final transport = TransportResponse(
        statusCode: 404,
        headers: const {},
        bodyBytes: Uint8List.fromList(<int>[1, 2]),
        body: '\u0001\u0002',
      );

      expect(binary.decode(transport), isNull);
    });
  });
}
