// Tests für UploadExecutor: dreistufiger Datei-Upload (GET Upload-ID ->
// POST Multipart -> optionales PATCH) über den neuen Runtime.
//
// Multipart-Requests sind gestreamte `http.BaseRequest`s
// (`http.MultipartRequest`); `MockClient`s einfacher `http.Request`-Handler
// (wie ihn `MockApiServer` aus `session_test_support.dart` nutzt) bekommt sie
// NIE zu sehen. Dieser Test verwendet daher einen eigenen, kleinen
// `http.BaseClient`, der sowohl normale (GET/PATCH) als auch Multipart-
// Requests aufzeichnet - für Multipart inklusive der tatsächlich
// übertragenen Datei-Bytes (extrahiert aus dem finalisierten
// Multipart-Body), damit die Tests echtes Verhalten prüfen (aufgezeichnete
// Bytes, Aufruf-Reihenfolge) statt sich gegenseitig zu simulieren.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport/upload_executor.dart';
import 'package:http/http.dart' as http;
import 'package:pointycastle/export.dart' show RSAPublicKey;

import 'runtime_test_helpers.dart';
import 'session_test_support.dart'
    show
        RecordedRequest,
        ResponseBuilder,
        ScriptedResponse,
        buildSessionRuntimeConfiguration,
        encodePublicKeyToCleanPem,
        encryptV2Response,
        ensureLegacyCryptoTestEnvironment,
        generateServerKeyPair,
        v1Envelope;

/// Eine vom [_UploadTestClient] aufgezeichnete Multipart-Anfrage inklusive
/// der aus dem finalisierten Multipart-Body extrahierten Rohbytes des
/// (einzigen) Datei-Teils.
class MultipartCapture {
  final String method;
  final String path;
  final Map<String, String> query;
  final Map<String, String> headers;
  final String fieldName;
  final String? filename;
  final Uint8List fileBytes;

  MultipartCapture({
    required this.method,
    required this.path,
    required this.query,
    required this.headers,
    required this.fieldName,
    required this.filename,
    required this.fileBytes,
  });

  /// Case-insensitive Header-Lookup (analog zu `RecordedRequest.header`).
  String? header(String name) {
    for (final entry in headers.entries) {
      if (entry.key.toLowerCase() == name.toLowerCase()) {
        return entry.value;
      }
    }
    return null;
  }
}

typedef MultipartResponseBuilder =
    FutureOr<ScriptedResponse> Function(MultipartCapture request);

/// Testclient: verarbeitet normale (unary) Requests wie `MockApiServer`
/// (FIFO-Skript je "METHOD path"), zeichnet Multipart-Requests aber
/// zusätzlich vollständig auf (inkl. der reinen Datei-Bytes) - dafür bietet
/// `MockClient` keine Unterstützung (siehe Datei-Kommentar oben).
class _UploadTestClient extends http.BaseClient {
  /// Chronologische Sequenz aller Requests als "METHOD /pfad" - für
  /// Reihenfolge-Assertions über GET/POST/PATCH hinweg.
  final List<String> sequence = [];

  final List<RecordedRequest> plainRequests = [];
  final List<MultipartCapture> multipartRequests = [];

  final Map<String, Queue<ResponseBuilder>> _plainQueues = {};
  final Map<String, Queue<MultipartResponseBuilder>> _multipartQueues = {};

  String _key(String method, String path) => '${method.toUpperCase()} $path';

  void enqueuePlainJson(
    String method,
    String path, {
    int statusCode = 200,
    required Map<String, dynamic> body,
  }) {
    _plainQueues
        .putIfAbsent(_key(method, path), () => Queue())
        .add((_) => ScriptedResponse(jsonEncode(body), statusCode: statusCode));
  }

  void enqueueMultipart(
    String method,
    String path,
    MultipartResponseBuilder responder,
  ) {
    _multipartQueues
        .putIfAbsent(_key(method, path), () => Queue())
        .add(responder);
  }

  /// Wie [enqueuePlainJson], aber mit einem rohen [ResponseBuilder] statt
  /// eines festen JSON-Bodys - erlaubt Seiteneffekte (z.B. `runtime.dispose()`
  /// synchron auslösen), während die Antwort für einen unären Request gebaut
  /// wird.
  void enqueuePlain(String method, String path, ResponseBuilder builder) {
    _plainQueues.putIfAbsent(_key(method, path), () => Queue()).add(builder);
  }

  void enqueueMultipartJson(
    String method,
    String path, {
    int statusCode = 200,
    required Map<String, dynamic> body,
  }) {
    enqueueMultipart(
      method,
      path,
      (_) => ScriptedResponse(jsonEncode(body), statusCode: statusCode),
    );
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    if (request is http.MultipartRequest) {
      return _handleMultipart(request);
    }
    return _handlePlain(request);
  }

  Future<http.StreamedResponse> _handlePlain(http.BaseRequest request) async {
    final String body = request is http.Request ? request.body : '';
    final rec = RecordedRequest(
      method: request.method,
      path: request.url.path,
      query: request.url.queryParameters,
      headers: Map<String, String>.of(request.headers),
      body: body,
    );
    plainRequests.add(rec);
    sequence.add(_key(request.method, request.url.path));

    final queue = _plainQueues[_key(request.method, request.url.path)];
    final builder = (queue != null && queue.isNotEmpty)
        ? queue.removeFirst()
        : null;
    final ScriptedResponse response = builder != null
        ? await builder(rec)
        : ScriptedResponse(
            jsonEncode(
              v1Envelope(
                internalStatus: '999',
                statusMessage: 'unscripted ${rec.method} ${rec.path}',
              ),
            ),
            statusCode: 404,
          );

    return _toStreamedResponse(response);
  }

  Future<http.StreamedResponse> _handleMultipart(
    http.MultipartRequest request,
  ) async {
    final http.MultipartFile file = request.files.single;
    final String fieldName = file.field;
    final String? filename = file.filename;

    // `finalize()` setzt den Content-Type-Header (`multipart/form-data;
    // boundary=...`) synchron; das Auslesen des zurückgegebenen ByteStream
    // treibt zusätzlich den (ggf. von UploadExecutor instrumentierten)
    // Datei-Stream an - wie es ein echter HTTP-Client beim Senden täte
    // (inkl. Fortschritts-/Abbruchprüfung pro Chunk).
    final Uint8List framed = await request.finalize().toBytes();
    final Map<String, String> headers = Map<String, String>.of(request.headers);

    final Uint8List fileBytes = _extractSingleFilePart(
      framed,
      headers['content-type'] ?? '',
    );

    final rec = MultipartCapture(
      method: request.method,
      path: request.url.path,
      query: request.url.queryParameters,
      headers: headers,
      fieldName: fieldName,
      filename: filename,
      fileBytes: fileBytes,
    );
    multipartRequests.add(rec);
    sequence.add(_key(request.method, request.url.path));

    final queue = _multipartQueues[_key(request.method, request.url.path)];
    final builder = (queue != null && queue.isNotEmpty)
        ? queue.removeFirst()
        : null;
    final ScriptedResponse response = builder != null
        ? await builder(rec)
        : ScriptedResponse(
            jsonEncode(
              v1Envelope(
                internalStatus: '999',
                statusMessage: 'unscripted multipart ${rec.method} ${rec.path}',
              ),
            ),
            statusCode: 404,
          );

    return _toStreamedResponse(response);
  }

  http.StreamedResponse _toStreamedResponse(ScriptedResponse response) {
    final bytes = utf8.encode(response.body);
    return http.StreamedResponse(
      response.delay == Duration.zero
          ? Stream.value(bytes)
          : Stream.fromFuture(
              Future<List<int>>.delayed(response.delay, () => bytes),
            ),
      response.statusCode,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        ...?response.headers,
      },
    );
  }
}

/// Extrahiert die reinen Bytes des (einzigen) Datei-Teils aus einem
/// finalisierten `multipart/form-data`-Body: alles zwischen dem Ende der
/// Teil-Header (`\r\n\r\n`) und dem schließenden Boundary-Marker
/// (`\r\n--boundary`).
Uint8List _extractSingleFilePart(Uint8List framed, String contentTypeHeader) {
  final match = RegExp(r'boundary=(.+)$').firstMatch(contentTypeHeader);
  if (match == null) {
    throw StateError(
      'Kein Multipart-Boundary im Content-Type gefunden: "$contentTypeHeader"',
    );
  }
  final String boundary = match.group(1)!;

  final int headerEnd = _indexOfSubsequence(framed, utf8.encode('\r\n\r\n'));
  if (headerEnd == -1) {
    throw StateError('Kein Ende der Multipart-Teil-Header gefunden.');
  }
  final int contentStart = headerEnd + 4;

  final int contentEnd = _indexOfSubsequence(
    framed,
    utf8.encode('\r\n--$boundary'),
    start: contentStart,
  );
  if (contentEnd == -1) {
    throw StateError('Kein schließender Multipart-Boundary gefunden.');
  }

  return framed.sublist(contentStart, contentEnd);
}

int _indexOfSubsequence(List<int> haystack, List<int> needle, {int start = 0}) {
  outer:
  for (var i = start; i <= haystack.length - needle.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
}

/// Wartet (per Polling mit echten kurzen Delays) auf [condition], statt eine
/// feste Verzögerung zu raten - robust gegenüber unterschiedlich vielen
/// Microtask-/Event-Loop-Durchläufen des Hintergrundprozesses.
Future<void> _waitUntil(
  bool Function() condition, {
  Duration timeout = const Duration(seconds: 2),
}) async {
  final DateTime deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('Timeout beim Warten auf eine Bedingung.');
    }
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
}

void main() {
  ensureLegacyCryptoTestEnvironment();

  late RSAPublicKey serverPublicKey;

  setUpAll(() async {
    serverPublicKey = (await generateServerKeyPair()).publicKey;
  });

  group('UploadExecutor: zentrale Response-Pipeline', () {
    test('entschlüsselt Multipart-Response vor dem Response-Parsing', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-encrypted'}),
      );
      client.enqueueMultipart('POST', '/dfapp/v1/uploadFile/upload-encrypted', (
        _,
      ) async {
        final manager = EncryptionManager();
        await manager.initializeRSAKeyPair();
        return ScriptedResponse(
          await encryptV2Response(
            jsonEncode(v1Envelope(data: {'encrypted': true})),
            manager.keyRSA!.publicKey,
          ),
        );
      });

      await executor.uploadFile(
        RestApiUploadFile.fromBytes(
          name: 'encrypted.bin',
          bytes: Uint8List.fromList([1, 2, 3]),
        ),
        fetchToObject: false,
      );

      expect(client.multipartRequests, hasLength(1));
    });

    test(
      'wiederholt Multipart nach Session-Refresh mit neuem Stream',
      () async {
        final client = _UploadTestClient();
        final config = buildSessionRuntimeConfiguration();
        final coordinator = SessionCoordinator(
          configuration: config,
          retryDelay: const Duration(milliseconds: 1),
        );
        final executor = UploadExecutor();
        final runtime = ApiRuntime(
          configuration: config,
          httpClient: client,
          sessionCoordinator: coordinator,
          uploadExecutor: executor,
        );
        addTearDown(runtime.dispose);

        for (var i = 0; i < 2; i++) {
          client.enqueuePlainJson(
            'GET',
            '/dfapp/v2/login/key',
            body: v1Envelope(
              data: {'key': encodePublicKeyToCleanPem(serverPublicKey)},
            ),
          );
        }
        client.enqueuePlainJson(
          'POST',
          '/dfapp/v2/login',
          body: v1Envelope(data: {'sessionId': 'sess-initial'}),
        );
        client.enqueuePlainJson(
          'GET',
          '/dfapp/v1/uploadFile',
          body: v1Envelope(data: {'uploadId': 'upload-retry'}),
        );
        client.enqueueMultipartJson(
          'POST',
          '/dfapp/v1/uploadFile/upload-retry',
          body: v1Envelope(
            internalStatus: '201',
            statusMessage: 'session invalid',
          ),
        );
        client.enqueuePlainJson(
          'POST',
          '/dfapp/v2/login',
          body: v1Envelope(data: {'sessionId': 'sess-refreshed'}),
        );
        client.enqueueMultipartJson(
          'POST',
          '/dfapp/v1/uploadFile/upload-retry',
          body: v1Envelope(data: {'uploaded': true}),
        );

        await coordinator.login('md5hash');
        final fileBytes = Uint8List.fromList([7, 8, 9, 10]);
        await executor.uploadFile(
          RestApiUploadFile.fromBytes(name: 'retry.bin', bytes: fileBytes),
          fetchToObject: false,
        );

        expect(client.multipartRequests, hasLength(2));
        expect(client.multipartRequests[0].fileBytes, fileBytes);
        expect(client.multipartRequests[1].fileBytes, fileBytes);
        expect(client.multipartRequests[0].header('sessionid'), 'sess-initial');
        expect(
          client.multipartRequests[1].header('sessionid'),
          'sess-refreshed',
        );
      },
    );

    test('wendet Response-Timeout auch auf Multipart an', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildSessionRuntimeConfiguration(
          responseTimeout: const Duration(milliseconds: 10),
        ),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-timeout'}),
      );
      client.enqueueMultipart(
        'POST',
        '/dfapp/v1/uploadFile/upload-timeout',
        (_) => ScriptedResponse(
          jsonEncode(v1Envelope(data: {'late': true})),
          delay: const Duration(milliseconds: 100),
        ),
      );

      await expectLater(
        executor.uploadFile(
          RestApiUploadFile.fromBytes(
            name: 'timeout.bin',
            bytes: Uint8List.fromList([1]),
          ),
          fetchToObject: false,
        ),
        throwsA(isA<TimeoutException>()),
      );
    });

    test('meldet Multipart-Fehler über Callback und Telemetrie', () async {
      final client = _UploadTestClient();
      final metrics = <RestApiHttpMetric>[];
      var licenseCallbackCount = 0;
      final callbacks = RestApiDOCUframeCallbacks(
        onHttpMetricRecorded: (metric) async => metrics.add(metric),
        onLicenseWrong: (_) async => licenseCallbackCount++,
      );
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        callbacks: callbacks,
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-license'}),
      );
      client.enqueueMultipartJson(
        'POST',
        '/dfapp/v1/uploadFile/upload-license',
        body: v1Envelope(
          internalStatus: '306',
          statusMessage: 'license invalid',
        ),
      );

      await expectLater(
        executor.uploadFile(
          RestApiUploadFile.fromBytes(
            name: 'license.bin',
            bytes: Uint8List.fromList([1]),
          ),
          fetchToObject: false,
        ),
        throwsA(isA<LicenseException>()),
      );

      expect(licenseCallbackCount, 1);
      expect(
        metrics.where(
          (metric) => metric.path == '/dfapp/v1/uploadFile/upload-license',
        ),
        hasLength(1),
      );
    });
  });

  group('UploadExecutor: uploadFile() Happy Path', () {
    test('GET->POST->PATCH-Sequenz, Multipart-Body (leerer Feldname, '
        'korrekter Dateiname/Inhalt), aktueller Session-Header, '
        'replaceOID-Query, PATCH-Antwort als Rückgabe', () async {
      final client = _UploadTestClient();
      final config = buildRuntimeConfiguration(sessionId: 'session-XYZ');
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: config,
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-1', 'marker': 'step1'}),
      );
      client.enqueueMultipartJson(
        'POST',
        '/dfapp/v1/uploadFile/upload-1',
        body: v1Envelope(data: {'marker': 'step2'}),
      );
      client.enqueuePlainJson(
        'PATCH',
        '/dfapp/v1/uploadFile/upload-1',
        body: v1Envelope(data: {'marker': 'step3'}),
      );

      final fileBytes = Uint8List.fromList(utf8.encode('hello upload world'));
      final file = RestApiUploadFile.fromBytes(
        name: 'greeting.txt',
        bytes: fileBytes,
      );

      final RestApiResponse response = await executor.uploadFile(
        file,
        replaceOID: 'OID-1',
      );

      expect(client.sequence, [
        'GET /dfapp/v1/uploadFile',
        'POST /dfapp/v1/uploadFile/upload-1',
        'PATCH /dfapp/v1/uploadFile/upload-1',
      ]);

      final decoded =
          jsonDecode(response.httpResponse.body) as Map<String, dynamic>;
      expect((decoded['data'] as Map)['marker'], 'step3');

      final multipart = client.multipartRequests.single;
      expect(multipart.fieldName, '');
      expect(multipart.filename, 'greeting.txt');
      expect(multipart.fileBytes, fileBytes);
      expect(
        multipart.header('content-type'),
        startsWith('multipart/form-data; boundary='),
      );
      expect(multipart.header('sessionid'), 'session-XYZ');
      expect(multipart.header('appkey'), 'TEST-APP-KEY');

      final RecordedRequest patchRequest = client.plainRequests.last;
      expect(patchRequest.method, 'PATCH');
      expect(patchRequest.query['replaceOID'], 'OID-1');
    });

    test(
      'fetchToObject:false -> kein PATCH, Rückgabe ist die Schritt-1-Antwort '
      '(NICHT die von Schritt 2 - Legacy-Asymmetrie zu uploadFileWithController)',
      () async {
        final client = _UploadTestClient();
        final executor = UploadExecutor();
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          uploadExecutor: executor,
        );
        addTearDown(runtime.dispose);

        client.enqueuePlainJson(
          'GET',
          '/dfapp/v1/uploadFile',
          body: v1Envelope(data: {'uploadId': 'upload-2', 'marker': 'step1'}),
        );
        client.enqueueMultipartJson(
          'POST',
          '/dfapp/v1/uploadFile/upload-2',
          body: v1Envelope(data: {'marker': 'step2'}),
        );

        final file = RestApiUploadFile.fromBytes(
          name: 'a.bin',
          bytes: Uint8List.fromList([1, 2, 3]),
        );

        final RestApiResponse response = await executor.uploadFile(
          file,
          fetchToObject: false,
        );

        expect(client.sequence, [
          'GET /dfapp/v1/uploadFile',
          'POST /dfapp/v1/uploadFile/upload-2',
        ]);
        expect(client.plainRequests.any((r) => r.method == 'PATCH'), isFalse);

        final decoded =
            jsonDecode(response.httpResponse.body) as Map<String, dynamic>;
        expect((decoded['data'] as Map)['marker'], 'step1');
      },
    );

    test('patch:false hat KEINE Wirkung (Legacy-Quirk: nur fetchToObject '
        'entscheidet über Schritt 3, patch ist toter Parameter)', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-3'}),
      );
      client.enqueueMultipartJson(
        'POST',
        '/dfapp/v1/uploadFile/upload-3',
        body: v1Envelope(data: {}),
      );
      client.enqueuePlainJson(
        'PATCH',
        '/dfapp/v1/uploadFile/upload-3',
        body: v1Envelope(data: {}),
      );

      final file = RestApiUploadFile.fromBytes(
        name: 'a.bin',
        bytes: Uint8List.fromList([1]),
      );

      await executor.uploadFile(file, patch: false, fetchToObject: true);

      expect(client.sequence, [
        'GET /dfapp/v1/uploadFile',
        'POST /dfapp/v1/uploadFile/upload-3',
        'PATCH /dfapp/v1/uploadFile/upload-3',
      ]);
    });

    test(
      'replaceOID leer -> Query-Parameter replaceOID fehlt komplett',
      () async {
        final client = _UploadTestClient();
        final executor = UploadExecutor();
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          uploadExecutor: executor,
        );
        addTearDown(runtime.dispose);

        client.enqueuePlainJson(
          'GET',
          '/dfapp/v1/uploadFile',
          body: v1Envelope(data: {'uploadId': 'upload-4'}),
        );
        client.enqueueMultipartJson(
          'POST',
          '/dfapp/v1/uploadFile/upload-4',
          body: v1Envelope(data: {}),
        );
        client.enqueuePlainJson(
          'PATCH',
          '/dfapp/v1/uploadFile/upload-4',
          body: v1Envelope(data: {}),
        );

        final file = RestApiUploadFile.fromBytes(
          name: 'a.bin',
          bytes: Uint8List.fromList([1]),
        );

        await executor.uploadFile(file);

        final RecordedRequest patchRequest = client.plainRequests.last;
        expect(patchRequest.query.containsKey('replaceOID'), isFalse);
      },
    );
  });

  group('UploadExecutor: uploadFileWithController() Rückgabe-Semantik', () {
    test('fetchToObject:true -> controller.result ist die PATCH-Antwort '
        '(Schritt 3)', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(
          data: {'uploadId': 'upload-ctrl-true', 'marker': 'step1'},
        ),
      );
      client.enqueueMultipartJson(
        'POST',
        '/dfapp/v1/uploadFile/upload-ctrl-true',
        body: v1Envelope(data: {'marker': 'step2'}),
      );
      client.enqueuePlainJson(
        'PATCH',
        '/dfapp/v1/uploadFile/upload-ctrl-true',
        body: v1Envelope(data: {'marker': 'step3'}),
      );

      final file = RestApiUploadFile.fromBytes(
        name: 'a.bin',
        bytes: Uint8List.fromList([1, 2, 3]),
      );

      final RestAPIFileUploadController controller = await executor
          .uploadFileWithController(file, fetchToObject: true);
      final RestApiResponse response = await controller.result;

      final decoded =
          jsonDecode(response.httpResponse.body) as Map<String, dynamic>;
      expect((decoded['data'] as Map)['marker'], 'step3');
    });

    test(
      'fetchToObject:false -> controller.result ist die POST-Antwort '
      '(Schritt 2, NICHT Schritt 1/GET - Asymmetrie zu uploadFile())',
      () async {
        final client = _UploadTestClient();
        final executor = UploadExecutor();
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          uploadExecutor: executor,
        );
        addTearDown(runtime.dispose);

        client.enqueuePlainJson(
          'GET',
          '/dfapp/v1/uploadFile',
          body: v1Envelope(
            data: {'uploadId': 'upload-ctrl-false', 'marker': 'step1'},
          ),
        );
        client.enqueueMultipartJson(
          'POST',
          '/dfapp/v1/uploadFile/upload-ctrl-false',
          body: v1Envelope(data: {'marker': 'step2'}),
        );
        // Bewusst KEIN PATCH eingeplant: fetchToObject:false darf Schritt 3
        // NICHT auslösen.

        final file = RestApiUploadFile.fromBytes(
          name: 'b.bin',
          bytes: Uint8List.fromList([4, 5, 6]),
        );

        final RestAPIFileUploadController controller = await executor
            .uploadFileWithController(file, fetchToObject: false);
        final RestApiResponse response = await controller.result;

        expect(client.plainRequests.any((r) => r.method == 'PATCH'), isFalse);
        final decoded =
            jsonDecode(response.httpResponse.body) as Map<String, dynamic>;
        expect((decoded['data'] as Map)['marker'], 'step2');
      },
    );
  });

  group('UploadExecutor: Fehler in Schritt 1', () {
    test('fehlende uploadId in data -> wirft WebServiceException, kein '
        'POST-Versuch', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {}),
      );

      final file = RestApiUploadFile.fromBytes(
        name: 'a.bin',
        bytes: Uint8List.fromList([1]),
      );

      await expectLater(
        executor.uploadFile(file),
        throwsA(isA<WebServiceException>()),
      );
      expect(client.multipartRequests, isEmpty);
    });

    test('Fehler-Envelope in Schritt 1 -> wirft die gemappte Exception, kein '
        'POST-Versuch', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(internalStatus: '201', statusMessage: 'invalid'),
      );

      final file = RestApiUploadFile.fromBytes(
        name: 'a.bin',
        bytes: Uint8List.fromList([1]),
      );

      await expectLater(
        executor.uploadFile(file),
        throwsA(isA<SessionInvalidException>()),
      );
      expect(client.multipartRequests, isEmpty);
    });
  });

  group('UploadExecutor: dispose-Guard', () {
    test('runtime bereits vor uploadFile() disposed -> StateError, kein '
        'HTTP-Request', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      await runtime.dispose();

      final file = RestApiUploadFile.fromBytes(
        name: 'a.bin',
        bytes: Uint8List.fromList([1]),
      );

      await expectLater(executor.uploadFile(file), throwsA(isA<StateError>()));
      expect(client.plainRequests, isEmpty);
      expect(client.multipartRequests, isEmpty);
    });

    test('runtime disposed unmittelbar nach erfolgreichem Schritt 1 (Race, die '
        'Fix 1 abfängt) -> Schritt 2 wirft StateError VOR dem Senden, '
        'controller.result schlägt fehl, kein Multipart-POST', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlain('GET', '/dfapp/v1/uploadFile', (_) {
        // Simuliert dispose(), das GENAU zwischen Schritt 1 (uploadId
        // erfolgreich geholt) und Schritt 2 (Multipart-POST) einschlägt -
        // die eigentliche Race, gegen die der neue Disposed-Guard in
        // `_postMultipart` schützt.
        unawaited(runtime.dispose());
        return ScriptedResponse(
          jsonEncode(v1Envelope(data: {'uploadId': 'upload-race'})),
        );
      });

      final file = RestApiUploadFile.fromBytes(
        name: 'a.bin',
        bytes: Uint8List.fromList([1]),
      );

      final RestAPIFileUploadController controller = await executor
          .uploadFileWithController(file);

      await expectLater(controller.result, throwsA(isA<StateError>()));
      expect(client.multipartRequests, isEmpty);
    });
  });

  group('UploadExecutor: Pfad-basierte Datei', () {
    test('nicht-Web: sendet den tatsächlichen Dateiinhalt', () async {
      final Directory tempDir = Directory.systemTemp.createTempSync(
        'upload_executor_test_',
      );
      addTearDown(() => tempDir.deleteSync(recursive: true));
      final File tempFile = File('${tempDir.path}/document.pdf');
      final Uint8List contentBytes = Uint8List.fromList(
        List<int>.generate(5000, (i) => i % 256),
      );
      tempFile.writeAsBytesSync(contentBytes);

      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-path'}),
      );
      client.enqueueMultipartJson(
        'POST',
        '/dfapp/v1/uploadFile/upload-path',
        body: v1Envelope(data: {}),
      );
      client.enqueuePlainJson(
        'PATCH',
        '/dfapp/v1/uploadFile/upload-path',
        body: v1Envelope(data: {}),
      );

      final file = RestApiUploadFile.fromPath(path: tempFile.path);
      expect(file.name, 'document.pdf');

      await executor.uploadFile(file);

      final multipart = client.multipartRequests.single;
      expect(multipart.fieldName, '');
      expect(multipart.filename, 'document.pdf');
      expect(multipart.fileBytes, contentBytes);
    });
  });

  group('UploadExecutor: Fortschritt', () {
    test(
      'onProgress meldet monoton steigende Bytes bis zur Gesamtlänge',
      () async {
        final Directory tempDir = Directory.systemTemp.createTempSync(
          'upload_executor_progress_',
        );
        addTearDown(() => tempDir.deleteSync(recursive: true));
        final File tempFile = File('${tempDir.path}/large.bin');
        final Uint8List contentBytes = Uint8List.fromList(
          List<int>.generate(2 * 1024 * 1024, (i) => i % 256),
        );
        tempFile.writeAsBytesSync(contentBytes);

        final client = _UploadTestClient();
        final executor = UploadExecutor();
        final runtime = ApiRuntime(
          configuration: buildRuntimeConfiguration(),
          httpClient: client,
          uploadExecutor: executor,
        );
        addTearDown(runtime.dispose);

        client.enqueuePlainJson(
          'GET',
          '/dfapp/v1/uploadFile',
          body: v1Envelope(data: {'uploadId': 'upload-progress'}),
        );
        client.enqueueMultipartJson(
          'POST',
          '/dfapp/v1/uploadFile/upload-progress',
          body: v1Envelope(data: {}),
        );
        client.enqueuePlainJson(
          'PATCH',
          '/dfapp/v1/uploadFile/upload-progress',
          body: v1Envelope(data: {}),
        );

        final List<List<int>> progressCalls = [];
        final file = RestApiUploadFile.fromPath(path: tempFile.path);

        await executor.uploadFile(
          file,
          onProgress: (sent, total) => progressCalls.add([sent, total]),
        );

        expect(progressCalls, isNotEmpty);
        for (var i = 1; i < progressCalls.length; i++) {
          expect(
            progressCalls[i][0],
            greaterThanOrEqualTo(progressCalls[i - 1][0]),
          );
        }
        expect(progressCalls.last[0], contentBytes.length);
        expect(progressCalls.every((c) => c[1] == contentBytes.length), isTrue);

        final multipart = client.multipartRequests.single;
        expect(multipart.fileBytes, contentBytes);
      },
    );
  });

  group('UploadExecutor: Abbruch über uploadFileWithController', () {
    test('controller.cancel() lässt result sofort fehlschlagen und verhindert '
        'ein nachfolgendes PATCH', () async {
      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-cancel'}),
      );

      // Das Gate hält NUR die POST-ANTWORT zurück; der Request selbst
      // (inkl. vollständiger Datei-Bytes) ist zu diesem Zeitpunkt bereits
      // beim Client angekommen und aufgezeichnet - realistisch, da Bytes,
      // die bereits auf der Leitung sind, sich nicht mehr "zurückholen"
      // lassen. Getestet wird daher die Garantie, die nach dem Versand
      // noch sinnvoll ist: `result` schlägt fehl UND Schritt 3 (PATCH)
      // wird nicht mehr ausgelöst.
      final postGate = Completer<void>();
      client.enqueueMultipart('POST', '/dfapp/v1/uploadFile/upload-cancel', (
        _,
      ) async {
        await postGate.future;
        return ScriptedResponse(jsonEncode(v1Envelope(data: {})));
      });

      final file = RestApiUploadFile.fromBytes(
        name: 'x.bin',
        bytes: Uint8List.fromList([9, 9, 9]),
      );

      final RestAPIFileUploadController controller = await executor
          .uploadFileWithController(file);

      await _waitUntil(() => client.multipartRequests.isNotEmpty);

      controller.cancel();
      await expectLater(controller.result, throwsA(anything));

      postGate.complete();

      // Dem Hintergrundprozess Zeit geben, nach der (verspäteten)
      // POST-Antwort weiterzulaufen (und - fälschlicherweise - ein PATCH
      // auszulösen, falls der Abbruch nicht beachtet würde).
      await Future<void>.delayed(const Duration(milliseconds: 100));

      expect(client.plainRequests.where((r) => r.method == 'PATCH'), isEmpty);
    });

    test('controller.cancel() sofort nach uploadFileWithController() (BEVOR '
        'der Multipart-Versand beginnt) -> kein POST wird gesendet', () async {
      // Pfad-basierte Datei (statt Bytes): `http.MultipartFile.fromPath`
      // hängt intern an einem ECHTEN dart:io-Await (`File.length()`), der
      // erst nach Ablauf ALLER bereits eingeplanten Mikrotasks bedient
      // wird. Da Schritt 1 (GET) in diesem Test rein Mikrotask-basiert
      // abläuft (kein echtes IO), ist beim Rücksprung aus
      // `await uploadFileWithController(...)` garantiert, dass der
      // Hintergrundprozess in `_postMultipart` noch VOR dem zweiten
      // `_throwIfCancelled`-Check (unmittelbar vor `_requireClient.send`)
      // steht - `cancel()` greift hier also nachweislich vor dem
      // eigentlichen Versand, nicht erst am vollständig durchgelaufenen
      // Checkpoint (siehe Test oben).
      final Directory tempDir = Directory.systemTemp.createTempSync(
        'upload_executor_early_cancel_',
      );
      addTearDown(() => tempDir.deleteSync(recursive: true));
      final File tempFile = File('${tempDir.path}/early.bin');
      tempFile.writeAsBytesSync(Uint8List.fromList([1, 2, 3, 4, 5]));

      final client = _UploadTestClient();
      final executor = UploadExecutor();
      final runtime = ApiRuntime(
        configuration: buildRuntimeConfiguration(),
        httpClient: client,
        uploadExecutor: executor,
      );
      addTearDown(runtime.dispose);

      client.enqueuePlainJson(
        'GET',
        '/dfapp/v1/uploadFile',
        body: v1Envelope(data: {'uploadId': 'upload-early-cancel'}),
      );
      // Bewusst KEIN enqueueMultipart(...): Der Test erwartet, dass der
      // Multipart-POST den Client NIE erreicht.

      final file = RestApiUploadFile.fromPath(path: tempFile.path);

      final RestAPIFileUploadController controller = await executor
          .uploadFileWithController(file);

      controller.cancel();

      await expectLater(controller.result, throwsA(anything));
      expect(client.multipartRequests, isEmpty);
    });
  });
}
