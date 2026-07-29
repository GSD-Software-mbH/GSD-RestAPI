// ignore_for_file: deprecated_member_use_from_same_package
//
// Test-Harness für die Legacy-Charakterisierungstests von
// RestApiDOCUframeManager.
//
// Startet einen echten `dart:io` HttpServer auf 127.0.0.1 (ephemeral port),
// zeichnet eingehende Requests auf (Methode, Pfad, Query, Header, Body) und
// erlaubt es Tests, pro Methode+Pfad Antworten einzuplanen (FIFO-Queue).
//
// Außerdem: Hilfsfunktionen um das gsd_encryption `EncryptionManager`-Plugin
// unter `flutter_test` lauffähig zu machen (FlutterSecureStorage benötigt
// einen MethodChannel, der ohne echte Plattform nicht existiert) sowie
// Hilfsfunktionen für den v2/login Verschlüsselungs-Roundtrip.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:encrypter_plus/encrypter_plus.dart' as encrypt_plus;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// Eine vom Test-Server aufgezeichnete eingehende HTTP-Anfrage.
class RecordedRequest {
  final String method;
  final String path;
  final Map<String, String> query;
  final Map<String, String> headers;
  final String body;

  RecordedRequest({
    required this.method,
    required this.path,
    required this.query,
    required this.headers,
    required this.body,
  });

  /// Case-insensitive Header-Lookup (dart:io normalisiert eingehende
  /// Header-Namen ohnehin auf Kleinschreibung).
  String? header(String name) => headers[name.toLowerCase()];

  @override
  String toString() =>
      'RecordedRequest($method $path, query: $query, headers: $headers, body: $body)';
}

/// Eine eingeplante Antwort des Test-Servers.
class ScriptedResponse {
  final int statusCode;
  final String body;
  final Map<String, String>? headers;

  /// Optionale künstliche Verzögerung, bevor die Antwort geschrieben wird.
  /// Nützlich, um überlappende (nebenläufige) Requests zu erzwingen.
  final Duration delay;

  ScriptedResponse(
    this.body, {
    this.statusCode = 200,
    this.headers,
    this.delay = Duration.zero,
  });
}

typedef ResponseBuilder =
    FutureOr<ScriptedResponse> Function(RecordedRequest request);

/// Baut das V1-Antwort-Envelope: {"status": {...}, "data": {...}}
Map<String, dynamic> v1Envelope({
  dynamic data,
  String internalStatus = '0',
  String statusMessage = 'OK',
}) {
  final map = <String, dynamic>{
    'status': {
      'internalStatus': internalStatus,
      'statusMessage': statusMessage,
    },
  };
  if (data != null) {
    map['data'] = data;
  }
  return map;
}

/// Lokaler HTTP-Test-Server für die Legacy-Charakterisierungstests.
///
/// Requests werden per "METHOD path" (ohne Query) in einer FIFO-Queue
/// abgearbeitet. Ist die Queue für einen Pfad leer, greift ein optionaler
/// Fallback-Handler, ansonsten wird 404 mit einem Fehler-Envelope
/// zurückgegeben (fällt in Tests sofort auf, wenn ein Request unerwartet war).
class LegacyTestServer {
  late final HttpServer _server;
  final List<RecordedRequest> requests = [];
  final Map<String, Queue<ResponseBuilder>> _queues = {};
  ResponseBuilder? fallback;

  Future<void> start() async {
    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _server.listen(_handle);
  }

  int get port => _server.port;

  String get baseUrl => 'http://127.0.0.1:$port';

  Future<void> close() async {
    await _server.close(force: true);
  }

  String _key(String method, String path) => '${method.toUpperCase()} $path';

  /// Plant eine Antwort für [method] + [path] ein (FIFO je Pfad).
  void enqueue(String method, String path, ResponseBuilder builder) {
    _queues.putIfAbsent(_key(method, path), () => Queue()).add(builder);
  }

  /// Bequemlichkeitsmethode: plant eine JSON-Antwort ein.
  void enqueueJson(
    String method,
    String path, {
    int statusCode = 200,
    required Map<String, dynamic> body,
    Duration delay = Duration.zero,
  }) {
    enqueue(
      method,
      path,
      (req) => ScriptedResponse(
        jsonEncode(body),
        statusCode: statusCode,
        delay: delay,
      ),
    );
  }

  /// Anzahl noch offener eingeplanter Antworten für [method] + [path].
  int pendingCount(String method, String path) =>
      _queues[_key(method, path)]?.length ?? 0;

  Future<void> _handle(HttpRequest request) async {
    final bodyBytes = await request.fold<BytesBuilder>(
      BytesBuilder(),
      (b, d) => b..add(d),
    );
    final body = utf8.decode(bodyBytes.takeBytes());

    final headers = <String, String>{};
    request.headers.forEach((name, values) {
      headers[name.toLowerCase()] = values.join(',');
    });

    final rec = RecordedRequest(
      method: request.method,
      path: request.uri.path,
      query: request.uri.queryParameters,
      headers: headers,
      body: body,
    );
    requests.add(rec);

    final queue = _queues[_key(request.method, request.uri.path)];
    ResponseBuilder? builder;
    if (queue != null && queue.isNotEmpty) {
      builder = queue.removeFirst();
    } else {
      builder = fallback;
    }

    ScriptedResponse response;
    if (builder != null) {
      response = await builder(rec);
    } else {
      response = ScriptedResponse(
        jsonEncode(
          v1Envelope(
            internalStatus: '999',
            statusMessage: 'unscripted request',
          ),
        ),
        statusCode: 404,
      );
    }

    if (response.delay > Duration.zero) {
      await Future<void>.delayed(response.delay);
    }

    request.response.statusCode = response.statusCode;
    request.response.headers.contentType = ContentType(
      'application',
      'json',
      charset: 'utf-8',
    );
    response.headers?.forEach((k, v) => request.response.headers.set(k, v));
    request.response.write(response.body);
    await request.response.close();
  }
}

const MethodChannel _secureStorageChannel = MethodChannel(
  'plugins.it_nomads.com/flutter_secure_storage',
);

bool _cryptoEnvironmentReady = false;

/// Muss vor der Nutzung von RestApiDOCUframeManager.login() (bzw. jeder
/// Codepfad, der EncryptionManager()._getv2LoginBody nutzt) aufgerufen
/// werden.
///
/// gsd_encryption nutzt FlutterSecureStorage für die Persistierung des
/// AES-Schlüssels. Unter `flutter_test` existiert keine echte Plattform,
/// wodurch der MethodChannel-Aufruf mit MissingPluginException fehlschlagen
/// würde. Wir mocken den Channel daher In-Memory (kein Wert vorhanden ->
/// EncryptionManager generiert einen neuen Schlüssel, "write" ist ein No-Op).
void ensureLegacyCryptoTestEnvironment() {
  TestWidgetsFlutterBinding.ensureInitialized();

  if (_cryptoEnvironmentReady) return;
  _cryptoEnvironmentReady = true;

  final Map<String, String> storage = {};

  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(_secureStorageChannel, (call) async {
        switch (call.method) {
          case 'read':
            return storage[call.arguments['key']];
          case 'write':
            storage[call.arguments['key'] as String] =
                call.arguments['value'] as String;
            return null;
          case 'delete':
            storage.remove(call.arguments['key']);
            return null;
          case 'deleteAll':
            storage.clear();
            return null;
          case 'containsKey':
            return storage.containsKey(call.arguments['key']);
          case 'readAll':
            return storage;
          default:
            return null;
        }
      });
}

/// Erzeugt ein neues (vom EncryptionManager-Singleton unabhängiges) RSA
/// Schlüsselpaar, das den "Server" in den Login-Tests repräsentiert.
Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generateServerKeyPair({
  int bitLength = 2048,
}) {
  return EncryptionManager().generateRandomRSAKey(bitLength: bitLength);
}

/// Kodiert einen öffentlichen RSA-Schlüssel als sauberes, standardkonformes
/// PEM (SPKI, keine Einrückung).
///
/// Hinweis: `gsd_encryption`s eigene `RSAPublicKey.encodeToPem()`-Extension
/// erzeugt PEM-Zeilen mit 4 Leerzeichen Einrückung (Artefakt eines
/// Dart-Multiline-Strings). Deren eigener Parser
/// `String.parsePublicKeyFromPem()` filtert Header/Footer-Zeilen aber via
/// `line.startsWith('---')` - was bei eingerückten Zeilen fehlschlägt und
/// zu einem korrupten Base64-Payload führt (siehe Testbericht). Das ist ein
/// Bug im externen Package, nicht im hier getesteten gsd_restapi-Code. Reale
/// Server liefern sauberes PEM ohne Einrückung, daher bilden wir das hier
/// nach, um den Login-Roundtrip realistisch zu simulieren, statt den
/// Drittanbieter-Bug im Test zu reproduzieren.
String encodePublicKeyToCleanPem(RSAPublicKey publicKey) {
  final asn1Seq = ASN1Sequence()
    ..add(ASN1Integer(publicKey.modulus!))
    ..add(ASN1Integer(publicKey.exponent!));
  final publicKeyBitString = ASN1BitString(stringValues: asn1Seq.encode());

  final algorithmSeq = ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromName('rsaEncryption'))
    ..add(ASN1Null());

  final topLevelSeq = ASN1Sequence()
    ..add(algorithmSeq)
    ..add(publicKeyBitString);

  final base64Key = base64Encode(topLevelSeq.encode());
  final chunked = RegExp(
    '.{1,64}',
  ).allMatches(base64Key).map((m) => m.group(0)).join('\n');

  return '-----BEGIN PUBLIC KEY-----\n$chunked\n-----END PUBLIC KEY-----\n';
}

/// Entschlüsselt einen von `RestApiDOCUframeManager._getv2LoginBody`
/// produzierten Request-Body (`{aesKey, data, publicKey}`) mit dem
/// privaten Schlüssel des "Servers" und liefert den ursprünglichen
/// Klartext-JSON-String zurück.
///
/// Dies beweist, dass die echte RSA/AES-Verschlüsselung des Manager-Codes
/// funktioniert, statt nur die Form des Bodys zu prüfen.
Future<String> decryptV2LoginBody(
  String requestBody,
  RSAPrivateKey serverPrivateKey,
) async {
  final map = jsonDecode(requestBody) as Map<String, dynamic>;
  final mgr = EncryptionManager();

  final aesKeyBytes = await mgr.decryptRSA(
    base64Decode(map['aesKey'] as String),
    privateKey: serverPrivateKey,
  );
  final aesKey = encrypt_plus.Key.fromBase64(base64Encode(aesKeyBytes));

  final merged = base64Decode(map['data'] as String);
  final Uint8List ivBytes = merged.sublist(0, 16);
  final Uint8List cipherBytes = merged.sublist(16);

  return mgr.decryptAES(
    jsonEncode({
      'iv': base64Encode(ivBytes),
      'data': base64Encode(cipherBytes),
    }),
    key: aesKey,
    padding: 'PKCS7',
  );
}

/// Baut eine RestApiDOCUframeConfig, die auf den lokalen [server] zeigt.
///
/// `allowSslError: true` ist zwingend nötig, da der Test-Server nur
/// Klartext-HTTP spricht (SecureHttpClientIO würde sonst mit
/// SecurityException ablehnen).
RestApiDOCUframeConfig buildLegacyConfig(
  LegacyTestServer server, {
  String alias = 'dfapp',
  String appKey = 'TEST-APP-KEY',
  String userName = 'tester',
  List<String>? appNames,
  bool multiRequest = false,
  int maxBufferSize = 10,
  int bufferFlushDelayMs = 100,
  String sessionId = '',
}) {
  return RestApiDOCUframeConfig(
    appKey: appKey,
    userName: userName,
    appNames: appNames ?? ['TestApp'],
    serverUrl: server.baseUrl,
    alias: alias,
    allowSslError: true,
    multiRequest: multiRequest,
    maxBufferSize: maxBufferSize,
    bufferFlushDelayMs: bufferFlushDelayMs,
    sessionId: sessionId,
  );
}
