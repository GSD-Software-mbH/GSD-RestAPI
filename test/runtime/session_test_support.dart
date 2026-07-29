// Gemeinsame Test-Infrastruktur für die SessionCoordinator-/Session-Retry-Tests
// von `test/runtime/session_coordinator_test.dart`.
//
// Bewusst KEIN Import aus test/legacy/: Statt die dortige
// `legacy_test_server.dart` (echter `dart:io` HttpServer) zu importieren,
// wird hier ein leichtgewichtiges, `MockClient`-basiertes Äquivalent
// bereitgestellt (passend zum `httpClient`-Injektionspunkt von `ApiRuntime`).
// Die Krypto-Hilfsfunktionen (Secure-Storage-Channel-Mock, sauberer
// PEM-Encoder, Server-seitige Entschlüsselung) sind bewusste Kopien der in
// `test/legacy/legacy_test_server.dart` bereits gelösten und dokumentierten
// Patterns (inkl. des dort beschriebenen `encodeToPem()`-Einrückungsbugs von
// `gsd_encryption`).

import 'dart:async';
import 'dart:collection';
import 'dart:convert';

import 'package:encrypter_plus/encrypter_plus.dart' as encrypt_plus;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// Eine vom [MockApiServer] aufgezeichnete eingehende Anfrage.
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

  /// Case-insensitive Header-Lookup.
  String? header(String name) => headers[name.toLowerCase()];

  @override
  String toString() =>
      'RecordedRequest($method $path, query: $query, headers: $headers, '
      'body: $body)';
}

/// Eine eingeplante Antwort des [MockApiServer].
class ScriptedResponse {
  final int statusCode;
  final String body;
  final Map<String, String>? headers;

  /// Optionale künstliche Verzögerung, bevor die Antwort geliefert wird.
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

/// Baut das V1-Antwort-Envelope: `{"status": {...}, "data": {...}}`.
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

/// `MockClient`-basierter Test-Server: Requests werden per "METHOD path"
/// (ohne Query) in einer FIFO-Queue abgearbeitet. Ist die Queue für einen
/// Pfad leer, greift ein optionaler Fallback-Handler, ansonsten wird 404 mit
/// einem Fehler-Envelope zurückgegeben (fällt in Tests sofort auf, wenn ein
/// Request unerwartet war).
///
/// Anders als `LegacyTestServer` (echter `dart:io`-Socket) läuft hier alles
/// synchron im Testprozess über `package:http/testing.dart`, passend zum
/// `httpClient`-Injektionspunkt von `ApiRuntime`/`HttpTransport`.
class MockApiServer {
  final List<RecordedRequest> requests = [];
  final Map<String, Queue<ResponseBuilder>> _queues = {};
  ResponseBuilder? fallback;

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

  /// Der in `ApiRuntime(httpClient: ...)` zu injizierende Client.
  http.Client get client => MockClient(_handle);

  Future<http.Response> _handle(http.Request request) async {
    final rec = RecordedRequest(
      method: request.method,
      path: request.url.path,
      query: request.url.queryParameters,
      headers: Map<String, String>.of(request.headers),
      body: request.body,
    );
    requests.add(rec);

    final queue = _queues[_key(request.method, request.url.path)];
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
            statusMessage:
                'unscripted request ${request.method} ${request.url.path}',
          ),
        ),
        statusCode: 404,
      );
    }

    if (response.delay > Duration.zero) {
      await Future<void>.delayed(response.delay);
    }

    return http.Response(
      response.body,
      response.statusCode,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        ...?response.headers,
      },
    );
  }
}

const MethodChannel _secureStorageChannel = MethodChannel(
  'plugins.it_nomads.com/flutter_secure_storage',
);

bool _cryptoEnvironmentReady = false;

/// Muss vor jeder Nutzung von `SessionCoordinator.login()`/`refreshSession()`
/// (bzw. jedem Codepfad, der `EncryptionManager` nutzt) aufgerufen werden.
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
/// zu einem korrupten Base64-Payload führt. Das ist ein Bug im externen
/// Package, nicht im hier getesteten gsd_restapi-Code. Reale Server liefern
/// sauberes PEM ohne Einrückung, daher bilden wir das hier nach, um den
/// Login-Roundtrip realistisch zu simulieren, statt den
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

/// Entschlüsselt einen von `SessionCoordinator._buildEncryptedLoginBody`
/// produzierten Request-Body (`{aesKey, data, publicKey}`) mit dem privaten
/// Schlüssel des "Servers" und liefert den ursprünglichen Klartext-JSON-String
/// zurück.
///
/// Dies beweist, dass die echte RSA/AES-Verschlüsselung des Codes
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

/// Verschlüsselt einen Server-Response-Body im vom Legacy-Manager erwarteten
/// Format `<RSA-verschlüsselter AES-Key>|<IV plus AES-Ciphertext>`.
Future<String> encryptV2Response(
  String clearBody,
  RSAPublicKey clientPublicKey,
) async {
  final manager = EncryptionManager();
  final aesKey = encrypt_plus.Key.fromSecureRandom(32);
  final encrypted =
      jsonDecode(
            await manager.encryptAES(clearBody, key: aesKey, padding: 'PKCS7'),
          )
          as Map<String, dynamic>;
  final mergedBody = Uint8List.fromList(<int>[
    ...base64Decode(encrypted['iv'] as String),
    ...base64Decode(encrypted['data'] as String),
  ]);
  final encryptedAesKey = await manager.encryptRSA(
    aesKey.bytes,
    publicKey: clientPublicKey,
  );

  return '${base64Encode(encryptedAesKey)}|${base64Encode(mergedBody)}';
}

/// Baut eine unveränderliche [RuntimeConfiguration] mit Test-Defaults für die
/// Session-/Login-Tests (u.a. mit `userName`/`device`/`additionalAppNames`,
/// die der generische `buildRuntimeConfiguration`-Helfer aus
/// `runtime_test_helpers.dart` nicht anbietet).
RuntimeConfiguration buildSessionRuntimeConfiguration({
  String serverUrl = 'https://mock.example:8443',
  String alias = 'dfapp',
  String appKey = 'TEST-APP-KEY',
  String userName = 'tester',
  List<String> appNames = const ['App1'],
  List<String> additionalAppNames = const [],
  RestApiDevice? device,
  String initialSessionId = '',
  bool multiRequest = false,
  int maxBufferSize = 10,
  int bufferFlushDelayMs = 100,
  Duration responseTimeout = const Duration(seconds: 5),
}) {
  return RuntimeConfiguration(
    serverUrl: serverUrl,
    baseUri: Uri.parse(serverUrl),
    alias: alias,
    appKey: appKey,
    userName: userName,
    appNames: List<String>.unmodifiable(appNames),
    additionalAppNames: List<String>.unmodifiable(additionalAppNames),
    device: device,
    connectionTimeout: const Duration(seconds: 5),
    responseTimeout: responseTimeout,
    allowSslError: false,
    debugLogs: false,
    useBase64UrlParameter: false,
    initialSessionId: initialSessionId,
    multiRequest: multiRequest,
    maxBufferSize: maxBufferSize,
    bufferFlushDelayMs: bufferFlushDelayMs,
  );
}
