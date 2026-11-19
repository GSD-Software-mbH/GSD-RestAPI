// Test-Harness für die Tests gegen einen echten HTTP-Server.
//
// Startet einen echten `dart:io` HttpServer auf 127.0.0.1 (ephemeral port),
// zeichnet eingehende Requests auf (Methode, Pfad, Query, Header, Body) und
// erlaubt es Tests, pro Methode+Pfad Antworten einzuplanen (FIFO-Queue).
//
// Außerdem: Hilfsfunktionen für den v2/login Verschlüsselungs-Roundtrip.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/crypto/rsa_key_generator.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// Eine vom Test-Server aufgezeichnete eingehende HTTP-Anfrage.
class RecordedRequest {
  RecordedRequest({
    required this.method,
    required this.path,
    required this.query,
    required this.headers,
    required this.body,
  });
  final String method;
  final String path;
  final Map<String, String> query;
  final Map<String, String> headers;
  final String body;

  /// Case-insensitive Header-Lookup (dart:io normalisiert eingehende
  /// Header-Namen ohnehin auf Kleinschreibung).
  String? header(String name) => headers[name.toLowerCase()];

  @override
  String toString() =>
      'RecordedRequest($method $path, query: $query, headers: $headers, '
      'body: $body)';
}

/// Eine eingeplante Antwort des Test-Servers.
class ScriptedResponse {
  ScriptedResponse(
    this.body, {
    this.statusCode = 200,
    this.headers,
    this.delay = Duration.zero,
  });
  final int statusCode;
  final String body;
  final Map<String, String>? headers;

  /// Optionale künstliche Verzögerung, bevor die Antwort geschrieben wird.
  /// Nützlich, um überlappende (nebenläufige) Requests zu erzwingen.
  final Duration delay;
}

typedef ResponseBuilder =
    FutureOr<ScriptedResponse> Function(RecordedRequest request);

/// Lokaler HTTP-Test-Server.
///
/// Requests werden per "METHOD path" (ohne Query) in einer FIFO-Queue
/// abgearbeitet. Ist die Queue für einen Pfad leer, greift ein optionaler
/// Fallback-Handler, ansonsten wird 404 mit einem Fehler-Envelope
/// zurückgegeben (fällt in Tests sofort auf, wenn ein Request unerwartet war).
class TestServer {
  late final HttpServer _server;
  final List<RecordedRequest> requests = [];
  final Map<String, Queue<ResponseBuilder>> _queues = {};
  ResponseBuilder? fallback;
  bool _secure = false;

  /// Startet den Server. Mit [securityContext] spricht er HTTPS statt
  /// Klartext-HTTP.
  Future<void> start({SecurityContext? securityContext}) async {
    _secure = securityContext != null;
    _server = securityContext == null
        ? await HttpServer.bind(InternetAddress.loopbackIPv4, 0)
        : await HttpServer.bindSecure(
            InternetAddress.loopbackIPv4,
            0,
            securityContext,
          );
    _server.listen(_handle);
  }

  int get port => _server.port;

  String get baseUrl => '${_secure ? 'https' : 'http'}://127.0.0.1:$port';

  Future<void> close() async {
    await _server.close(force: true);
  }

  String _key(String method, String path) => '${method.toUpperCase()} $path';

  /// Plant eine Antwort für [method] + [path] ein (FIFO je Pfad).
  void enqueue(String method, String path, ResponseBuilder builder) {
    _queues.putIfAbsent(_key(method, path), Queue.new).add(builder);
  }

  /// Bequemlichkeitsmethode: plant eine JSON-Antwort ein.
  void enqueueJson(
    String method,
    String path, {
    required Map<String, dynamic> body,
    int statusCode = 200,
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
          TestServer.v1Envelope(
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

  /// Baut das V1-Antwort-Envelope: {"status": {...}, "data": {...}}
  static Map<String, dynamic> v1Envelope({
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

  /// Erzeugt ein neues (vom Schlüsselpaar des Clients unabhängiges) RSA
  /// Schlüsselpaar, das den "Server" in den Login-Tests repräsentiert.
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>>
  generateServerKeyPair({
    int bitLength = 2048,
  }) {
    return RsaKeyGenerator.generate(bitLength: bitLength);
  }

  /// Kodiert einen öffentlichen RSA-Schlüssel als sauberes, standardkonformes
  /// PEM (SPKI, keine Einrückung).
  ///
  /// Hinweis: Der Client sendet seinen Schlüssel in der eingerückten Form von
  /// `gsd_encryption` 0.1.28 (`Pem.encodePublicKey`). Reale Server liefern
  /// ihren Schlüssel als sauberes PEM ohne Einrückung, das bilden wir hier
  /// nach.
  static String encodePublicKeyToCleanPem(RSAPublicKey publicKey) {
    final asn1Seq = ASN1Sequence()
      ..add(ASN1Integer(publicKey.modulus))
      ..add(ASN1Integer(publicKey.exponent));
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

  /// Entschlüsselt einen von `SessionCoordinator.login`
  /// produzierten Request-Body (`{aesKey, data, publicKey}`) mit dem
  /// privaten Schlüssel des "Servers" und liefert den ursprünglichen
  /// Klartext-JSON-String zurück.
  ///
  /// Dies beweist, dass die echte RSA/AES-Verschlüsselung des Login-Codes
  /// funktioniert, statt nur die Form des Bodys zu prüfen.
  static Future<String> decryptV2LoginBody(
    String requestBody,
    RSAPrivateKey serverPrivateKey,
  ) async {
    final map = jsonDecode(requestBody) as Map<String, dynamic>;
    final aesKey = HandshakeCrypto.rsaDecrypt(
      base64Decode(map['aesKey'] as String),
      serverPrivateKey,
    );

    final merged = base64Decode(map['data'] as String);
    return utf8.decode(
      HandshakeCrypto.aesDecrypt(
        merged.sublist(HandshakeCrypto.ivLength),
        key: aesKey,
        iv: merged.sublist(0, HandshakeCrypto.ivLength),
      ),
    );
  }

  /// Baut eine GsdApiConfig, die auf den lokalen [server] zeigt.
  ///
  /// `allowSslError: true` (Standard) ist für den Klartext-HTTP-Server
  /// zwingend nötig (der Transport würde sonst mit GsdSecurityException
  /// ablehnen) und lässt beim HTTPS-Server das selbstsignierte Zertifikat zu.
  static GsdApiConfig buildTestConfig(
    TestServer server, {
    String alias = 'dfapp',
    String appKey = 'TEST-APP-KEY',
    String userName = 'tester',
    List<String>? appNames,
    bool multiRequest = false,
    int maxBufferSize = 10,
    int bufferFlushDelayMs = 100,
    bool allowSslError = true,
  }) {
    return GsdApiConfig(
      appKey: appKey,
      userName: userName,
      appNames: appNames ?? ['TestApp'],
      serverUrl: server.baseUrl,
      alias: alias,
      allowSslError: allowSslError,
      multiRequest: multiRequest,
      maxBufferSize: maxBufferSize,
      bufferFlushDelayMs: bufferFlushDelayMs,
    );
  }
}
