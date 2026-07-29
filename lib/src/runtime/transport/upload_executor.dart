import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';

import '../api_request.dart';
import '../api_runtime.dart';
import '../policies/authentication_policy.dart';
import '../policies/deduplication_policy.dart';
import '../policies/rest_api_response_policy.dart';
import '../transport_response.dart';

/// Meldet den Fortschritt des Multipart-Uploadschritts: [sentBytes] von
/// insgesamt [totalBytes] bereits an den HTTP-Client übergebenen
/// Datei-Bytes.
///
/// Bezieht sich NUR auf die reinen Dateibytes (`http.MultipartFile.length`),
/// nicht auf die zusätzlichen Multipart-Boundary-/Header-Bytes - der
/// tatsächlich auf die Leitung geschriebene Umfang ist dadurch geringfügig
/// größer als [totalBytes].
@internal
typedef UploadProgressCallback = void Function(int sentBytes, int totalBytes);

/// Führt den dreistufigen Datei-Upload des Legacy-Managers
/// (`RestApiDOCUframeManager.uploadFile`/`uploadFileWithController`,
/// `lib/legacy/restapidocuframemanager.dart`) über den neuen Runtime aus - als
/// letzter Runtime-Koordinator (PR 3d).
///
/// Ablauf (identisch zum Legacy-Vertrag):
/// 1. `GET v1/uploadFile` (ohne ID!) liefert `data.uploadId` - über
///    [ApiRuntime.execute] mit [RestApiResponsePolicy]
///    (`AuthenticationPolicy.session`, Deduplizierung deaktiviert).
///    `/uploadFile`-Pfade sind über `MultiRequestEligibility` zentral von
///    `v1/multi` ausgeschlossen.
/// 2. `POST v1/uploadFile/{uploadId}` überträgt die Datei als
///    `multipart/form-data`. `HttpTransport` unterstützt kein Multipart
///    (nur Methode/URI/Header/String-Body), daher sendet dieser Schritt
///    DIREKT über denselben rohen `http.Client` wie der Runtime (siehe
///    [attachTransport] - KEIN zweiter Client).
/// 3. Bei `fetchToObject: true`: `PATCH v1/uploadFile/{uploadId}` (mit
///    `?replaceOID=...`, sofern nicht leer) erstellt das Dokumentobjekt -
///    wieder über [ApiRuntime.execute].
///
/// ### Multipart-Wire-Format (Bugfix, nicht Bug-Kopie)
///
/// Der Legacy-`_postUploadFile` setzte einen Header
/// `content-type: application/x-www-form-urlencoded` - toter Code, denn
/// `http.MultipartRequest.finalize()` überschreibt `content-type`
/// UNBEDINGT mit `multipart/form-data; boundary=...` (die `headers`-Map
/// von `http.BaseRequest` vergleicht Schlüssel case-insensitiv). Der
/// Server erhielt also schon immer echtes `multipart/form-data` mit GENAU
/// EINEM Datei-Teil, dessen FELDNAME der leere String `''` ist (siehe
/// `http.MultipartFile.fromPath('', ...)`/`.fromBytes("", ...)` im
/// Legacy-Code). Dieser Executor reproduziert exakt dieses effektive
/// Wire-Verhalten (leerer Feldname, `filename: file.name`), setzt aber
/// erst gar keinen widersprüchlichen Content-Type-Header (`contentType:
/// ''` beim `HeaderProvider`) - der Bug wird bereinigt, nicht kopiert.
///
/// ### Rückgabe-Semantik: [uploadFile] vs. [uploadFileWithController]
///
/// Beide Methoden geben bei `fetchToObject: true` die Antwort von Schritt 3
/// (PATCH) zurück. Bei `fetchToObject: false` unterscheiden sie sich - eine
/// tatsächliche Legacy-Asymmetrie, keine Vereinfachung:
/// - [uploadFile] gibt dann die Antwort von SCHRITT 1 zurück (GET
///   uploadId) - `RestApiDOCUframeManager.uploadFile` behält dafür die
///   lokale Variable aus `_getUploadID()` und verwirft das Ergebnis von
///   `_postUploadFile` vollständig.
/// - [uploadFileWithController] gibt dann die Antwort von SCHRITT 2 zurück
///   (POST) - `uploadFileWithController` initialisiert seine lokale
///   `restApiResponse`-Variable aus dem Ergebnis von `_postUploadFile` und
///   nicht aus `_getUploadID()`.
///
/// [patch] wird - wie im Legacy-Manager - in KEINER der beiden Methoden
/// ausgewertet; er bleibt nur für Signaturkompatibilität erhalten. Einzig
/// [RestApiUploadFile]/`fetchToObject` steuert, ob Schritt 3 läuft.
///
/// Eine fehlende/leere `data.uploadId` in Schritt 1 wirft SOFORT (siehe
/// [uploadFile]-Doku) - Schritt 2 wird dann NICHT versucht. Das ist eine
/// bewusste Abweichung vom Legacy-Manager, der `_postUploadFile`
/// unabhängig vom Ergebnis von Schritt 1 aufrief; dessen nachgelagerte
/// `restApiResponse.isOk`-Prüfung war ohnehin unerreichbar (jede
/// `RestApiResponse`-Konstruktion mit einem Fehler-`internalStatus` wirft
/// bereits selbst, siehe `lib/shared/responses/restapiresponse.dart` - `isOk`
/// kann nach einer NICHT werfenden Konstruktion nie `false` sein).
///
/// ### Fortschritt und Abbruch
///
/// [onProgress] (beide Methoden) wird pro gelesenem Byte-Chunk der Datei
/// aufgerufen (kumulative gesendete Bytes / Gesamtlänge). Bei
/// `bytes`-Uploads liefert `http.MultipartFile.fromBytes` einen
/// Ein-Chunk-Stream (ein einziger Aufruf mit `sent == total`); bei
/// `path`-Uploads liest `dart:io` in mehreren Chunks.
///
/// Abbruch ist NUR über [uploadFileWithController] möglich
/// (`controller.cancel()`, wie im Legacy-Manager fehlt [uploadFile] jede
/// Abbruchmöglichkeit). Siehe [_CancellableUploadController] für die
/// Design-Entscheidung, warum der öffentliche, unveränderte
/// `RestAPIFileUploadController` dafür intern erweitert statt 1:1
/// wiederverwendet wird.
@internal
class UploadExecutor {
  ApiRuntime? _runtime;
  http.Client? _client;

  /// Erstellt einen noch nicht angebundenen Executor. Muss vor Verwendung
  /// über die `ApiRuntime`-Factory angebunden werden
  /// (`ApiRuntime(uploadExecutor: ...)`), die intern [attachTransport] und
  /// [attachRuntime] aufruft - analog zu `SessionCoordinator`/
  /// `BatchCoordinator`.
  UploadExecutor();

  /// Verbindet den Executor mit dem [ApiRuntime], über den die Schritte 1
  /// (Upload-ID holen) und 3 (Patch-auf-Objekt) laufen. Wird von der
  /// `ApiRuntime`-Factory genau einmal aufgerufen.
  void attachRuntime(ApiRuntime runtime) {
    if (_runtime != null && !identical(_runtime, runtime)) {
      throw StateError(
        'UploadExecutor ist bereits an einen anderen ApiRuntime gebunden.',
      );
    }
    _runtime = runtime;
  }

  /// Verbindet den Executor mit dem rohen HTTP-Client des angebundenen
  /// `ApiRuntime` - benötigt für Schritt 2 (Multipart-POST), den
  /// `HttpTransport` NICHT unterstützt
  /// (`http.MultipartRequest` ist ein gestreamtes `http.BaseRequest`, kein
  /// Methode/URI/Header/String-Body-Tupel).
  ///
  /// Bewusst KEIN eigener Client: Derselbe, vom Runtime injizierte oder
  /// plattformspezifisch erzeugte Client wird wiederverwendet (siehe
  /// `HttpTransport.client`), damit Tests einen `MockClient`/eigenen
  /// `http.BaseClient` injizieren können und der Client-Lifecycle (siehe
  /// `ApiRuntime.dispose`) an einer Stelle bleibt.
  void attachTransport({required http.Client client}) {
    if (_client != null && !identical(_client, client)) {
      throw StateError(
        'UploadExecutor ist bereits an einen anderen HTTP-Client gebunden.',
      );
    }
    _client = client;
  }

  ApiRuntime get _requireRuntime {
    final runtime = _runtime;
    if (runtime == null) {
      throw StateError(
        'UploadExecutor ist nicht an einen ApiRuntime gebunden; den '
        'Executor über die ApiRuntime-Factory anbinden '
        '(ApiRuntime(uploadExecutor: ...)).',
      );
    }
    return runtime;
  }

  http.Client get _requireClient {
    final client = _client;
    if (client == null) {
      throw StateError(
        'UploadExecutor ist nicht an einen HTTP-Client gebunden; den '
        'Executor über die ApiRuntime-Factory anbinden.',
      );
    }
    return client;
  }

  /// Lädt [file] in bis zu drei Schritten hoch und wartet auf den
  /// vollständigen Abschluss (siehe Klassendoku für Ablauf und
  /// Rückgabe-Semantik).
  ///
  /// Wirft, wenn Schritt 1 fehlschlägt ODER keine gültige `uploadId`
  /// liefert - Schritt 2 wird dann NICHT versucht (siehe Klassendoku).
  Future<RestApiResponse> uploadFile(
    RestApiUploadFile file, {
    String replaceOID = '',
    bool patch = true,
    bool fetchToObject = true,
    UploadProgressCallback? onProgress,
  }) async {
    final RestApiResponse uploadIdResponse = await _fetchUploadId();
    final String uploadId = _extractUploadId(uploadIdResponse);

    await _postMultipart(file, uploadId, onProgress: onProgress);

    if (fetchToObject) {
      return _patchToObject(uploadId, replaceOID);
    }
    return uploadIdResponse;
  }

  /// Wie [uploadFile], aber über einen `RestAPIFileUploadController`
  /// steuerbar: Schritt 1 wird noch abgewartet (der Controller braucht die
  /// `uploadId` für seinen Konstruktor), Schritt 2 (Multipart-POST) und
  /// Schritt 3 (optionales PATCH) laufen danach im Hintergrund weiter -
  /// diese Methode kehrt bereits VOR deren Abschluss zurück.
  ///
  /// Siehe Klassendoku zur (von [uploadFile] abweichenden)
  /// Rückgabe-Semantik bei `fetchToObject: false` sowie zu Abbruch über
  /// `controller.cancel()`.
  Future<RestAPIFileUploadController> uploadFileWithController(
    RestApiUploadFile file, {
    String replaceOID = '',
    bool patch = true,
    bool fetchToObject = true,
    UploadProgressCallback? onProgress,
  }) async {
    final RestApiResponse uploadIdResponse = await _fetchUploadId();
    final String uploadId = _extractUploadId(uploadIdResponse);

    final controller = _CancellableUploadController(uploadId);

    unawaited(
      _runInBackground(
        controller: controller,
        file: file,
        uploadId: uploadId,
        replaceOID: replaceOID,
        fetchToObject: fetchToObject,
        onProgress: onProgress,
      ),
    );

    return controller;
  }

  Future<void> _runInBackground({
    required _CancellableUploadController controller,
    required RestApiUploadFile file,
    required String uploadId,
    required String replaceOID,
    required bool fetchToObject,
    UploadProgressCallback? onProgress,
  }) async {
    try {
      final RestApiResponse postResponse = await _postMultipart(
        file,
        uploadId,
        onProgress: onProgress,
        isCancelled: () => controller.cancelRequested,
      );

      if (controller.cancelRequested) {
        // `cancel()` hat `controller.result` bereits (mit dem
        // Legacy-Fehler "Upload cancelled") abgeschlossen; Schritt 3
        // entfällt bewusst, um kein ungewolltes Dokumentobjekt mehr
        // anzulegen.
        return;
      }

      if (fetchToObject) {
        final RestApiResponse patchResponse = await _patchToObject(
          uploadId,
          replaceOID,
        );
        controller.complete(patchResponse);
      } else {
        controller.complete(postResponse);
      }
    } catch (error) {
      controller.completeError(error);
    }
  }

  Future<RestApiResponse> _fetchUploadId() {
    return _requireRuntime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/uploadFile',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.disabled,
        responsePolicy: const RestApiResponsePolicy(),
        operationId: 'v1.uploadFile.getId',
      ),
    );
  }

  /// Extrahiert `data.uploadId` aus der Antwort von Schritt 1.
  ///
  /// Wirft [WebServiceException], wenn `data.uploadId` fehlt, kein String
  /// oder leer ist. Der Legacy-Manager las stattdessen ungeprüft
  /// `jsonDecode(...)["data"]["uploadId"]`, was bei fehlendem `data`-Feld
  /// mit einer rohen `NoSuchMethodError`/`TypeError` abgestürzt wäre - hier
  /// bewusst durch eine saubere, dokumentierte Exception ersetzt (siehe
  /// Klassendoku).
  String _extractUploadId(RestApiResponse response) {
    final dynamic decoded = jsonDecode(response.httpResponse.body);
    final dynamic data = decoded is Map<String, dynamic>
        ? decoded['data']
        : null;
    final dynamic uploadId = data is Map<String, dynamic>
        ? data['uploadId']
        : null;

    if (uploadId is! String || uploadId.isEmpty) {
      throw WebServiceException(
        'GET v1/uploadFile lieferte keine gültige uploadId in '
        '"data.uploadId".',
        response.internalStatus,
        response.statusMessage,
      );
    }

    return uploadId;
  }

  Future<RestApiResponse> _patchToObject(String uploadId, String replaceOID) {
    return _requireRuntime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.patch,
        version: ApiVersion.v1,
        path: '/uploadFile/$uploadId',
        // Legacy-Parität (`_patchUploadFile`): der Query-Parameter fehlt
        // GANZ, wenn `replaceOID` leer ist - kein leerer `replaceOID=`.
        queryParameters: replaceOID.isEmpty ? null : {'replaceOID': replaceOID},
        authentication: AuthenticationPolicy.session,
        responsePolicy: const RestApiResponsePolicy(),
        operationId: 'v1.uploadFile.patch',
      ),
    );
  }

  /// Schritt 2: Überträgt [file] als `multipart/form-data` an
  /// `POST v1/uploadFile/{uploadId}` - direkt über den rohen HTTP-Client
  /// (siehe Klassendoku, warum `HttpTransport` hier nicht genutzt wird).
  ///
  /// Konstruiert (und validiert) am Ende eine [RestApiResponse] aus der
  /// Antwort - genau wie der Legacy-`_postUploadFile` (wirft bei einem
  /// Fehler-Envelope). [uploadFile] verwirft dieses Ergebnis anschließend
  /// (siehe dortige Rückgabedokumentation); [uploadFileWithController]
  /// nutzt es bei `fetchToObject: false` als `result`.
  Future<RestApiResponse> _postMultipart(
    RestApiUploadFile file,
    String uploadId, {
    UploadProgressCallback? onProgress,
    bool Function()? isCancelled,
  }) async {
    _throwIfRuntimeDisposed();
    _throwIfCancelled(isCancelled);

    return _requireRuntime.executeExternalTransport(
      request: ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v1,
        path: '/uploadFile/$uploadId',
        // Unterdrückt den JSON-Default. `MultipartRequest.finalize()` setzt
        // pro Versuch den echten Content-Type einschließlich neuer Boundary.
        contentType: '',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.disabled,
        responsePolicy: const RestApiResponsePolicy(),
        operationId: 'v1.uploadFile.postMultipart',
      ),
      send: (uri, headers) async {
        _throwIfCancelled(isCancelled);

        // Dieser Block läuft bei einem Session-Retry erneut. Request,
        // Boundary, MultipartFile und Datei-Stream sind deshalb niemals
        // wiederverwendet.
        final request = http.MultipartRequest('POST', uri)
          ..headers.addAll(headers);
        final rawFile = await _buildMultipartFile(file);

        _throwIfCancelled(isCancelled);
        request.files.add(
          onProgress == null && isCancelled == null
              ? rawFile
              : _instrumentedMultipartFile(
                  rawFile,
                  onProgress: onProgress,
                  isCancelled: isCancelled,
                ),
        );

        final http.StreamedResponse streamed;
        try {
          streamed = await _requireClient.send(request);
        } catch (error) {
          if (error is _UploadCancelledException) {
            rethrow;
          }
          if (isCancelled?.call() ?? false) {
            throw const _UploadCancelledException();
          }
          rethrow;
        }

        final http.Response httpResponse = await http.Response.fromStream(
          streamed,
        );
        return TransportResponse(
          statusCode: httpResponse.statusCode,
          headers: httpResponse.headers,
          bodyBytes: httpResponse.bodyBytes,
          body: httpResponse.body,
        );
      },
    );
  }

  void _throwIfCancelled(bool Function()? isCancelled) {
    if (isCancelled?.call() ?? false) {
      throw const _UploadCancelledException();
    }
  }

  /// Wirft [StateError] (gleiche Vertragsform wie der Disposed-Guard von
  /// [ApiRuntime.execute]), wenn der angebundene Runtime bereits über
  /// [ApiRuntime.dispose] freigegeben wurde.
  ///
  /// Schritt 1 (`_fetchUploadId`) und Schritt 3 (`_patchToObject`) laufen
  /// über [ApiRuntime.execute] und sind dadurch bereits selbst geschützt.
  /// Schritt 2 (dieser Aufrufer, [_postMultipart]) sendet dagegen DIREKT
  /// über den rohen HTTP-Client (siehe Klassendoku) - ohne diese Prüfung
  /// könnte ein Multipart-POST nach [ApiRuntime.dispose] noch laufen (bei
  /// einem vom Runtime selbst erzeugten, dann bereits geschlossenen Client
  /// nur mit einem opaken "client closed"-Fehler statt eines klaren
  /// [StateError]).
  void _throwIfRuntimeDisposed() {
    if (_requireRuntime.isDisposed) {
      throw StateError(
        'ApiRuntime wurde bereits mit dispose() freigegeben; '
        'Datei-Upload (Multipart-POST) ist nicht mehr erlaubt.',
      );
    }
  }

  /// Baut die effektive Wire-Repräsentation der Legacy-Datei-Übertragung
  /// nach (siehe Klassendoku): EIN Multipart-Teil mit leerem Feldnamen.
  ///
  /// `isPath && !kIsWeb`: liest die Datei über `dart:io`
  /// (`MultipartFile.fromPath`). Sonst (Bytes ODER `isPath` unter Web -
  /// Legacy-Quirk, siehe Klassendoku/`RestApiUploadFile`-Doku: Web-Aufrufer
  /// sollen `.fromBytes` verwenden) werden `file.bytes` gesendet - `?? []`
  /// wie im Legacy-Manager, falls `bytes` (Pfad-Fall unter Web) `null` ist.
  Future<http.MultipartFile> _buildMultipartFile(RestApiUploadFile file) async {
    if (file.isPath && !kIsWeb) {
      return http.MultipartFile.fromPath('', file.path!, filename: file.name);
    }
    return http.MultipartFile.fromBytes(
      '',
      file.bytes ?? const [],
      filename: file.name,
    );
  }

  /// Verpackt den Byte-Stream von [source] so, dass jeder gelesene Chunk
  /// [onProgress] meldet (kumulative gesendete Bytes, Gesamtlänge aus
  /// `MultipartFile.length`) und - falls [isCancelled] zwischenzeitlich
  /// `true` liefert - der Stream mit einem Abbruchfehler endet, statt
  /// weitere Bytes zu senden.
  ///
  /// Best effort: Ob ein so ausgelöster Stream-Fehler den zugrundeliegenden
  /// `http.Client` tatsächlich veranlasst, die Verbindung sofort zu
  /// kappen, hängt von dessen Implementierung ab (echte IO-/Browser-Clients
  /// brechen typischerweise ab; ein reiner Test-Client könnte den Fehler
  /// erst beim Auslesen bemerken). Der Aufrufer (`_postMultipart`) fängt
  /// den Fehler in jedem Fall ab und ordnet ihn dem Abbruch zu.
  http.MultipartFile _instrumentedMultipartFile(
    http.MultipartFile source, {
    required UploadProgressCallback? onProgress,
    required bool Function()? isCancelled,
  }) {
    final int total = source.length;
    var sent = 0;

    final Stream<List<int>> instrumented = source.finalize().transform(
      StreamTransformer<List<int>, List<int>>.fromHandlers(
        handleData: (chunk, sink) {
          if (isCancelled?.call() ?? false) {
            sink.addError(const _UploadCancelledException());
            return;
          }
          sent += chunk.length;
          onProgress?.call(sent, total);
          sink.add(chunk);
        },
      ),
    );

    return http.MultipartFile(
      source.field,
      instrumented,
      total,
      filename: source.filename,
      contentType: source.contentType,
    );
  }
}

/// Interner Abbruchfehler für einen laufenden Multipart-Versand.
///
/// Wird NIE nach außen an Aufrufer von [UploadExecutor] gereicht: Der
/// öffentliche `RestAPIFileUploadController.cancel()`
/// (`lib/shared/restapifileuploadcontroller.dart`) schließt `result` bereits
/// synchron mit dem unveränderten Legacy-Fehler (dem String
/// `"Upload cancelled"`) ab, bevor der Hintergrundprozess diesen Fehler
/// überhaupt sehen könnte.
class _UploadCancelledException implements Exception {
  const _UploadCancelledException();

  @override
  String toString() =>
      'Upload cancelled (intern, siehe RestAPIFileUploadController.cancel)';
}

/// Erweitert den öffentlichen, UNVERÄNDERTEN `RestAPIFileUploadController`
/// (`lib/shared/restapifileuploadcontroller.dart`) um einen intern abfragbaren
/// Abbruch-Zustand.
///
/// ENTSCHEIDUNG (siehe PR-Bericht): Der Legacy-Controller passt unverändert
/// für `result`/`complete`/`completeError` - dessen eigener
/// Completer-Schutz (`if (!_cancelled && !_completer.isCompleted)`)
/// verhindert bereits zuverlässig, dass nach `cancel()` noch ein Ergebnis
/// nach außen dringt. Er bietet aber KEINEN Hook, über den ein
/// Hintergrundprozess einen laufenden Abbruch erkennen könnte (`_cancelled`
/// ist privat, kein Getter, kein Callback/Stream). Ohne einen solchen Hook
/// würde der Hintergrundprozess nach einem Abbruch weiterhin sinnlos
/// Bandbreite verschwenden (Multipart-Versand zu Ende führen) UND einen
/// unerwünschten Seiteneffekt auslösen (PATCH legt trotzdem ein
/// Dokumentobjekt an). Eine private Unterklasse mit einem zusätzlichen,
/// lesbaren Flag löst das, OHNE die Legacy-Datei zu verändern und OHNE die
/// öffentliche Rückgabetyp-Signatur (`RestAPIFileUploadController`) zu
/// ändern - `cancel()` bleibt dank virtueller Methodendispatch auch bei
/// einer nach außen als `RestAPIFileUploadController` typisierten Referenz
/// wirksam überschrieben.
class _CancellableUploadController extends RestAPIFileUploadController {
  bool _cancelRequested = false;

  _CancellableUploadController(super.uploadId);

  bool get cancelRequested => _cancelRequested;

  @override
  void cancel() {
    _cancelRequested = true;
    super.cancel();
  }
}
