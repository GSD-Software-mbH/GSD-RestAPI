import 'dart:async';

import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_file_upload_controller.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_upload_file.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

/// Führt den dreistufigen Datei-Upload des Legacy-Managers
/// (`uploadFile`/`uploadFileWithController`, bis 0.2.x) über den neuen Runtime aus - als
/// letzter Runtime-Koordinator (PR 3d).
///
/// Ablauf (identisch zum Legacy-Vertrag):
/// 1. `GET v1/uploadFile` (ohne ID!) liefert `data.uploadId` - über
///    [ApiRuntime.execute] mit [DataResponsePolicy]
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
///   uploadId) - `uploadFile` des Legacy-Managers behielt dafür die
///   lokale Variable aus `_getUploadID()` und verwirft das Ergebnis von
///   `_postUploadFile` vollständig.
/// - [uploadFileWithController] gibt dann die Antwort von SCHRITT 2 zurück
///   (POST) - `uploadFileWithController` initialisiert seine lokale
///   `restApiResponse`-Variable aus dem Ergebnis von `_postUploadFile` und
///   nicht aus `_getUploadID()`.
///
/// Einzig `fetchToObject` steuert, ob Schritt 3 läuft.
///
/// Eine fehlende/leere `data.uploadId` in Schritt 1 wirft SOFORT (siehe
/// [uploadFile]-Doku) - Schritt 2 wird dann NICHT versucht. Das ist eine
/// bewusste Abweichung vom Legacy-Manager, der `_postUploadFile`
/// unabhängig vom Ergebnis von Schritt 1 aufrief; ein Fehlerstatus wirft
/// ohnehin schon bei der Auswertung des Umschlags.
///
/// ### Abbruch
///
/// Abbruch ist NUR über [uploadFileWithController] möglich
/// (`controller.cancel()`, wie im Legacy-Manager fehlt [uploadFile] jede
/// Abbruchmöglichkeit). Siehe [_CancellableUploadController] für die
/// Design-Entscheidung, warum der öffentliche, unveränderte
/// `GsdFileUploadController` dafür intern erweitert statt 1:1
/// wiederverwendet wird.
@internal
class UploadExecutor {
  /// Erstellt einen noch nicht angebundenen Executor. Muss vor Verwendung
  /// über die `ApiRuntime`-Factory angebunden werden
  /// (`ApiRuntime(uploadExecutor: ...)`), die intern [attachTransport] und
  /// [attachRuntime] aufruft - analog zu `SessionCoordinator`/
  /// `BatchCoordinator`.
  UploadExecutor();

  static const String _fetchUploadIdOperation = 'v1.uploadFile.getId';

  ApiRuntime? _runtime;
  http.Client? _client;

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
  Future<Object?> uploadFile(
    GsdUploadFile file, {
    String replaceOID = '',
    bool fetchToObject = true,
  }) async {
    final uploadIdData = await _fetchUploadId();
    final uploadId = _extractUploadId(uploadIdData);

    await _postMultipart(file, uploadId);

    if (fetchToObject) {
      return _patchToObject(uploadId, replaceOID);
    }
    return uploadIdData;
  }

  /// Wie [uploadFile], aber über einen `GsdFileUploadController`
  /// steuerbar: Schritt 1 wird noch abgewartet (der Controller braucht die
  /// `uploadId` für seinen Konstruktor), Schritt 2 (Multipart-POST) und
  /// Schritt 3 (optionales PATCH) laufen danach im Hintergrund weiter -
  /// diese Methode kehrt bereits VOR deren Abschluss zurück.
  ///
  /// Siehe Klassendoku zur (von [uploadFile] abweichenden)
  /// Rückgabe-Semantik bei `fetchToObject: false` sowie zu Abbruch über
  /// `controller.cancel()`.
  Future<GsdFileUploadController> uploadFileWithController(
    GsdUploadFile file, {
    String replaceOID = '',
    bool fetchToObject = true,
  }) async {
    final uploadId = _extractUploadId(await _fetchUploadId());

    final controller = _CancellableUploadController(uploadId);

    unawaited(
      _runInBackground(
        controller: controller,
        file: file,
        uploadId: uploadId,
        replaceOID: replaceOID,
        fetchToObject: fetchToObject,
      ),
    );

    return controller;
  }

  Future<void> _runInBackground({
    required _CancellableUploadController controller,
    required GsdUploadFile file,
    required String uploadId,
    required String replaceOID,
    required bool fetchToObject,
  }) async {
    try {
      final postResponse = await _postMultipart(
        file,
        uploadId,
        isCancelled: () => controller.cancelRequested,
      );

      if (controller.cancelRequested) {
        // `cancel()` hat `controller.result` bereits mit
        // `GsdUploadCancelledException` abgeschlossen; Schritt 3 entfällt
        // bewusst, um kein ungewolltes Dokumentobjekt mehr anzulegen.
        return;
      }

      // Ab hier legt der Server das Objekt an; ein späterer Abbruch bewirkt
      // nichts mehr, und `result` liefert den Erfolg.
      controller.lockCancellation();

      if (fetchToObject) {
        final patchResponse = await _patchToObject(
          uploadId,
          replaceOID,
        );
        controller.complete(patchResponse);
      } else {
        controller.complete(postResponse);
      }
      // Jeder Fehler des Uploads geht unverändert an den Controller.
      // ignore: avoid_catches_without_on_clauses
    } catch (error) {
      controller.completeError(error);
    }
  }

  Future<Object?> _fetchUploadId() {
    return _requireRuntime.execute(
      const ApiRequest<Object?>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
        path: '/uploadFile',
        authentication: AuthenticationPolicy.session,
        responsePolicy: DataResponsePolicy<Object?>(),
        operationId: _fetchUploadIdOperation,
      ),
    );
  }

  /// Extrahiert `data.uploadId` aus `data` von Schritt 1.
  ///
  /// Wirft [GsdParseException], wenn `data.uploadId` fehlt, kein String
  /// oder leer ist. Der Legacy-Manager las stattdessen ungeprüft
  /// `jsonDecode(...)["data"]["uploadId"]`, was bei fehlendem `data`-Feld
  /// mit einer rohen `NoSuchMethodError`/`TypeError` abgestürzt wäre - hier
  /// bewusst durch eine saubere, dokumentierte Exception ersetzt (siehe
  /// Klassendoku).
  String _extractUploadId(Object? data) {
    final uploadId = data is Map<String, Object?> ? data['uploadId'] : null;

    if (uploadId is! String || uploadId.isEmpty) {
      throw GsdParseException(
        operationId: _fetchUploadIdOperation,
        path: 'data.uploadId',
      );
    }

    return uploadId;
  }

  Future<Object?> _patchToObject(String uploadId, String replaceOID) {
    return _requireRuntime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.patch,
        version: GsdApiVersion.v1,
        path: '/uploadFile/$uploadId',
        // Legacy-Parität (`_patchUploadFile`): der Query-Parameter fehlt
        // GANZ, wenn `replaceOID` leer ist - kein leerer `replaceOID=`.
        queryParameters: replaceOID.isEmpty ? null : {'replaceOID': replaceOID},
        authentication: AuthenticationPolicy.session,
        responsePolicy: const DataResponsePolicy<Object?>(),
        operationId: 'v1.uploadFile.patch',
      ),
    );
  }

  /// Schritt 2: Überträgt [file] als `multipart/form-data` an
  /// `POST v1/uploadFile/{uploadId}` - direkt über den rohen HTTP-Client
  /// (siehe Klassendoku, warum `HttpTransport` hier nicht genutzt wird).
  ///
  /// Wertet am Ende den Umschlag der Antwort aus und liefert `data` -
  /// genau wie der Legacy-`_postUploadFile` wirft ein Fehlerstatus.
  /// [uploadFile] verwirft dieses Ergebnis anschließend (siehe dortige
  /// Rückgabedokumentation); [uploadFileWithController] nutzt es bei
  /// `fetchToObject: false` als `result`.
  Future<Object?> _postMultipart(
    GsdUploadFile file,
    String uploadId, {
    bool Function()? isCancelled,
  }) async {
    _throwIfRuntimeDisposed();
    _throwIfCancelled(isCancelled);

    return _requireRuntime.executeExternalTransport(
      request: ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
        path: '/uploadFile/$uploadId',
        // Unterdrückt den JSON-Default. `MultipartRequest.finalize()` setzt
        // pro Versuch den echten Content-Type einschließlich neuer Boundary.
        contentType: '',
        authentication: AuthenticationPolicy.session,
        responsePolicy: const DataResponsePolicy<Object?>(),
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
          isCancelled == null
              ? rawFile
              : _cancellableMultipartFile(rawFile, isCancelled),
        );

        final http.StreamedResponse streamed;
        try {
          streamed = await _requireClient.send(request);
        } catch (error) {
          if (error is GsdUploadCancelledException) {
            rethrow;
          }
          if (isCancelled?.call() ?? false) {
            throw const GsdUploadCancelledException();
          }
          rethrow;
        }

        final httpResponse = await http.Response.fromStream(
          streamed,
        );
        return TransportResponse(
          statusCode: httpResponse.statusCode,
          headers: httpResponse.headers,
          bodyBytes: httpResponse.bodyBytes,
          body: httpResponse.body,
          reasonPhrase: httpResponse.reasonPhrase,
        );
      },
    );
  }

  void _throwIfCancelled(bool Function()? isCancelled) {
    if (isCancelled?.call() ?? false) {
      throw const GsdUploadCancelledException();
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
  /// Ein Pfad wird auf der IO-Plattform gelesen (`MultipartFile.fromPath`);
  /// im Web lässt sich ein [GsdUploadFile] mit Pfad gar nicht erst erzeugen.
  Future<http.MultipartFile> _buildMultipartFile(GsdUploadFile file) async {
    final path = file.path;
    if (path != null) {
      return http.MultipartFile.fromPath('', path, filename: file.name);
    }
    return http.MultipartFile.fromBytes('', file.bytes!, filename: file.name);
  }

  /// Verpackt den Byte-Stream von [source] so, dass er mit einem
  /// Abbruchfehler endet, statt weitere Bytes zu senden, sobald
  /// [isCancelled] `true` liefert.
  ///
  /// Best effort: Ob ein so ausgelöster Stream-Fehler den zugrundeliegenden
  /// `http.Client` tatsächlich veranlasst, die Verbindung sofort zu
  /// kappen, hängt von dessen Implementierung ab (echte IO-/Browser-Clients
  /// brechen typischerweise ab; ein reiner Test-Client könnte den Fehler
  /// erst beim Auslesen bemerken). Der Aufrufer (`_postMultipart`) fängt
  /// den Fehler in jedem Fall ab und ordnet ihn dem Abbruch zu.
  http.MultipartFile _cancellableMultipartFile(
    http.MultipartFile source,
    bool Function() isCancelled,
  ) {
    final cancellable = source.finalize().transform(
      StreamTransformer<List<int>, List<int>>.fromHandlers(
        handleData: (chunk, sink) {
          if (isCancelled()) {
            sink.addError(const GsdUploadCancelledException());
            return;
          }
          sink.add(chunk);
        },
      ),
    );

    return http.MultipartFile(
      source.field,
      cancellable,
      source.length,
      filename: source.filename,
      contentType: source.contentType,
    );
  }
}

/// Erweitert den öffentlichen, UNVERÄNDERTEN `GsdFileUploadController`
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
/// öffentliche Rückgabetyp-Signatur (`GsdFileUploadController`) zu
/// ändern - `cancel()` bleibt dank virtueller Methodendispatch auch bei
/// einer nach außen als `GsdFileUploadController` typisierten Referenz
/// wirksam überschrieben.
class _CancellableUploadController extends GsdFileUploadController {
  _CancellableUploadController(super.uploadId);
  bool _cancelRequested = false;
  bool _cancellationLocked = false;

  bool get cancelRequested => _cancelRequested;

  /// Schritt 3 startet: Ein Abbruch bewirkt ab jetzt nichts mehr.
  void lockCancellation() => _cancellationLocked = true;

  @override
  void cancel() {
    if (_cancellationLocked) {
      return;
    }
    _cancelRequested = true;
    super.cancel();
  }
}
