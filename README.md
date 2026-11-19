# GSD RestAPI

Dart-Client für die DOCUframe REST-API mit verschlüsseltem Login, Session-Erneuerung, 2FA,
nativen V1-/V3-Endpunkten, Multi-Requests, Uploads und Telemetrie. Reines Dart: läuft auf der
VM, in Flutter-Apps und im Browser.

[Schnellstart](#schnellstart) · [API-Überblick](#api-überblick) ·
[Authentifizierung](#authentifizierung-und-sessions) · [Fehler](#fehler) ·
[Ereignisse](#ereignisse) · [HTTP-Client](#eigener-http-client) ·
[Migration](#migration-von-02)

## Funktionsumfang

- verschlüsselter Login mit automatischer Session-Erneuerung und 2FA
- 15 fachlich gruppierte V1-APIs und native V3-Endpunkte
- Modelle für Antworten mit bekannter Form, sonst das dekodierte `data`
- typisierte Request-Modelle für V3
- Fehler als `sealed`-Hierarchie `GsdApiException`
- Multi-Request-Bündelung, Deduplizierung und Request-Prioritäten
- Datei- und Preview-Downloads sowie abbrechbare Uploads
- Session-, Log- und Metrik-Ereignisse als Streams
- injizierbarer `http.Client`
- kontrollierter Raw-Zugang für kundenspezifische Endpunkte

## Installation

Voraussetzung ist Dart `^3.10.0`.

```shell
dart pub add gsd_restapi
```

## Schnellstart

```dart
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

Future<void> main() async {
  final api = GsdApiClient(
    configuration: GsdApiConfig(
      appKey: 'GSD-DFApp',
      userName: 'GSDAdmin',
      appNames: const ['GSD-RestApi', 'GSD-DFApp'],
      serverUrl: 'https://127.0.0.1:8080',
      alias: 'dfapp',
      multiRequest: true,
    ),
  );
  final sessionIds = api.sessionIdChanges.listen((sessionId) {
    // Neue oder geleerte Session-ID speichern.
  });

  try {
    // DOCUframe erwartet den MD5-Hash, nicht das Klartextpasswort.
    final md5Password = md5.convert(utf8.encode('mein-passwort')).toString();
    final login = await api.v1.authentication.login(md5Password);
    print(login.sessionId);

    final Object? objects = await api.v1.objects.getObjects('Dokument');
    print(objects);
  } on GsdApiException catch (error) {
    print('${error.runtimeType}: ${error.message}');
  } finally {
    await api.dispose();
    await sessionIds.cancel();
  }
}
```

Ein lauffähiges Beispiel mit Zugangsdaten aus Umgebungsvariablen steht in
[`example/example.dart`](example/example.dart).

## API-Überblick

Alle Gruppen eines `GsdApiClient` teilen sich dieselbe Session, Runtime und denselben
HTTP-Client:

| Zugriff | Aufgabe |
| --- | --- |
| `api.v1` | native, fachlich gruppierte V1-Funktionen |
| `api.v3` | native V3-Funktionen |
| `api.raw` | kontrollierter Zugang für nicht native Endpunkte |
| `api.sessionId`, `api.isAuthenticated` | aktuelle Session |
| `api.sessionIdChanges`, `licenseErrors`, `invalidCredentials`, `logs`, `httpMetrics` | Ereignisse |
| `api.executeWithoutBuffering(...)` | führt einen Scope ohne Buffering aus |
| `api.executeWithPriority(...)` | setzt die Priorität eines Scopes |
| `api.hasPendingRequests`, `pendingRequestCount`, `waitForIdle()` | laufende Requests |
| `api.runtimeSettings`, `updateRuntimeSettings(...)` | Runtime-Werte, im Idle-Zustand änderbar |
| `api.device`, `setDevice(...)` | Login-Gerät lesen, ersetzen oder entfernen |
| `api.dispose()`, `isDisposed` | gibt Client, Timer und Streams frei |

Client und Gruppen sind einfache Klassen; Tests können sie mit `mocktail` mocken.

### Native V1-Gruppen

| Gruppe | Zugriff | Inhalt |
| --- | --- | --- |
| Authentication | `api.v1.authentication` | Login, Logout, Sessions und 2FA |
| Service | `api.v1.service` | Erreichbarkeit, Lizenzfreigabe und Version |
| Account | `api.v1.account` | Demo-Accounts |
| Appointments | `api.v1.appointments` | Termine, Serien und Einladungen |
| Documents | `api.v1.documents` | Dateien, Previews, Status und Uploads |
| Folders | `api.v1.folders` | Ordnernavigation und Ordneroperationen |
| Integrations | `api.v1.integrations` | Makros und Anrufe |
| xSync | `api.v1.xSync` | Sync-Klassen und Sync-Objekte |
| Mail | `api.v1.mail` | E-Mails erstellen, bearbeiten und senden |
| Messages | `api.v1.messages` | interne Nachrichten |
| Models | `api.v1.models` | Modellstruktur und Wörterbücher |
| Objects | `api.v1.objects` | Objekte, Aktionen, Locks und Rechte |
| Personal | `api.v1.personal` | ungelesene Dokumente, Aufgaben und Papierkorb |
| Settings | `api.v1.settings` | Benutzer- und Systemeinstellungen |
| Time Recording | `api.v1.timeRecording` | PZE, Zeitschlüssel und Zeitkonten |

Antworten mit bekannter Form kommen als Modell:

| Endpunkt | Rückgabe |
| --- | --- |
| `v1.authentication.login` | `GsdLoginResult` |
| `v1.authentication.get2FASecret` | `GsdTwoFactorSecret` |
| `v1.service.checkService`, `checkServiceWithUri` | `GsdCheckServiceResult` |
| `v1.service.getVersionInfo` | `GsdVersionInfo` |
| `v1.objects.getLockObject` | `GsdObjectLock` |
| `v1.settings.getUserSystemSettings` | `GsdUserSystemSettings` |
| `v1.xSync.getSyncObjectsOfClass` | `GsdSyncObjectsResult` |
| `v1.documents.getFile` | `GsdFileDownload` (Bytes und Header) |
| `v1.documents.getPreview` | `Uint8List?` |
| `v1.documents.uploadFileWithController` | `GsdFileUploadController` |

Alle übrigen V1-Endpunkte liefern das dekodierte `data` der Antwort als `Object?`:

```dart
final Object? folder = await api.v1.folders.getFolderByType('Eingang');

final Object? object = await api.v1.objects.getObject(
  'OBJECT-OID',
  serialization: 'edit',
);
```

### Native V3-Endpunkte

| HTTP-Endpunkt | Zugriff | Request | Rückgabe |
| --- | --- | --- | --- |
| `POST v3/model/structure` | `api.v3.model.structure(...)` | `List<GsdStructureRequest>` | `List<Object?>` |
| `GET v3/versionInfo` | `api.v3.system.versionInfo()` | – | `Map<String, Object?>` |
| `GET v3/appConfig` | `api.v3.system.appConfig()` | – | `List<Object?>` |
| `GET v3/appTheme` | `api.v3.system.appTheme()` | – | `List<Object?>` |
| `POST v3/view/load` | `api.v3.view.load(...)` | `List<GsdViewLoadRequest>` | `List<Object?>` |
| `POST v3/view/action` | `api.v3.view.action(...)` | `GsdViewActionRequest` | `Map<String, Object?>` (ganzer Body) |
| `POST v3/objectdata/byid` | `api.v3.objectData.getById(...)` | `List<GsdObjectsByIdRequest>` | `List<Object?>` |
| `POST v3/objectdata/byQuery` | `api.v3.objectData.getByQuery(...)` | `List<GsdObjectsByQueryRequest>` | `List<Object?>` |
| `POST v3/objectdata/byParentObject` | `api.v3.objectData.getByParentObject(...)` | `List<GsdObjectsByParentRequest>` | `List<Object?>` |
| `GET v3/file/{oid}` | `api.v3.file.get(...)` | – | `GsdFileDownload` |

```dart
final objects = await api.v3.objectData.getById([
  const GsdObjectsByIdRequest(classId: 100, context: 'edit', ids: [200, 201]),
]);
```

`api.v3.file.get()` lädt Binärinhalte und liefert Bytes und Header (`content-type`,
`content-disposition`), ohne Entschlüsselung und ohne `v1/multi`-Buffering. Bei
E-Mail-Anhängen kann als `oid` die OID des Abschnitts oder die des Anhangs verwendet werden. Die
Zusatzparameter sind optional und werden nur gesendet, wenn sie gesetzt sind:

| Parameter | Wirkung |
| --- | --- |
| `page` | Seitenzahl bei mehrseitigen Dokumenten |
| `usePdf` | liefert die PDF-Repräsentation statt des Originals |
| `attachItem` | Index des E-Mail-Anhangs, wenn `oid` eine E-Mail ist |
| `zipItem` | Index des Items innerhalb eines ZIP-Anhangs |
| `maxSize` | verkleinert Bilder; der Wert definiert die kurze Seite |

```dart
// GET v3/file/1PTF?page=3
final file = await api.v3.file.get('1PTF', page: 3);
final Uint8List bytes = file.bytes;
```

## Authentifizierung und Sessions

### Anmelden

`login()` erwartet ein bereits MD5-gehashtes Passwort:

```dart
final GsdLoginResult login = await api.v1.authentication.login(
  md5Password,
  twoFactorAuthToken: token,
);
```

Verlangt der Server beim Login einen 2FA-Token, wirft `login()`
`GsdTwoFactorTokenMissingException`; die Anwendung fragt den Token ab und ruft `login()` erneut.

Recoverbare Sessionfehler behandelt die Runtime einmal: Sie erneuert die Session und wiederholt
den Request. Parallele Refresh-Anforderungen verwenden denselben laufenden Refresh. Verlangt der
Server dabei einen 2FA-Token, fragt sie den `twoFactorTokenProvider`:

```dart
final api = GsdApiClient(
  configuration: configuration,
  twoFactorTokenProvider: () async => showTwoFactorDialog(),
);
```

### Gespeicherte Session

Eine gespeicherte Session geht an den Konstruktor; mit dem Passwort wird sie refresh-fähig:

```dart
final api = GsdApiClient(
  configuration: configuration,
  sessionId: storedSessionId,
);
api.v1.authentication.setPassword(storedMd5Password);
```

Alternativ setzt `restoreSession` Session und Passwort zusammen:

```dart
api.v1.authentication.restoreSession(
  storedSessionId,
  md5Password: storedMd5Password,
);
```

Ein leeres Passwort deaktiviert die automatische Wiederanmeldung.

### Abmelden und freigeben

`dispose()` meldet sich bewusst nicht beim Server ab:

```dart
try {
  await api.v1.authentication.logout();
} finally {
  await api.dispose();
}
```

`dispose()` ist asynchron und idempotent. Es bricht einen laufenden Refresh ab, beantwortet eine
offene 2FA-Anfrage mit `''`, schließt Batch und HTTP-Client und zuletzt die Streams. Jede
Haupt-, Demo- oder temporäre Instanz muss freigegeben werden.

## Fehler

Ein Fehlerstatus wirft. Alle Exceptions des Pakets erben von der `sealed`-Basis
`GsdApiException`:

```text
GsdApiException (sealed)            message
├── GsdHttpException                statusCode, reasonPhrase
├── GsdParseException               operationId, path
├── GsdSecurityException            (http:// ohne allowSslError)
├── GsdUploadCancelledException
└── GsdServerException              internalStatus, statusMessage
    ├── GsdSessionInvalidException (201), GsdSessionMissingException (204)
    ├── GsdInvalidCredentialsException (302), GsdLicenseException (306, 101)
    ├── GsdTwoFactorRequiredException (340)
    └── GsdTwoFactorTokenMissingException (341), GsdTwoFactorTokenInvalidException (342)
```

```dart
try {
  await api.v1.objects.getObjects('Dokument');
} on GsdApiException catch (error) {
  switch (error) {
    case GsdServerException(:final statusMessage):
      showError(statusMessage);
    case GsdHttpException() || GsdParseException():
      showTechnicalError(error);
    case GsdSecurityException() || GsdUploadCancelledException():
      rethrow;
  }
}
```

- Der Umschlag-Status geht vor dem HTTP-Status, für Einzelantworten wie für `v1/multi`-Einträge.
- Ein Body ohne JSON wirft bei HTTP-Status ungleich 2xx `GsdHttpException`, sonst
  `GsdParseException`.
- Passt ein Feld nicht zum Modell, wirft `GsdParseException` mit `operationId` und Pfad, nie mit
  dem Body.
- Transportfehler (`SocketException`, `ClientException`, `TimeoutException`) gehen unverändert
  durch.

## Ereignisse

Ereignisse kommen als synchrone Broadcast-Streams am Client:

| Stream | Inhalt |
| --- | --- |
| `sessionIdChanges` | jede neue Session-ID; `''` nach Logout und Login-Fehlern |
| `licenseErrors` | `GsdLicenseException`, bevor sie beim Aufrufer ankommt |
| `invalidCredentials` | `GsdInvalidCredentialsException`, bevor sie beim Aufrufer ankommt |
| `logs` | Log-Zeilen; Header-Werte und Bodies sind redigiert |
| `httpMetrics` | eine `GsdHttpMetric` je abgeschlossenem HTTP-Request |

Ohne Listener geht ein Ereignis verloren. Deshalb direkt nach dem Konstruktor zuhören und das Abo
erst nach `await dispose()` kündigen.

## Eigener HTTP-Client

Wer jeden Request beeinflussen will (Verzögerung, Proxy, Tests), übergibt einen
`http.Client`. Der Client übernimmt ihn und schließt ihn in `dispose()`:

```dart
final api = GsdApiClient(
  configuration: configuration,
  httpClient: DelayingHttpClient(
    GsdApiClient.createHttpClient(allowSslError: configuration.allowSslError),
  ),
);
```

`GsdApiClient.createHttpClient` erzeugt den Client, den er sonst selbst nutzt: auf IO mit
`allowSslError` und `connectionTimeout`, im Web einen `BrowserClient`. Die HTTPS-Pflicht
(`http://` nur mit `allowSslError`) gilt auch für einen übergebenen Client.

## Raw-Zugang

`api.raw` ist der kontrollierte Zugang für Endpunkte ohne native Methode:

```dart
final GsdRawApiResponse response = await api.raw.request(
  version: GsdApiVersion.v1,
  method: GsdHttpMethod.post,
  path: '/Abwesenheitsantrag/$oid/$action',
  queryParameters: {'mode': 'preview'},
  body: '{"value":42}',
);

if (response.statusCode == 200) {
  print(response.body);
}
```

- `path` enthält weder Server, Alias noch Versionspräfix; die Version kommt aus `version`.
- Query-Parameter gehören in `queryParameters`.
- Absolute URLs, Traversal, Backslashes, Query und Fragmente im Pfad werden abgelehnt.
- Raw-Requests werden weder gepuffert noch dedupliziert.
- HTTP-Fehler kommen als `GsdRawApiResponse` zurück; Transportfehler werfen.
- Raw verwendet dieselbe Session-Erneuerung wie native Requests.

## Multi-Request und Prioritäten

Multi-Request wird über die Konfiguration aktiviert. Geeignete parallele V1-Aufrufe innerhalb
des Flush-Fensters werden über `POST v1/multi` gebündelt:

```dart
final pages = await Future.wait([
  for (var page = 0; page < 10; page++)
    api.v1.objects.getObjects('Dokument', page: page),
]);
```

Ein einzelner gepufferter Aufruf wird direkt gesendet. Login, Logout, Session- und
Service-Checks, Uploads, Datei- und Preview-Downloads, Sync, Raw und V3 laufen ebenfalls direkt.

Buffering und Priorität lassen sich für einen ganzen asynchronen Scope steuern:

```dart
final immediate = await api.executeWithoutBuffering(
  () => api.v1.objects.getObject('OBJECT-OID'),
);

final background = await api.executeWithPriority(
  () => api.v1.objects.getObjects('Dokument'),
  GsdRequestPriority.low,
);
```

- `high`: sofort und ungepuffert
- `normal`: Standardpriorität
- `low`: eigener Buffer und Flush-Timer

## Uploads

```dart
final file = GsdUploadFile.fromBytes(name: 'document.pdf', bytes: pdfBytes);

final controller = await api.v1.documents.uploadFileWithController(file);
print('Upload-ID: ${controller.uploadId}');

final Object? result = await controller.result;

// Solange der Upload läuft:
// controller.cancel();
```

- Ein Abbruch endet mit `GsdUploadCancelledException`. Nach dem Start des letzten Schritts
  (PATCH) bewirkt `cancel()` nichts mehr; `result` liefert dann den Erfolg.
- `GsdUploadFile.fromPath` wirft im Web `UnsupportedError`; dort `fromBytes` verwenden.
- Ein Session-Retry beim Multipart sendet die Datei neu.

## Migration von 0.2

Namen, Konstruktor, Callbacks → Streams, V3-Bodies, Rückgaben, Exceptions und den Request-Hook
behandelt der [Migrationsleitfaden](doc/migration/0.2-to-0.3.md).

## Entwicklung

```shell
dart analyze --fatal-infos
dart test
dart test -p chrome
dart run build_runner build --delete-conflicting-outputs
```

Die Modelle entstehen mit `json_serializable`; die `*.g.dart` sind eingecheckt.

Weitere Informationen: [Changelog](CHANGELOG.md) · [Lizenz](LICENSE) ·
[Repository](https://github.com/GSD-Software-mbH/GSD-RestAPI)

## Sicherheit

- `allowSslError: true` ist ausschließlich für kontrollierte Entwicklungsumgebungen vorgesehen.
- Der MD5-Hash ist Teil des DOCUframe-Protokolls und ersetzt keine sichere Passwortspeicherung.
- Zugangsdaten, App-Keys, Sessions und 2FA-Tokens dürfen nicht protokolliert werden.
- Der AES-Schlüssel des Logins entsteht je Login und liegt nur im Speicher.
