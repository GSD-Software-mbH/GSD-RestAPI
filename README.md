# GSD RestAPI

Flutter-Client für die DOCUframe REST-API mit Session-Verwaltung,
verschlüsseltem Login, nativen V1-/V2-Endpunkten, Multi-Requests, Uploads und
Telemetrie.

> **Empfohlen:** Neue Anwendungen verwenden `DOCUframeApi`. Der bisherige
> `RestApiDOCUframeManager` bleibt für Bestandsanwendungen verfügbar, ist aber
> als veraltet markiert und funktional eingefroren.

[Schnellstart](#schnellstart) · [API-Überblick](#api-überblick) ·
[Authentifizierung](#authentifizierung-und-sessions) ·
[Migration](#migration-vom-legacy-manager) · [Beispiel-App](#beispiel-app) ·
[Entwicklung](#entwicklung)

## Funktionsumfang

- verschlüsselter Login mit automatischer Session-Erneuerung und 2FA
- 14 fachlich gruppierte V1-APIs und native V2-Endpunkte
- kontrollierter Raw-Zugang für kundenspezifische Endpunkte
- Multi-Request-Bündelung, Deduplizierung und Request-Prioritäten
- Datei- und Preview-Downloads sowie abbrechbare Uploads
- einheitliche Response-, Fehler- und Entschlüsselungspipeline
- Logging und HTTP-Metriken über Callbacks
- Flutter-Unterstützung für Mobile, Desktop und Web

## Installation

### Voraussetzungen

| Voraussetzung | Version |
| --- | --- |
| Dart | `^3.8.1` |
| Flutter | `>=1.17.0` |

### Abhängigkeit

```shell
flutter pub add gsd_restapi
```

## Schnellstart

Für die neue API genügt ein Import:

```dart
import 'package:gsd_restapi/docuframe_api.dart';

final api = DOCUframeApi(
  configuration: RestApiDOCUframeConfig(
    appKey: 'GSD-DFApp',
    userName: 'GSDAdmin',
    appNames: <String>['GSD-RestApi', 'GSD-DFApp'],
    serverUrl: 'https://127.0.0.1:8080',
    alias: 'dfapp',
    multiRequest: true,
  ),
  callbacks: RestApiDOCUframeCallbacks(
    onSessionIdChanged: (String sessionId) async {
      // Neue oder geleerte Session-ID persistieren.
    },
    onMissing2FAToken: () async {
      // In der Anwendung einen 2FA-Dialog öffnen.
      return '';
    },
  ),
);

try {
  // DOCUframe erwartet hier den MD5-Hash, nicht das Klartextpasswort.
  final login = await api.v1.authentication.login(
    'mein-passwort'.toMd5Hash(),
  );

  if (!login.isOk) {
    throw StateError('Anmeldung fehlgeschlagen.');
  }

  final response = await api.v1.objects.getObjects(
    'Dokument',
    page: 0,
  );

  if (response.isOk) {
    print(response.httpResponse.body);
  }
} finally {
  await api.dispose();
}
```

`DOCUframeApi` übernimmt beim Erzeugen eine Momentaufnahme der Konfiguration.
Die ursprüngliche `RestApiDOCUframeConfig` danach zu verändern, beeinflusst die
laufende API nicht.

## API-Überblick

Alle Bereiche einer `DOCUframeApi` teilen sich dieselbe Session, Runtime und
denselben HTTP-Client:

| Zugriff | Aufgabe |
| --- | --- |
| `api.v1` | native, fachlich gruppierte V1-Funktionen |
| `api.v2` | native V2-Funktionen |
| `api.raw` | kontrollierter Zugang für nicht native Endpunkte |
| `api.management` | Callbacks, laufende Requests und Runtime-Einstellungen |
| `api.sessionId` | aktuelle Session-ID |
| `api.isAuthenticated` | zeigt an, ob eine Session vorhanden ist |
| `api.executeWithoutBuffering(...)` | führt einen Scope ohne Buffering aus |
| `api.executeWithPriority(...)` | setzt die Priorität eines Scopes |
| `api.dispose()` | gibt Client, Timer und Runtime-Ressourcen frei |

### Native V1-Gruppen

Methodennamen, Parameter, Defaults und Rückgabetypen orientieren sich an der
bisherigen API; nur der fachliche Gruppenzugriff kommt hinzu.

| Gruppe | Zugriff | Inhalt |
| --- | --- | --- |
| Authentication | `api.v1.authentication` | Login, Logout, Sessions und 2FA |
| Service | `api.v1.service` | Erreichbarkeit, Lizenzfreigabe und Version |
| Account | `api.v1.account` | Demo-Accounts |
| Appointments | `api.v1.appointments` | Termine, Serien und Einladungen |
| Documents | `api.v1.documents` | Dateien, Previews, Status und Uploads |
| Folders | `api.v1.folders` | Ordnernavigation und Ordneroperationen |
| Integrations | `api.v1.integrations` | Sync, Makros und Anrufe |
| Mail | `api.v1.mail` | E-Mails erstellen, bearbeiten und senden |
| Messages | `api.v1.messages` | interne Nachrichten |
| Models | `api.v1.models` | Modellstruktur und Wörterbücher |
| Objects | `api.v1.objects` | Objekte, Aktionen, Locks und Rechte |
| Personal | `api.v1.personal` | ungelesene Dokumente, Aufgaben und Papierkorb |
| Settings | `api.v1.settings` | Benutzer- und Systemeinstellungen |
| Time Recording | `api.v1.timeRecording` | PZE, Zeitschlüssel und Zeitkonten |

```dart
final folder = await api.v1.folders.getFolderByType('Eingang');

final object = await api.v1.objects.getObject(
  'OBJECT-OID',
  serialization: 'edit',
);

final appointments = await api.v1.appointments.getAppointments(
  DateTime.now(),
  DateTime.now().add(const Duration(days: 7)),
);
```

### Native V2-Endpunkte

| HTTP-Endpunkt | Zugriff |
| --- | --- |
| `POST v2/model/structure` | `api.v2.model.structure(...)` |
| `GET v2/versionInfo` | `api.v2.system.versionInfo()` |
| `GET v2/appConfig` | `api.v2.system.appConfig()` |
| `GET v2/appTheme` | `api.v2.system.appTheme()` |
| `POST v2/view/load` | `api.v2.view.load(...)` |
| `POST v2/view/action` | `api.v2.view.action(...)` |
| `POST v2/objectdata/byid` | `api.v2.objectData.getById(...)` |
| `POST v2/objectdata/byQuery` | `api.v2.objectData.getByQuery(...)` |
| `POST v2/objectdata/byParentObject` | `api.v2.objectData.getByParentObject(...)` |
| `GET v2/file/{oid}` | `api.v2.file.get(...)` |

Die V2-POST-Bodies werden derzeit als JSON-String übergeben. So bleibt der
Wire-Vertrag sichtbar, bis die Datenstrukturen stabil genug für eigene DTOs
sind:

```dart
import 'dart:convert';

final response = await api.v2.objectData.getById(
  body: jsonEncode(<Object>[
    <String, Object>{
      'classId': 100,
      'type': '',
      'context': 'edit',
      'ids': <int>[200, 201],
    },
  ]),
);
```

`api.v2.file.get()` lädt Binärinhalte und liefert die Bytes unverändert
zurück (keine Response-Entschlüsselung, kein `v1/multi`-Buffering). Bei
E-Mail-Anhängen kann als `oid` die OID des Abschnitts oder die des Anhangs
verwendet werden. Alle Zusatzparameter sind optional und werden nur dann
gesendet, wenn sie gesetzt sind:

| Parameter | Wirkung |
| --- | --- |
| `page` | Seitenzahl bei mehrseitigen Dokumenten |
| `usePdf` | Liefert die PDF-Repräsentation statt des Originals |
| `attachItem` | Index des E-Mail-Anhangs, wenn `oid` eine E-Mail ist |
| `zipItem` | Index des Items innerhalb eines ZIP-Anhangs |
| `maxSize` | Verkleinert Bilder; der Wert definiert die kurze Seite |

```dart
// GET v2/file/1PTF?page=3
final file = await api.v2.file.get('1PTF', page: 3);
if (file.isOk) {
  final Uint8List bytes = file.httpResponse.bodyBytes;
}

// Anhang 3 einer E-Mail, verkleinert auf 512px kurze Seite
final attachment = await api.v2.file.get(
  mailOid,
  attachItem: 3,
  maxSize: 512,
);
```

## Authentifizierung und Sessions

### Anmelden

`login()` erwartet aus Kompatibilitätsgründen ein bereits MD5-gehashtes
Passwort:

```dart
final login = await api.v1.authentication.login(
  md5Password,
  twoFactorAuthToken: token,
);
```

Recoverbare Sessionfehler werden bei vorhandenen Login-Daten einmal behandelt:
Die Runtime erneuert die Session und wiederholt den Request. Parallele
Refresh-Anforderungen verwenden denselben laufenden Refresh.

### Persistierte Session wiederherstellen

Session und Passwort können gemeinsam gesetzt werden, damit bereits der erste
Request nach einem App-Start refresh-fähig ist:

```dart
api.v1.authentication.restoreSession(
  persistedSessionId,
  md5Password: persistedMd5Password,
);
```

Ist die Session-ID schon in der Konstruktor-Konfiguration enthalten, genügt:

```dart
api.v1.authentication.setPassword(persistedMd5Password);
```

Ein leerer Passwortwert deaktiviert die automatische Wiederanmeldung.

### Abmelden und freigeben

`dispose()` führt bewusst keinen Server-Logout aus:

```dart
try {
  await api.v1.authentication.logout();
} finally {
  await api.dispose();
}
```

`dispose()` ist asynchron und idempotent. Jede Haupt-, Demo- oder temporäre
API-Instanz muss freigegeben werden.

## RawApi für kundenspezifische Endpunkte

`api.raw` ist der kontrollierte Escape Hatch für Endpunkte, die noch keine
native Methode besitzen:

```dart
final RawApiResponse response = await api.raw.request(
  version: ApiVersion.v1,
  method: ApiHttpMethod.post,
  path: '/Abwesenheitsantrag/$oid/$action',
  queryParameters: <String, String>{'mode': 'preview'},
  body: '{"value":42}',
);

if (response.statusCode == 200) {
  print(response.body);
}
```

Dabei gilt:

- `path` enthält weder Server, Alias noch `v1`/`v2`.
- Query-Parameter gehören in `queryParameters`.
- Absolute URLs, Traversal, Backslashes, Query und Fragmente im Pfad werden
  abgelehnt.
- Raw-Requests werden weder gepuffert noch dedupliziert.
- HTTP-Fehler werden als `RawApiResponse` zurückgegeben; Transportfehler werfen
  eine Exception.
- Raw verwendet dieselbe Session-Erneuerung wie native Requests.

Wiederholt verwendete fachliche Endpunkte sollten als native, typisierte
Methode ergänzt werden.

## Management und Runtime-Einstellungen

`api.management` ersetzt direkte Zugriffe auf veränderliche Interna des
Legacy-Managers:

```dart
api.management.callbacks.onLicenseWrong = handleLicenseError;

await api.management.waitForIdle();

api.management.updateRuntimeSettings(
  additionalAppNames: <String>['LicensedModule'],
  multiRequest: true,
  perPageCount: 100,
  maxBufferSize: 10,
  bufferFlushDelayMs: 100,
);

api.management.setDevice(updatedDevice); // null entfernt das Gerät
```

| Zugriff | Bedeutung |
| --- | --- |
| `callbacks` | effektive Callback-Instanz |
| `hasPendingRequests` | zeigt laufende logische Requests an |
| `pendingRequestCount` | Anzahl laufender logischer Requests |
| `waitForIdle()` | wartet, bis alle laufenden Requests beendet sind |
| `runtimeSettings` | unveränderliche Momentaufnahme der Runtime-Werte |
| `updateRuntimeSettings(...)` | aktualisiert unterstützte Werte im Idle-Zustand |
| `device` / `setDevice(...)` | liest, ersetzt oder entfernt das Login-Gerät |
| `isDisposed` | zeigt an, ob die Runtime freigegeben wurde |

Server, Alias, App-Key, Benutzer, SSL-Verhalten und Timeouts sind an den
Transport gebunden. Dafür muss eine neue `DOCUframeApi` erzeugt werden.

## Multi-Request und Prioritäten

Multi-Request wird über die Konfiguration aktiviert. Geeignete parallele
V1-Aufrufe innerhalb des Flush-Fensters werden über `POST v1/multi` gebündelt:

```dart
final responses = await Future.wait(<Future<RestApiResponse>>[
  for (var page = 0; page < 10; page++)
    api.v1.objects.getObjects('Dokument', page: page),
]);
```

Ein einzelner gepufferter Aufruf wird direkt gesendet. Login, Logout,
Session-/Service-Checks, Uploads, Datei-/Preview-Downloads, Sync, Raw und die
nativen V2-Aufrufe laufen ebenfalls direkt.

Buffering und Priorität lassen sich für einen vollständigen asynchronen Scope
steuern:

```dart
final immediate = await api.executeWithoutBuffering(
  () => api.v1.objects.getObject('OBJECT-OID'),
);

final background = await api.executeWithPriority(
  () => api.v1.objects.getObjects('Dokument'),
  RequestPriority.low,
);
```

- `high`: sofort und ungepuffert
- `normal`: Standardpriorität
- `low`: eigener Buffer und Flush-Timer

## Uploads

```dart
final file = RestApiUploadFile.fromBytes(
  name: 'document.pdf',
  bytes: pdfBytes,
);

final controller = await api.v1.documents.uploadFileWithController(file);
print('Upload-ID: ${controller.uploadId}');

final RestApiResponse result = await controller.result;

// Solange der Upload läuft:
// controller.cancel();
```

Uploads verwenden dieselbe Session-, Timeout-, Entschlüsselungs- und
Fehlerpipeline. Der Controller stellt Upload-ID, Ergebnis und Abbruch bereit.

## Responses, Fehler und Telemetrie

Native JSON-Endpunkte liefern überwiegend `RestApiResponse` oder einen bereits
vorhandenen spezialisierten Response-Typ:

```dart
final response = await api.v2.system.versionInfo();

if (response.isOk) {
  print(response.httpResponse.body);
}
```

Typisierte Fehler umfassen unter anderem:

- `SessionInvalidException`, `TokenOrSessionIsMissingException`
- `UserAndPassWrongException`, `LicenseException`
- `Require2FALoginException`, `Missing2FATokenException`
- `Invalid2FATokenException`, `HttpRequestException`
- `SecurityException`, `WebServiceException`

`RestApiDOCUframeCallbacks` stellt Handler für Session-Änderungen, fehlende
2FA-Tokens, Login-/Lizenzfehler, Logs und HTTP-Metriken bereit. Handler können
über `api.management.callbacks` nachträglich gesetzt oder mit
`clearAllCallbacks()` entfernt werden.

Sensible Login-Daten, App-Keys und Session-IDs gehören nicht in eigene Logs.

## Migration vom Legacy-Manager

Die wichtigsten Zuordnungen sind:

```text
manager.login(...)                 -> api.v1.authentication.login(...)
manager.getObjects(...)            -> api.v1.objects.getObjects(...)
manager.getFolderByType(...)       -> api.v1.folders.getFolderByType(...)
manager.getFile(...)               -> api.v1.documents.getFile(...)
manager.customRequest(...)         -> api.raw.request(...)
manager.setPassword(...)           -> api.v1.authentication.setPassword(...)
manager.pendingResponses.isEmpty   -> !api.management.hasPendingRequests
                                      oder await api.management.waitForIdle()
manager.callbacks                  -> api.management.callbacks
```

Legacy-Manager und `DOCUframeApi` nicht innerhalb desselben fachlichen Flows
mischen: Beide besitzen eigene Clients, Buffer und Sessionzustände.

Der [vollständige Migrationsguide](docs/migration/legacy-to-docuframe-api.md)
behandelt zusätzlich Runtime-Einstellungen, Service-Probes, Upload-Hilfen,
Demo-Accounts und die konkrete Umstellung von `docuframeapp-flutter`.

## Beispiel-App

Die App unter [`example/`](example/) kann zwischen Legacy- und neuer API
umschalten. Sie enthält Login-, Session-, V1-Multi-Request- und V2-Testaktionen
sowie editierbare JSON-Bodies für V2-POST-Endpunkte.

```shell
cd example
flutter run
```

## Entwicklung

```shell
flutter analyze
flutter test

cd example
flutter analyze
flutter test
```

Die Tests decken Legacy-Verhalten, öffentliche Architekturgrenzen,
V1-Wire-Parität, V2-Request-Fixtures, Session-Retry, Deduplizierung,
Multi-Request, Uploads, Entschlüsselung und Lifecycle ab.

Weitere Informationen: [Changelog](CHANGELOG.md) · [Lizenz](LICENSE) ·
[Repository](https://github.com/GSD-Software-mbH/GSD-RestAPI)

## Sicherheit

- `allowSslError: true` ist ausschließlich für kontrollierte
  Entwicklungsumgebungen vorgesehen.
- Der MD5-Hash ist Teil des bestehenden DOCUframe-Protokolls und ersetzt keine
  sichere Passwortspeicherung.
- Zugangsdaten, App-Keys, Sessions und 2FA-Tokens dürfen nicht protokolliert
  werden.
- Für einen Server-Logout zuerst `api.v1.authentication.logout()` aufrufen und
  die API anschließend in `finally` mit `dispose()` freigeben.
