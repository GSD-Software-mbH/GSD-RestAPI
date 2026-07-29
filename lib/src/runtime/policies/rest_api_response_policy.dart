import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import 'package:gsd_restapi/gsd_restapi.dart';

import '../transport_response.dart';
import 'response_policy.dart';

/// Übergangs-Policy für V1 UND V2: dekodiert eine [TransportResponse] über
/// den bestehenden Legacy-Envelope
/// (`{"status": {"internalStatus", "statusMessage"}, "data": ...}`) und das
/// vorhandene Exception-Mapping aus [RestApiResponse].
///
/// Hintergrund: Das V2-Wire-Format ist noch nicht stabil, daher gibt es
/// vorerst keine V2-DTOs/Mapper (siehe Migrationsplan, "Übergangsphase
/// ohne V2-DTOs"). Neue V2-Methoden geben übergangsweise [RestApiResponse]
/// zurück.
///
/// Das Exception-Verhalten kommt unverändert aus dem
/// [RestApiResponse]-Konstruktor (u.a. `201` ->
/// [SessionInvalidException], `204` -> [TokenOrSessionIsMissingException],
/// `302` -> [UserAndPassWrongException], `306`/`101` -> [LicenseException],
/// `340`-`342` -> 2FA-Exceptions, unbekannt -> [WebServiceException]).
@internal
class RestApiResponsePolicy implements ResponsePolicy<RestApiResponse> {
  const RestApiResponsePolicy();

  @override
  RestApiResponse decode(TransportResponse response) {
    // Adapter auf http.Response: Statuscode, Header und Body-Bytes bleiben
    // erhalten. Bewusst über die Bytes, damit die Charset-Dekodierung
    // (Content-Type-Header) identisch zum Legacy-Pfad funktioniert.
    final http.Response httpResponse = http.Response.bytes(
      response.bodyBytes,
      response.statusCode,
      headers: response.headers,
    );

    return RestApiResponse(httpResponse);
  }
}
