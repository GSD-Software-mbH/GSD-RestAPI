import 'dart:convert';

import 'package:restapi/responses/restapicheckserviceresponse/restapidatabase.dart';
import 'package:restapi/responses/restapicheckserviceresponse/restapimodule.dart';
import 'package:restapi/responses/restapiresponse.dart';

/// class for login rest-api responses
class RestApiCheckServiceResponse extends RestApiResponse {
  /// sessionId from the [httpResponse.body]
  String applicationVersion = "";
  String applicationName = "";
  List<RestApiDatabase> databases = [];

  /// Creates a [RestApiLoginResponse] object
  ///
  /// Throws a [FormatException] if the response body is missing the 'data.sessionId' field.
  RestApiCheckServiceResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {

        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];

        applicationName = dataJson['applicationName'] ?? "";
        applicationVersion = dataJson['applicationVersion'] ?? "";
        dynamic webservice = dataJson['webservice'];

        if(webservice != null) {
          Map<String, dynamic>? databasesJson = webservice['moduleVersion'];
          applicationVersion = webservice['version'] ?? "";

          if(databasesJson != null && databasesJson.entries.isNotEmpty) {
            for (var i = 0; i < databasesJson.entries.length; i++) {
              RestApiDatabase database = RestApiDatabase(databasesJson.keys.elementAt(i), []);
              dynamic modulesJson = databasesJson.values.elementAt(i);

              if(modulesJson != null) {
                for (var i = 0; i < modulesJson.length; i++) {
                  database.modules.add(RestApiModule(modulesJson[i]["moduleName"] ?? "", modulesJson[i]["moduleVersion"] ?? ""));
                }
              }

              databases.add(database);
            }
          }
        }
      }
    }
  }
}
