import 'dart:convert';

import 'package:restapi/responses/restapicheckserviceresponse/restapimodule.dart';
import 'package:restapi/responses/restapiresponse.dart';

/// class for login rest-api responses
class RestApiVersionInfoResponse extends RestApiResponse {
  /// sessionId from the [httpResponse.body]
  String serviceVersion = "";
  DateTime? structureChangeDate;
  List<RestApiModule> modules = [];

  /// Creates a [RestApiLoginResponse] object
  ///
  /// Throws a [FormatException] if the response body is missing the 'data.sessionId' field.
  RestApiVersionInfoResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        serviceVersion = dataJson['webserviceVersion'] ?? "";
        dynamic structureChangeDateJson = dataJson['structureChangeDate'];
        dynamic modulesJson = dataJson['listOfModules'];

        if(structureChangeDateJson != null) {
          structureChangeDate = DateTime.parse(structureChangeDateJson);
        }

        if (modulesJson != null) {
          for (var i = 0; i < modulesJson.length; i++) {
            modules.add(RestApiModule(modulesJson[i]["moduleName"] ?? "", modulesJson[i]["moduleVersion"] ?? ""));
          }
        }
      }
    }
  }
}
