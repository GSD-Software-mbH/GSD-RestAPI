import 'dart:convert';

import 'package:restapi/responses/restapiresponse.dart';

/// class for login rest-api responses
class RestApiLoginResponse extends RestApiResponse {
  /// sessionId from the [httpResponse.body]
  String sessionId = "";
  List<String> applications = [];

  /// Creates a [RestApiLoginResponse] object
  ///
  /// Throws a [FormatException] if the response body is missing the 'data.sessionId' field.
  RestApiLoginResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        if (!dataJson.containsKey("sessionId")) {
          throw const FormatException("missing 'data.sessionId' field in response body");
        } else {
          sessionId = dataJson['sessionId'];
        }

        dynamic acls = dataJson["acls"];
        dynamic currentAclApplication;

        if(acls == null) {
          return;
        }

        for (var i = 0; i < acls.length; i++) {
          currentAclApplication = acls[i]["application"];

          if(currentAclApplication != null) {
            applications.add(currentAclApplication);
          }
        }
      }
    }
  }

  bool hasApplication(String application) {
    return applications.contains(application);
  }
}
