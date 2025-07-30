import 'dart:convert';

import 'package:restapi/responses/restapiresponse.dart';

class RestApiObjectLockResponse extends RestApiResponse {
  /// sessionId from the [httpResponse.body]
  bool isLocked = false;
  List<String> messages = [];

  /// Creates a [RestApiLoginResponse] object
  ///
  /// Throws a [FormatException] if the response body is missing the 'data.sessionId' field.
  RestApiObjectLockResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {

        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        if (!dataJson.containsKey("isLocked")) {

          throw const FormatException("missing 'data.isLocked' field in response body");
        } else {
          isLocked = dataJson['isLocked'];
        }

        dynamic messagesJson = dataJson["messages"];
        dynamic currentMessage;

        if(messagesJson == null) {
          return;
        }

        for (var i = 0; i < messagesJson.length; i++) {
          currentMessage = messagesJson[i];

          if(currentMessage != null) {
            messages.add(currentMessage);
          }
        }
      }
    }
  }
}
