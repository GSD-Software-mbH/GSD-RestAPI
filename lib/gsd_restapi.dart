library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:collection/collection.dart';
import 'package:encrypter_plus/encrypter_plus.dart' as encrpyt;
import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:iso8601_duration/iso8601_duration.dart';

import 'package:gsd_restapi/httpclient/httpclient.dart';

// Core Classes
part 'restapidocuframedatabase.dart';
part 'restapidevice.dart';
part 'restapidevicetype.dart';
part 'restapidocuframefoldertype.dart';
part 'restapidocuframemanager.dart';
part 'restapidocuframemodule.dart';
part 'restapiaclentry.dart';
part 'restapi2fastatus.dart';
part 'restapirequest.dart';
part 'restapibufferedrequest.dart';
part 'restapiuploadfile.dart';
part 'restapifileuploadcontroller.dart';
part 'restapihttpmetric.dart';

//Sync Classes
part 'sync/restapisynccontainer.dart';
part 'sync/restapisyncdataclass.dart';

// Modular Architecture
part 'config/restapiconfig.dart';
part 'config/restapidocuframeconfig.dart';
part 'callbacks/restapicallbacks.dart';
part 'callbacks/restapidocuframecallbacks.dart';
part 'extension.dart';

// Responses
part 'responses/refreshsessionresponse.dart';
part 'responses/restapicheckserviceresponse.dart';
part 'responses/restapifileresponse.dart';
part 'responses/restapiloginresponse.dart';
part 'responses/restapiloginsecurekeyresponse.dart';
part 'responses/restapiobjectlockresponse.dart';
part 'responses/restapiresponse.dart';
part 'responses/restapiusersystemsettingsresponse.dart';
part 'responses/restapiversioninforesponse.dart';
part 'responses/restapi2fasecretresponse.dart';
part 'responses/sync/restapisyncclassresponse.dart';

// Exceptions
part 'exception/httprequestexception.dart';
part 'exception/licenseexception.dart';
part 'exception/securityexception.dart';
part 'exception/sessioninvalidexception.dart';
part 'exception/tokenorsessionismissingexception.dart';
part 'exception/userandpasswrongexception.dart';
part 'exception/webserviceexepection.dart';
part 'exception/missing2fatokenexeption.dart';
part 'exception/invalid2fatokenexeption.dart';
part 'exception/require2faloginexception.dart';
