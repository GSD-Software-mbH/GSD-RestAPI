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

// Legacy API
part 'legacy/restapidocuframemanager.dart';
part 'legacy/restapirequest.dart';
part 'legacy/restapibufferedrequest.dart';

// Shared models and infrastructure
part 'shared/httpmethod.dart';
part 'shared/restapidocuframedatabase.dart';
part 'shared/restapidevice.dart';
part 'shared/restapidevicetype.dart';
part 'shared/restapidocuframefoldertype.dart';
part 'shared/restapidocuframemodule.dart';
part 'shared/restapiaclentry.dart';
part 'shared/restapi2fastatus.dart';
part 'shared/restapiuploadfile.dart';
part 'shared/restapifileuploadcontroller.dart';
part 'shared/restapihttpmetric.dart';
part 'shared/sync/restapisynccontainer.dart';
part 'shared/sync/restapisyncdataclass.dart';
part 'shared/config/restapiconfig.dart';
part 'shared/config/restapidocuframeconfig.dart';
part 'shared/callbacks/restapicallbacks.dart';
part 'shared/callbacks/restapidocuframecallbacks.dart';
part 'shared/extension.dart';
part 'shared/responses/refreshsessionresponse.dart';
part 'shared/responses/restapicheckserviceresponse.dart';
part 'shared/responses/restapifileresponse.dart';
part 'shared/responses/restapiloginresponse.dart';
part 'shared/responses/restapiloginsecurekeyresponse.dart';
part 'shared/responses/restapiobjectlockresponse.dart';
part 'shared/responses/restapiresponse.dart';
part 'shared/responses/restapiusersystemsettingsresponse.dart';
part 'shared/responses/restapiversioninforesponse.dart';
part 'shared/responses/restapi2fasecretresponse.dart';
part 'shared/responses/sync/restapisyncclassresponse.dart';
part 'shared/exception/httprequestexception.dart';
part 'shared/exception/licenseexception.dart';
part 'shared/exception/securityexception.dart';
part 'shared/exception/sessioninvalidexception.dart';
part 'shared/exception/tokenorsessionismissingexception.dart';
part 'shared/exception/userandpasswrongexception.dart';
part 'shared/exception/webserviceexepection.dart';
part 'shared/exception/missing2fatokenexeption.dart';
part 'shared/exception/invalid2fatokenexeption.dart';
part 'shared/exception/require2faloginexception.dart';
