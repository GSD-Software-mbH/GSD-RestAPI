library restapi;

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'package:collection/collection.dart';
import 'package:encrypt/encrypt.dart' as encrpyt;
import 'package:encryption/encryptionmanager.dart';
import 'package:encryption/extension.dart';
import 'package:event/event.dart';
import 'package:file_picker/file_picker.dart';
import 'package:firebase_performance/firebase_performance.dart' as firebase_performance;
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:iso8601_duration/iso8601_duration.dart';
import 'package:pointycastle/export.dart';
import 'package:restapi/httpclient/httpclient.dart';

// Core Classes
part 'restapidatabase.dart';
part 'restapidevice.dart';
part 'restapidevicetype.dart';
part 'restapifoldertype.dart';
part 'restapimanager.dart';
part 'restapimodule.dart';
part 'restapirequest.dart';
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
