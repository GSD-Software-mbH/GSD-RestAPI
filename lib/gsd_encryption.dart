library gsd_encryption;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';
import 'package:gsd_encryption/web/webrsaencryptionmanagerdummy.dart'
    if (dart.library.html) 'package:gsd_encryption/web/webrsaencryptionmanager.dart';
import 'package:flutter/foundation.dart' as foundation;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:pointycastle/pointycastle.dart';

part 'encryptionmanager.dart';
part 'encryptionoptions.dart';  
part 'extension.dart';