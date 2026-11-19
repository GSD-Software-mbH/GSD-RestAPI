/// Liefert das 2FA-Token, wenn eine laufende Sitzung einen 341 bekommt.
///
/// Ein leerer String heißt "kein Token"; der Request wirft dann den 341
/// weiter.
typedef GsdTwoFactorTokenProvider = Future<String> Function();
