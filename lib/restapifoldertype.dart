part of 'restapi.dart';

/// Enum für verschiedene Ordnertypen in der REST-API
/// 
/// Definiert die verschiedenen Arten, wie Ordner identifiziert und abgerufen werden können.
enum RestApiFolderType {
  /// Ordner nach Typ identifizieren (Nummer: 0, Wert: 'type')
  type(0, 'type'),
  
  /// Ordner nach Pfad identifizieren (Nummer: 100, Wert: 'path')
  path(100, 'path'),
  
  /// Ordner nach OID (Object ID) identifizieren (Nummer: 200, Wert: 'oid')
  oid(200, 'oid');

  /// Erstellt eine neue Instanz des Ordnertyps
  /// 
  /// [number] - Numerische Kennung des Ordnertyps
  /// [value] - String-Wert für API-Aufrufe
  const RestApiFolderType(this.number, this.value );

  /// Numerische Kennung des Ordnertyps
  final int number;
  
  /// String-Wert für API-Aufrufe
  final String value;
}