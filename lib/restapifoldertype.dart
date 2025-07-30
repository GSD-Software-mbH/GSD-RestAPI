enum RestApiFolderType {
  type(0, 'type'),
  path(100, 'path'),
  oid(200, 'oid');

  const RestApiFolderType(this.number, this.value );

  final int number;
  final String value;
}