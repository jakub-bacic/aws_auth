// ignore_for_file: public_member_api_docs

import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart';
import 'package:intl/intl.dart';

String quote(String input) {
  return Uri.encodeQueryComponent(input).replaceAll('+', '%20');
}

String trimAll(String input) {
  return input.trim().replaceAll(RegExp(' +'), ' ');
}

String normalizePath(String input) {
  if (input.isEmpty) {
    return '/';
  }

  var uri = Uri(path: input);
  return uri.normalizePath().path.replaceAll(RegExp('/+'), '/');
}

String formatDate(DateTime timestamp, {bool includeTime = true}) {
  var format = 'yyyyMMdd';
  if (includeTime) {
    format += "'T'HHmmss'Z'";
  }
  return DateFormat(format).format(timestamp);
}

List<int> hmac(List<int> key, List<int> message) {
  var hmacSha256 = Hmac(sha256, key);
  return hmacSha256.convert(message).bytes;
}

class Headers extends CanonicalizedMap<String, String, String> {
  Headers() : super((key) => key.toLowerCase());

  Headers.from(Map<String, String> other)
      : super.from(other, (key) => key.toLowerCase());
}
