import 'package:aws_auth/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Utils:quote', () {
    test('Do not encode unreserved characters', () {
      expect(quote('abc-_.~abc'), 'abc-_.~abc');
    });

    test('Encode characters', () {
      expect(quote('*\'()"!?@%\$/\\'), '%2A%27%28%29%22%21%3F%40%25%24%2F%5C');
    });

    test('Encode space character as %20', () {
      expect(quote('value with spaces'), 'value%20with%20spaces');
    });
  });

  group('Utils:trimAll', () {
    test('Remove excess white space before value', () {
      expect(trimAll('   leading spaces'), 'leading spaces');
    });

    test('Remove excess white space after value', () {
      expect(trimAll('trailing spaces   '), 'trailing spaces');
    });

    test('Convert sequential spaces to a single space', () {
      expect(trimAll('sequential  spaces     test'), 'sequential spaces test');
    });
  });

  group('Utils:normalizePath', () {
    test('Normalize empty path to single forward slash', () {
      expect(normalizePath(''), '/');
    });

    test('Remove redundant path components', () {
      expect(normalizePath('/foo//bar///baz'), '/foo/bar/baz');
    });

    test('Remove relative path components (single dot)', () {
      expect(normalizePath('/foo/./bar/./baz'), '/foo/bar/baz');
    });

    test('Remove relative path components (double dot)', () {
      expect(normalizePath('/foo/bar/../../baz'), '/baz');
    });
  });

  group('Utils:formatDate', () {
    DateTime timestamp;

    setUp(() {
      timestamp = DateTime(2020, 2, 1, 3, 4, 5);
    });

    test('Format date (with time)', () {
      expect(formatDate(timestamp), '20200201T030405Z');
    });

    test('Format date (without time)', () {
      expect(formatDate(timestamp, includeTime: false), '20200201');
    });
  });
}
