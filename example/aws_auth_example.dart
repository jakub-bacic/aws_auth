import 'package:aws_auth/aws_auth.dart';

Uri createPresignGetCallerIdentityUrl(
    AWSCredentials credentials, String region) {
  // create signer instance
  var signer = AWS4Signer(credentials, region, 'sts');

  // create request
  final req = AWSRequest(
    'https://sts.${region}.amazonaws.com/',
    queryParameters: {
      'Action': 'GetCallerIdentity',
      'Version': '2011-06-15',
    },
  );

  // presign the request
  signer.presign(req, expires: Duration(minutes: 1));

  return req.url;
}

void main() async {
  // provide AWS config
  final AWS_ACCESS_KEY_ID = 'aws_access_key_id';
  final AWS_SECRET_ACCESS_KEY = 'aws_secret_access_key';
  final AWS_SESSION_TOKEN = null; // optional
  final AWS_REGION = 'eu-central-1';

  // create credentials object
  final credentials = AWSCredentials(
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    sessionToken: AWS_SESSION_TOKEN,
  );

  final url = createPresignGetCallerIdentityUrl(credentials, AWS_REGION);
  print(url);
}
