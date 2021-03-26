import 'package:aws_auth/aws_auth.dart';

AWSRequest createPresignGetCallerIdentityRequest(
  AWSCredentials credentials,
  String region,
  Duration expires,
) {
  // create signer instance
  var signer = AWS4Signer(credentials, region, 'sts');

  // create request
  final req = AWSRequest(
    'https://sts.$region.amazonaws.com/',
    queryParameters: {
      'Action': 'GetCallerIdentity',
      'Version': '2011-06-15',
    },
  );

  // presign the request
  signer.presign(req, expires: expires);

  return req;
}

AWSRequest createGetCallerIdentityRequest(
  AWSCredentials credentials,
  String region,
) {
  // create signer instance
  var signer = AWS4Signer(credentials, region, 'sts');

  // create request
  final req = AWSRequest.formData(
    'https://sts.$region.amazonaws.com/',
    body: {
      'Action': 'GetCallerIdentity',
      'Version': '2011-06-15',
    },
  );

  // sign the request
  signer.sign(req);

  return req;
}

String formatAsCurlCommand(AWSRequest req) {
  var cmd = ['curl', '-v'];

  // set method
  cmd.add('-X ${req.method}');

  // set headers
  req.headers.forEach((key, value) {
    cmd.add("-H '$key: $value'");
  });

  // set body
  if (req.body.isNotEmpty) {
    cmd.add("-d '${req.body}'");
  }

  // set url
  cmd.add(req.url.toString());

  return cmd.join(' ') + '\n';
}

void main() async {
  // provide your AWS config
  final AWS_ACCESS_KEY_ID = 'aws_access_key_id';
  final AWS_SECRET_ACCESS_KEY = 'aws_secret_access_key';
  final AWS_REGION = 'eu-central-1';

  // create credentials object
  final credentials = AWSCredentials(
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    sessionToken: null,
  );

  print('SIGNING:');
  final signedReq = createGetCallerIdentityRequest(
    credentials,
    AWS_REGION,
  );
  print(formatAsCurlCommand(signedReq));

  print('PRESIGNING:');
  final presignedReq = createPresignGetCallerIdentityRequest(
    credentials,
    AWS_REGION,
    Duration(minutes: 5),
  );
  print(formatAsCurlCommand(presignedReq));
}
