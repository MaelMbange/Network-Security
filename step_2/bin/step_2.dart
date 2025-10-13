import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:pointycastle/export.dart';

Future<void> main(List<String> arguments) async {
  var parser = ArgParser()
    ..addOption(
      'port',
      abbr: 'p',
      defaultsTo: '8888',
      callback: (value) {
        if (value != null) {
          var port = int.tryParse(value);
          if (port == null || port < 0 || port > 65535) {
            print('Invalid port number: $value');
            exit(64);
          }
        }
      },
      help: 'Port to listen on',
    )
    ..addFlag(
      'help',
      abbr: 'h',
      help: 'Show this help message',
      negatable: false,
    );

  var results = parser.parse(arguments);
  if (results['help'] as bool) {
    print(parser.usage);
    return;
  }
  final port = int.parse(results['port']);

  ServerSocket.bind(InternetAddress.anyIPv4, port).then((serverSocket) {
    print(
      'Server[🔁]: is running on ${serverSocket.address.address}:${serverSocket.port}',
    );
    serverSocket.listen(
      (socket) {
        socket.setOption(SocketOption.tcpNoDelay, true);
        socket.writeln("Hello world");

        String password = 'laPassphrasePartagee';
        Uint8List? saltB64;
        Uint8List? iv;
        Uint8List? cipherTextB64;

        utf8.decoder
            .bind(socket)
            .transform(const LineSplitter())
            .listen(
              (line) async {
                if (line.contains(':')) {
                  var head = line.split(':')[0];
                  var body = line.split(':')[1];

                  switch (head) {
                    case 'SALT':
                      saltB64 = base64.decode(body);
                      print('Server[🔑 - SALT]: $body');

                    case 'IV':
                      iv = base64.decode(body);
                      print('Server[🔑 - IV]: $body');

                    case 'CT':
                      cipherTextB64 = base64.decode(body);
                      print('Server[🔑 - CT]: $body');

                    case _:
                      print('CLIENT[❓ - UNKNOWN]: $line');
                  }
                }

                if (saltB64 != null && iv != null && cipherTextB64 != null) {
                  _handleMessage(saltB64, password, iv, cipherTextB64, socket);
                }
              },
              onDone: () => print(
                'Server[🛑 - CLOSING]: Connection with ${socket.remoteAddress.address}:${socket.remotePort} closed',
              ),
              onError: (error) => print(
                'Server[❌ - ERROR]: Error occurred with ${socket.remoteAddress.address}:${socket.remotePort} - $error',
              ),
            );
      },
      onDone: () {
        print('Server[🛑 - CLOSING]: All connections closed');
      },
      onError: (error) => print('Server[❌ - ERROR]: Error occurred - $error'),
    );
  });
}

void _handleMessage(
  Uint8List? saltB64,
  String password,
  Uint8List? iv,
  Uint8List? cipherTextB64,
  Socket socket,
) {
  print('Server[✅ - ENCRYPTED]: Creating response');
  var pbkdf2 = KeyDerivator('SHA-256/HMAC/PBKDF2')
    ..init(Pbkdf2Parameters(saltB64!, 600000, 32));

  print('Server - Deriving key from password');
  final secretKey = pbkdf2.process(utf8.encode(password));

  print('Server - Decrypting message');
  final cipher =
      PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()))..init(
        false,
        PaddedBlockCipherParameters(
          ParametersWithIV(KeyParameter(secretKey), iv!),
          null,
        ),
      );

  final plainText = cipher.process(cipherTextB64!);
  final stringText = utf8.decode(plainText);

  print('Server[🔓 - DECRYPTED]: $stringText');
  print('Server[✉️ - SENDING]: Sending decrypted message back to client');

  var sha3 = SHA3Digest(256);
  final tagInput = Uint8List.fromList([
    ...secretKey,
    ...plainText,
    ...utf8.encode("that's all folks"),
  ]);

  final tag = sha3.process(tagInput);
  final tag64 = base64.encode(tag);
  print('Server[🔖 - TAG]: $tag64');
  socket.writeln('TAG:$tag64');
}
