import 'dart:convert';
import 'dart:io';

void main(List<String> arguments) {
  ServerSocket.bind(InternetAddress.anyIPv4,8888).then((serverSocket){
    print('Server[🔁]: is running on ${serverSocket.address.address}:${serverSocket.port}');
    serverSocket.listen((socket){
      socket.writeln("Hello world");
      
      utf8.decoder.bind(socket).listen(
      print, 
      onDone: () => print('Server[🛑 - CLOSING]: Connection with ${socket.remoteAddress.address}:${socket.remotePort} closed'),
      onError: (error) => print('Server[❌ - ERROR]: Error occurred with ${socket.remoteAddress.address}:${socket.remotePort} - $error'));
    },
      onDone:(){
        print('Server[🛑 - CLOSING]: All connections closed');
      },
      onError: (error) => print('Server[❌ - ERROR]: Error occurred - $error')
    );
  });
}


      