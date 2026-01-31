import socket

HOST = "127.0.0.1"
PORT = 65432
buf = 1024

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.connect((HOST,PORT))
	print(f"Connected to host!")
	s.sendall(b"Node receiving!")
	while True:
		try:
			data = s.recv(1024)
			if not data:
				print(f"Connection closed.")
				break
			print(f"Command recieved: {data.decode()}")
		except ConnectionResetError:
			print(f"Connection closed by the server.")
			break

