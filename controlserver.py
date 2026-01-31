import socket

HOST = "127.0.0.1"
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST,PORT))
	print(f"Looking for autonomous node\n")
	s.listen()
	conn,addr=s.accept()
	print(f"Node found!")
	print(f"Enter a blank input to close the connection.")
	with conn:
		print(f"Connected by {addr}")
		print(f"Enter the commands: ")
		while True:
			data = input()
			if not data:
				print("Null value detected, connection terminated.")
				break
			conn.sendall(data.encode())
			s.close()
