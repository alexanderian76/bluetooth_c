all:
	gcc -Wall -Wextra -g main.c -lbluetooth
	
server: server_build server_run

server_build:
	gcc -Wall -Wextra -g server.c -lbluetooth -o server
	
server_run:
	./server

run:
	./a.out

client: client_build client_run

client_build:
	gcc -Wall -Wextra -g client.c -lbluetooth -o client
	
client_run:
	./client

test: test_build test_run

test_build:
	gcc test.c -lbluetooth -o test

test_run:
	./test


catch: catch_build catch_run

catch_build:
	gcc catch.c -lbluetooth -o catch

catch_run:
	./catch


monitor: monitor_build monitor_run

monitor_build:
	gcc monitor.c -lbluetooth -o monitor

monitor_run:
	./monitor