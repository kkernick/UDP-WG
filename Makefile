all: main

main: src/main.cpp
	g++ src/main.cpp -o main -std=c++20 -lssl -lcrypto -lsodium
