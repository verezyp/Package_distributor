all: 
	g++ -std=c++11 -pthread -o packet_distributor task1.cpp -lpcap
