$(SERDIR)server:main.cpp
	$(CC) $^ -o $@ -lgmp -O -lcryptopp -lstdc++
	$(CC) auth_server.cpp -o auth_server -lgmp -O -lcryptopp -lstdc++