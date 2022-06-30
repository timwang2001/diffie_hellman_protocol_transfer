$(SERDIR)server:main.cpp
	$(CC) $^ -o $@ -lgmp -O -lcryptopp -lstdc++
	$(CC) auth_server_new.cpp -o new_auth_server -lgmp -O -lcryptopp -lstdc++