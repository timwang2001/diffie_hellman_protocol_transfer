$(OBJDIR)client:main.cpp
	$(CC) $^ -o $@ -lgmp -O -lcryptopp -lstdc++
	$(CC) auth_client.cpp -w -o auth_client -lgmp -O -lcryptopp -lstdc++