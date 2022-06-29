$(OBJDIR)client:main.cpp
	$(CC) $^ -o $@ -lgmp -O -lcryptopp -lstdc++
	$(CC) auth_client.cpp -o auth_client -lgmp -O -lcryptopp -lstdc++