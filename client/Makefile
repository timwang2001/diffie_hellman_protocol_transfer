$(OBJDIR)client:main.cpp
	$(CC) $^ -o $@ -lgmp -O -lcryptopp -lstdc++
	$(CC) auth_client_new.cpp -w -o new_auth_client -lgmp -O -lcryptopp -lstdc++