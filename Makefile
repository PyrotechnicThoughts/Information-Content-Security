# all: capture decrypt hash_table

all: capture

capture: capture.c
	gcc capture.c decrypt.c hash_table.c -o ./debug/capture -lnids -lpcap -lssl -lcrypto -Wall -g
# gcc capture.c -o ./debug/capture -lnids -lpcap -Wall -g


decrypt: decrypt.c
	gcc decrypt.c -o ./debug/decrypt -lssl -lcrypto -Wall -g

hash_table:
	gcc hash_table.c -o ./debug/hash_table -Wall -g

clean:
	rm ./debug/apture ./debug/decrypt ./debug/hash_table