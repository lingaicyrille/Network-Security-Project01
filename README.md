<h1>Simplified Cryptographic Applications</h1>

 
<h2>Description</h2>
The project consist to write three independent programs in three separate directories: a key generation program, a sender's program, and a receiver's program, to implement the public-key encrypted message and its authentic digital digest. X represents the sender and Y represents the receiver. We have to generate a symmetric key in the key generation program called " keyGen". We take a 16 characteres users input from the keyboard and save these 16 characters string to the file name "Symmetric.key". In the sender's program in the directory "Sender", we calculate RSA-En ky+(AES-ENkxy((SHA256(M))||M). to test the program, the corresponding key file need to be copied here from the directory "KeyGen". then we read the information on the keys to be used in this program from the key files and generate Ky+ and Kxy. In the receiver's program in the directory "Receiver", we decrypt the message using RSA and AES decryption to get the message SHA256(M) and M and compare SHA256(M) with the locally calculated SHA256 hash of M, report hashing error if any, and then save M to a file. <b>Basically, a sender is sending a secure message to a receiver and the receiver is making sure it is the original message he has received from the sender.</b>
<br />


<h2>Languages and Utilities Used</h2>

- <b>Java Programming Language</b> 
- <b>Matlab</b>
