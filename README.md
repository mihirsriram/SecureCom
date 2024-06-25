# SecureCom: Client-Server Communication System (RSA Encryption and Digital Signatures)
 SecureCom: A client-server communication system using RSA encryption and digital signatures to ensure secure, authenticated, and tamper-proof data exchanges.
---------------------------------------------------------------------------------------------------------------------------------------------------------------

Overview of the network threats and attacks:
-------------------------------------------
These are the following vulnerabilities that are possessed by the network without adding any security 
to it.

1. Confidentiality: Unauthorized individuals have the capability to intercept and view any 
information that is transmitted through a network, which can potentially put confidential 
data, like credit card numbers, passwords, and personal information at risk of being 
compromised.

3. Integrity: Verifying the integrity of data during transmission can be challenging, as there is a 
risk that an attacker may tamper with the data without being detected. This could potentially 
result in a loss of data integrity.

4. Authentication: Authenticating the identity of parties communicating with each other can be 
challenging, which can result in impersonation attacks and the potential transmission of 
sensitive information to unauthorized individuals.

5. Non-repudiation: it would be difficult to prove the authenticity of the data and to determine 
whether the sender really sent the data. This can lead to disputes over the validity of data 
transmissions.

6. Trust: Establishing trust between parties communicating with each other can be challenging, 
which can result in man-in-the-middle attacks where an attacker can intercept and modify 
data transmitted between the parties.

7. Man-in-the-middle attacks involve interception and modification of network traffic by an 
unauthorized party, such as substituting a genuine public key with a fake one, injecting 
malicious code, or forging digital signatures. The use of digital signatures and certificate 
authorities (CA) can help prevent this threat, but the server code must verify the authenticity 
of all incoming certificates and messages.

8. Denial-of-service attacks refer to flooding the server with excessive requests, exploiting 
vulnerabilities in the server software or network infrastructure, or consuming all available 
resources, such as CPU, memory, or bandwidth. To prevent such attacks, the server code 
should implement defensive measures such as rate limiting, timeouts, and other preventive 
mechanisms.

Enhancing Network security:

By utilizing Wireshark, we were able to identify weaknesses in the network we constructed. These are 
the following cryptographic controls used to mitigate and above vulnerabilities.

1. Network receiving the certificate - The network sends its public key and a flag, which indicates 
that it is the network and is encrypted with the public key of the Certificate Authority (CA). 
This flag serves as an identifier for verification purposes by the CA and is not replicable by 
anyone else in the real world. The CA verifies this flag, and if it matches the request made by 
the network, it issues a certificate to the network. However, the network can only request its 
certificate once during its lifetime. This sequence is quite limited, and it seems that there are 
no active attacks that can take place. Thissatisfies authentication, trust, also non-repudiation.

2. Client Registration - After establishing a connection, the Network sends its certificate to the 
client, which verifies it and then sends its public key, IP, and Port encrypted with the Network's 
public key. Even if an attacker sends bad parameters to the server while blocking the client, 
the client can check the received certificate's contents and discard any bad certificate 
forwarded by the attacker. The Network generates a unique ID for every request from an IP 
and updates the iptable, which helps to prevent impersonation. 
Next, the Network decrypts the contents from the client and assigns an ID for that IP: Port 
combination. Then, it sends a signed message to the CA containing the client's public key, ID, 
IP, Port, and own certificate. Only the Network can request a certificate for a client. The CA 
verifies the certificate, and if it belongs to the Network, it verifies the signed message using 
the Network's public key to confirm that it came from the server. It then creates a certificate 
for the client with available data and sends it to the Network. The server receives the 
certificate and matches the details with what it originally provided to the CA. Finally, it 
forwards the certificate to the client, which verifies it for its public key, IP, and Port. If there's 
a mismatch, the client discards the certificate. This also satisfies authentication, trust, also
non-repudiation.

3. Client to Client communication - In this scenario, C1 wants to send a message to C2. After 
establishing the initial connection, C2 sends its certificate to C1, which verifies it along with 
C2's ID. Then, C1 sends its own certificate to C2, and C2 receives it and obtains C1's public key. 
From that point on, C2 will accept any certificate sent to it and obtain the ID from it, but this 
risk of impersonation is mitigated by using signatures. To establish secure communication, C1 
creates a random symmetric key, encrypts it with C2's public key, computes the hash of the 
key, signs it, and sends it to C2 along with the encrypted key. C2 decrypts the key and verifies 
the signed hash to ensure that C1 was the actual sender.
With the shared symmetric key, the clients can communicate seamlessly, and all messages are 
protected with authentication, integrity, and confidentiality. Timestamps are included in the 
messages to prevent replay attacks, and the program supports refreshing the iptable by 
removing inactive clients periodically.

4. security mechanisms such as encryption (AES and RSA), digital signatures, and certificates are 
used to enhance security.
