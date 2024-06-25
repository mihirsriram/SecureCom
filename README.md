# SecureCom: Client-Server Communication System (RSA Encryption and Digital Signatures)
SecureCom is a robust client-server communication system designed to ensure secure data exchanges using RSA encryption and digital signatures. This project focuses on mitigating various network threats and enhancing security through cryptographic controls.
---------------------------------------------------------------------------------------------------------------------------------------------------------------

Features:
---------
Confidentiality: Prevents unauthorized individuals from intercepting and viewing transmitted information.


Integrity: Ensures data is not tampered with during transmission.

Authentication: Verifies the identity of parties involved in communication.

Non-repudiation: Provides proof of the authenticity of data and its sender.

Trust: Establishes secure trust between communicating parties.

Man-in-the-Middle Attack Prevention: Uses digital signatures and certificates to prevent interception and modification of network traffic.

Denial-of-Service Attack Prevention: Implements defensive measures like rate limiting and timeouts.

Security Mechanisms
-------------------
Encryption: Utilizes AES for symmetric encryption and RSA for asymmetric encryption.

Digital Signatures: Ensures the authenticity and integrity of messages.

Certificates: Uses Certificate Authorities (CA) for verifying identities.

Getting Started
---------------
Prerequisites

Python 3.x
Crypto library

Installation
------------
Clone the repository:

git clone https://github.com/mihirsriram/SecureCom.git

Navigate to the project directory:

cd SecureCom

Install the required libraries:
Running the Network Server
--------------------------
Start the Certificate Authority (CA):


python ca.py

Start the Network server:

python network.py <CA_IP>:<CA_PORT> <NETWORK_IP>:<NETWORK_PORT>

Running the Client

Start the Client:

python client.py <NETWORK_IP>:<NETWORK_PORT> <CLIENT_IP>:<CLIENT_PORT>

Usage
-----
Network Initialization: The network sends its public key encrypted with the CA's public key for verification and receives a certificate from the CA.

Client Registration: The client registers with the network, receives a certificate, and can then communicate securely with other clients.

Client-to-Client Communication: Clients exchange certificates and establish a secure communication channel using symmetric keys encrypted with RSA.

Contributing
Please fork the repository and submit pull requests.
