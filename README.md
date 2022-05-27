# Chat Server Project
*Assignment for the Communication and Security Protocols module (University of Limerick)*

Implementation of a protocol that allows a mutually agreed session key to be generated between three clients wishing to communicate securely via a server.

#### 3 main phases:

1. Authentication phase: the three clients authenticate themselves to the server using Public Key cryptography
2. Key Agreement phase: once authenticated, the three clients exchange random numbers that will allow them to generate a mutually agreed session key by hashing all three random numbers together.
3. Communication phase: once the the session key is established, the clients can now communicate in a secure way
