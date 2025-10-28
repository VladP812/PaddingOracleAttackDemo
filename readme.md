<h1 align="center">Padding Oracle Attack</h1>

This python script demonstrates what is a Padding Oracle Attack and how it works.

That's why you first Encrypt and then HMAC the Cyphertext. 
Otherwise to verify the message signature you'd have to decrypt first, enabling this attack.
When you Encrypt then HMAC you can verify the HMAC before encrypting, which doesn't allow this attack to happen.

Detailed explanation (not by me): https://www.youtube.com/watch?v=O5SeQxErXA4&t=343s

I might upload my own video explaining this in the future.
