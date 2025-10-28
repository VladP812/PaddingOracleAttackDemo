<h1 align="center">Padding Oracle Attack</h1>

This python script demonstrates what is a Padding Oracle Attack and how it works.

That's why you first Encrypt and then HMAC the Cyphertext. 
Otherwise to verify the message signature you'd have to decrypt first, enabling this attack.
When you Encrypt then HMAC you can verify the HMAC before decrypting (upon receiving), which doesn't allow this attack to happen.

Walkthrough: https://youtu.be/SpxSNs3KW1o
