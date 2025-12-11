# JWT Weak Secret

A tool to perform a brute-force attack on a Json Web Token to discover the secret key.
If suscessful, you can generate a new JWT based on the secret key found. 

First you need to send the original JWT, without any modification. Then you can send the modified malicious Payload and you will recieve the new JWT to bypass. 

**Example Usage:**

```bash
go run main.go -w <wordlist>
```

<div align="center">
  <img src="assets/jwt.png">
</div>