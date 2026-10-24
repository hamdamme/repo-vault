# Security

repo-vault is an experimental workflow wrapper, not a reviewed security product. It delegates encryption and decryption to the installed age command. It does not implement cryptographic primitives.

Do not rely on this project as the only protection for production credentials. Use an established secret-management system when your environment requires access control, audit logging, automated rotation, or recovery guarantees.

## Reporting a vulnerability

Please do not include real secrets, private keys, or sensitive repository contents in a public issue. For a security concern, contact the repository owner privately through GitHub.

## Known limitations

- A secret accidentally committed in plaintext may remain in Git history and clones. Rotate it; deleting the latest copy is not enough.
- A recipient may retain plaintext they decrypted before their public key was removed.
- Recipient key ownership and authenticity must be verified out of band.
- Recipient keys and ciphertext file names remain visible.
- This initial version has not been independently audited.
