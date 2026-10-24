# repo-vault

A small Git workflow wrapper around age. It encrypts selected, Git-ignored files for a list of age recipients and stores the ciphertext under .repo-vault/secrets/.

Status: experimental starter. This project has not had a security audit. It does not implement cryptography; it invokes the age command-line tool.

## What it does

- Stores public recipient keys in .repo-vault/recipients.txt.
- Encrypts a Git-ignored file to .repo-vault/secrets/<path>.age.
- Refuses to encrypt a plaintext file already tracked by Git.
- Decrypts only to an explicit path outside the repository.
- Leaves the original plaintext in place so you can inspect it and keep it ignored.

## What it does not do

- It does not erase plaintext files or rewrite Git history.
- It does not revoke copies of plaintext that a recipient already decrypted.
- It does not verify that a public key belongs to a particular person.
- It does not replace a production secret manager or a security review.

## Requirements

- Python 3.10 or later
- Git
- The age command-line tool installed and available in PATH

Install age from its official repository: https://github.com/FiloSottile/age

## Install from a checkout

From this directory:

    python -m pip install .

## Example workflow

Generate an age identity on your own machine and derive its public recipient key:

    age-keygen -o ~/.config/age/repo-vault-identity.txt
    age-keygen -y ~/.config/age/repo-vault-identity.txt

Pass the public key printed by the second command to init:

    repo-vault init --recipient age1...

Before encrypting a file, add its plaintext path to the repository's .gitignore. Then encrypt it:

    repo-vault encrypt .env.production

The encrypted file is written to .repo-vault/secrets/.env.production.age. Commit the encrypted file and recipient list. Do not commit the plaintext or your private identity.

Add another team's public key:

    repo-vault add-recipient age1...
    repo-vault recipients

After changing recipients, decrypt and re-encrypt existing secrets for the updated recipient list before committing replacements. Anyone who already decrypted a file may still have a copy.

Decrypt outside the repository:

    repo-vault decrypt .repo-vault/secrets/.env.production.age \
      --identity ~/.config/age/repo-vault-identity.txt \
      --output /private/tmp/env.production

The output is created with owner-only permissions where the operating system supports them. Keep it private and remove it when no longer needed.

## Important handling notes

- If a plaintext secret was committed before, ignoring it now does not remove it from Git history. Treat it as exposed and rotate it.
- Keep private age identities out of the repository and protect them with appropriate local access controls.
- Review every staged change before committing. The secrets folder should contain ciphertext; the source file should remain ignored.
- File names and repository metadata are not encrypted.
- Encryption does not hide changes, access patterns, or file sizes.

## References

- age, the official encryption tool and format: https://github.com/FiloSottile/age
- git-secret, an established GPG-based Git workflow: https://github.com/sobolevn/git-secret
