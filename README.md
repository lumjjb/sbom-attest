# Sbom-attest tool

Based on https://github.com/slsa-framework/slsa-github-generator-go

Note that this is a testing utility for the kubecon talk: https://sched.co/182GT

## Build

```
go build -o sbom-attest ./cmd/sbom-attest
```

## Example

```
# Upload to rekor

➜  sbom-attest $ shasum -a 256 /Users/lumb/git/examples/libraries/poco/md5/build/bin/md5
2eeff24898c4ab6bbf8ca2d8d1257391b9a578a9bcb91fc42fb2b55155703473  /Users/lumb/git/examples/libraries/poco/md5/build/bin/md5
➜  sbom-attest $ shasum -a 256 /Users/lumb/git/examples/libraries/poco/md5/md5-spdx.json
99843e08e08c7e627a23c9182aa003a6b0bdb9036c47e34dfb28139df6d05fe5  /Users/lumb/git/examples/libraries/poco/md5/md5-spdx.json
➜  sbom-attest $ ./sbom-attest attest --local --predicateType "google.com/sbom" --subjects "2eeff24898c4ab6bbf8ca2d8d1257391b9a578a9bcb91fc42fb2b55155703473 test"  --sbomUri https://storage.googleapis.com/lumjjb-sbom/md5-spdx.json --sbomSha256 99843e08e08c7e627a23c9182aa003a6b0bdb9036c47e34dfb28139df6d05fe5
no auth provider enabled
Retrieving signed certificate...

        Note that there may be personally identifiable information associated with this signed artifact.
        This may include the email address associated with the account with which you authenticate.
        This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later.
        By typing 'y', you attest that you grant (or have permission to grant) and agree to have this information stored permanently in transparency logs.

Are you sure you want to continue? (y/[N]): y
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&code_challenge=AILkDT4hbGI9RqdltKfewonxm7ycGImXncB6M3bwPX4&code_challenge_method=S256&nonce=2FV9wO2pnCaICu4LsiC6wQBIjHL&redirect_uri=http%3A%2F%2Flocalhost%3A49669%2Fauth%2Fcallback&response_type=code&scope=openid+email&state=2FV9wJw4h2OgJbuO5D23I7LShaj
Uploaded signed attestation to rekor with UUID 24296fb24b8ad77a5d7d9910fb1745e67a9282c661670e06907c18b9834f18e5a724ddaf515cfa2d.

➜  sbom-attest $ rekor-cli get --uuid 24296fb24b8ad77a5d7d9910fb1745e67a9282c661670e06907c18b9834f18e5a724ddaf515cfa2d
LogID: c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d
Attestation: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"google.com/sbom","subject":[{"name":"test","digest":{"sha256":"2eeff24898c4ab6bbf8ca2d8d1257391b9a578a9bcb91fc42fb2b55155703473"}}],"predicate":{"sboms":[{"format":"SPDX","digest":{"sha256":"99843e08e08c7e627a23c9182aa003a6b0bdb9036c47e34dfb28139df6d05fe5"},"uri":"https://storage.googleapis.com/lumjjb-sbom/md5-spdx.json"}],"build-metadata":{"artifact-source-repo":"NoAssertion","artifact-source-repo-commit":"NoAssertion","attestation-generator-repo":"NoAssertion","attestation-generator-repo-commit":"NoAssertion"}}}
Index: 4305581
IntegratedTime: 2022-09-30T19:37:06Z
UUID: 24296fb24b8ad77a5d7d9910fb1745e67a9282c661670e06907c18b9834f18e5a724ddaf515cfa2d
Body: {
  "IntotoObj": {
    "content": {
      "hash": {
        "algorithm": "sha256",
        "value": "7eaee98820e5285fb4c24d802769748510399394e208d2f7668194fb9619690c"
      },
      "payloadHash": {
        "algorithm": "sha256",
        "value": "25a9961f57d6f05c4f828509c23a53c54421c259913dcf3de1e694999b45025f"
      }
    },
    "publicKey": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNtekNDQWlHZ0F3SUJBZ0lVZkxnQXArWUQvK0xBMlVyblQzaEUrSHg1cVpFd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09UTXdNVGt6TnpBMldoY05Nakl3T1RNd01UazBOekEyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVodmI1bi9wRjJrcW0xWHBmTDZ0MnpFSkFvaU10V2lFMEJKWGoKdVN4RnZ5SWMxZlpENEhFSjNzK1VpUjZyblExZi81eFBkbTRscXFJM1pranhyMUVidEtPQ0FVQXdnZ0U4TUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVU4NzlFCjVXMkg1b3VUQmZHalcyZi80VmJBbWdnd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0hRWURWUjBSQVFIL0JCTXdFWUVQYkhWdFlrQm5iMjluYkdVdVkyOXRNQ2tHQ2lzR0FRUUJnNzh3QVFFRQpHMmgwZEhCek9pOHZZV05qYjNWdWRITXVaMjl2WjJ4bExtTnZiVENCaWdZS0t3WUJCQUhXZVFJRUFnUjhCSG9BCmVBQjJBQWhna3ZBb1V2OW9SZEhSYXllRW5FVm5HS3dXUGNNNDBtM212Q0lHTm05eUFBQUJnNC9uQi9nQUFBUUQKQUVjd1JRSWhBT3U3L2xMWjU5SjBLVVlTY2VUamJlVEZNK1JnZ2ZjOExDSlZUMUZacWJjUEFpQStUM242UWZsTgoyQXY2Tks5UXoxdGJSVUlDa1dlMWlnNHhFTi9tUXVPN21qQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQUpvQ2JlCk93eWx6T1pIMXEwZFRSK2FGTjJxOFJqbDQyQWQ1MjhjNXNBazNPYWpxM2hqRk1ZaFdiWnhqamVlNk9ZQ01RRHgKWi9uYjA4bEJTTmg4SU0yVlJMcTUzSmMzaWVDQTRSRms4QmxmM2l5djNVN3B5ak5SSHk5TmVvSm9qRzJiWkhBPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
  }
}
```
