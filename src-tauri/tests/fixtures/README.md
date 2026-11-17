# Test fixtures

Keystores written by other implementations, used to check Keystore Studio's codecs against them.
They hold throwaway keys only.

| File | Written by | Password | Contents |
| --- | --- | --- | --- |
| `sample.bks`, `sample.uber` | Bouncy Castle via keytool | `changeit` | key pair `server`, certificate `trusted`, AES key `aes` |
| `sample.bcfks` | Bouncy Castle via keytool | `changeit` | as above |
| `pyjks/christmas.{bksv1,bksv2,uber}` | Bouncy Castle (from the pyjks test suite) | `12345678` | one entry of every kind, including a public key on its own |
| `pyjks/custom_entry_passwords.*` | Bouncy Castle (pyjks) | store `store_password`; keys `private_password`, `secret_password`, `public_password` | entries under their own passwords |
| `pyjks/empty.*` | Bouncy Castle (pyjks) | empty | no entries |
| `bouncycastle/oldKeyStore.bcfks` | Bouncy Castle (`BCFKSStoreTest`) | `hello world` | key pair `privkey`, chain of 2 |
| `bouncycastle/oldKeyStoreNoPW.bcfks` | Bouncy Castle | none | as above |
| `bouncycastle/kwpKeyStore.bcfks` | Bouncy Castle | `hello world` | `privkey`, `trusted` (= `trustedCertData.cer`), `secret1` AES (`secretPwd1`), `secret2` DESede (`secretPwd2`) |
| `bouncycastle/legacyScryptKeyStore.bcfks` | Bouncy Castle 1.86 (scrypt, `p = r` convention) | `hello world` | AES key `seckey` |
| `bouncycastle/legacyScryptSignedKeyStore.bcfks` | Bouncy Castle 1.86, signature-protected | none (key: `hello world`) | AES key `seckey` |

Licences: [pyjks/LICENSE](pyjks/LICENSE) (MIT, Kurt Rose) and
[bouncycastle/LICENSE.md](bouncycastle/LICENSE.md) (MIT, Legion of the Bouncy Castle).

The writers are proven by re-encoding these files with their own salts, nonces and dates and
comparing the bytes (`bks::tests::real_bouncy_castle_files_are_reproduced_bit_for_bit`,
`bcfks::tests::real_bouncy_castle_files_are_reproduced_bit_for_bit`).
