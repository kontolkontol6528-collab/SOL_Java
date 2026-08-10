# SOL_Java

Scanner that generates 12-word mnemonics by shuffling a BIP39 wordlist (`bip39.txt`), validates the mnemonic checksum, then derives Solana addresses using the `m/44'/501'/0'/0'` path (Phantom-compatible) and checks balances via the public Solana RPC. Hits (non-zero balances) are appended to `hits.txt`.

Usage:

1. Place `bip39.txt` (2048 English BIP39 words, one per line) in the project root.
2. Build: `mvn -DskipTests clean package`
3. Run: `java -jar target/SOL_Java-0.1.0-shaded.jar`

Notes:
- Uses max cores minus one for worker threads.
- Live dashboard prints tries and hits on a single line.
- Appends to `hits.txt` when non-zero balances are found.

Security: Do not run this with mnemonics or keys you care about. This tool is for research/educational purposes.
