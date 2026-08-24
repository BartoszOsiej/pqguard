Output assets/pqguard-demo.gif

Set FontSize 16
Set Width 960
Set Height 420
Set Shell bash
Set Theme {
  "name": "pqguard",
  "black": "#0d1117",
  "red": "#f85149",
  "green": "#3fb950",
  "yellow": "#e3b341",
  "blue": "#58a6ff",
  "magenta": "#a371f7",
  "cyan": "#39c5cf",
  "white": "#e6edf3",
  "brightBlack": "#8b949e"
}

Type "pqguard keygen --output my-key"
Enter
Sleep 800ms
Type "   ✓ Keypair generated: my-key.pub, my-key.key"
Enter
Type "   Algorithm: ML-KEM-768 (FIPS 203)"
Enter
Sleep 600ms

Type "pqguard info my-key.pub"
Enter
Sleep 600ms
Type "   📋 Key Information"
Enter
Type "   Type: PQGUARD-PUBLIC-KEY"
Enter
Type "   Algorithm: ML-KEM-768"
Enter
Type "   Size: 9472 bits"
Enter
Sleep 400ms

Type "echo 'Top secret data' > secret.txt"
Enter
Sleep 400ms

Type "pqguard encrypt secret.txt -r my-key.pub -o secret.pqg"
Enter
Sleep 800ms
Type "   Size: 17 bytes → 1376 bytes (8094.1%)"
Enter
Type "   KEM: ML-KEM-768"
Enter
Type "   Cipher: AES-256-GCM"
Enter
Sleep 600ms

Type "pqguard decrypt secret.pqg -k my-key.key -o decrypted.txt"
Enter
Sleep 800ms
Type "   Decrypted: 17 bytes"
Enter
Type "   Algorithm: ML-KEM-768"
Enter
Sleep 400ms

Type "diff secret.txt decrypted.txt && echo '✓ Perfect match'"
Enter
Sleep 1s

Type "# ML-KEM-768 + AES-256-GCM — quantum-safe encryption"
Enter
Sleep 800ms
