Output assets/pqguard-demo.svg

Set FontSize 16
Set Width 960
Set Height 420
Set Shell bash
Set MarginColor "#0d1117"
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

Type "pqguard info my-key.pub"
Enter
Sleep 600ms

Type "echo 'Top secret data' > secret.txt"
Enter
Sleep 400ms

Type "pqguard encrypt secret.txt -r my-key.pub -o secret.pqg"
Enter
Sleep 800ms

Type "pqguard decrypt secret.pqg -k my-key.key -o decrypted.txt"
Enter
Sleep 800ms

Type "diff secret.txt decrypted.txt && echo '✓ Perfect match'"
Enter
Sleep 1s

Type "# ML-KEM-768 + AES-256-GCM — quantum-safe"
Enter
Sleep 800ms
