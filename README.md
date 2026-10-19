# EdgeEver Encrypted Notebook

An EdgeEver plugin that creates passphrase-protected notebooks. Notebook text is encrypted in the client before it is saved as an EdgeEver note. The plugin toolbar offers **New encrypted notebook** and **Notebook list** actions, and the plugin commands provide create/open shortcuts.

## Notebook editor

A decrypted notebook opens in the plugin's own Markdown editor with Write and Preview modes. Its side panel lets you create, select, rename, and delete notes. Choose **Encrypt and save** to save the complete notebook as one encrypted payload. Each time you open a notebook, the plugin asks for its passphrase again.

The preview supports headings, paragraphs, emphasis, links, lists, blockquotes, inline code, and fenced code blocks. It builds DOM nodes and renders Markdown as text; raw HTML is not executed.

## Encryption format

- The settings page offers AES-GCM with 256-bit (default) or 128-bit keys. The selection applies to newly created notebooks; saved notebooks retain their own algorithm metadata.
- A key is derived from the passphrase using PBKDF2-HMAC-SHA-256 with 310,000 iterations.
- Every save generates a fresh 16-byte random salt and 12-byte random AES-GCM nonce (IV). The nonce must not repeat with the same key; generating a fresh salt also derives a fresh key for each save.
- AES-GCM uses a 128-bit authentication tag. A wrong passphrase or modified ciphertext fails authentication.
- The stored envelope carries the algorithm, KDF name and iteration count, salt, nonce, and ciphertext. These parameters are required for decryption and are not secret. The envelope encoding is only a serialization format, not extra encryption.
- Notebook names, the encrypted data note, and its `encrypted-notebook-vault` discovery tag remain visible in EdgeEver. Note titles and Markdown are encrypted together inside the payload.
- Creation waits for EdgeEver to sync a newly created notebook and expose its permanent ID before writing the encrypted data note. The notebook temporarily receives a unique syncing name so it can be found reliably across local-to-server ID remapping; the requested name is restored before the encrypted note is written. If sync does not finish within one minute, the encrypted payload stays in memory in the open creation form and can be retried after sync. The plugin does not write a vault note against a temporary notebook ID.
- Vault discovery queries the tag across notebooks, then matches the vault note's current notebook association. This allows the plugin to detect stale notebook IDs; it offers a repair action to move an orphaned vault note into the notebook selected in the plugin. Older untagged vaults are found through paginated title searches both within the selected notebook and across the workspace when looking for orphaned vaults.

## Client-side plaintext

The plugin retains decrypted note text and the passphrase only in client-side JavaScript memory while the notebook remains open. It clears its in-memory references and panel content when the notebook is locked, the panel closes, or the plugin deactivates. Unsaved edits prompt before navigation or close.

JavaScript cannot guarantee secure memory erasure: strings are immutable and the runtime may retain copies until garbage collection. Browser internals, screenshots, crash reporting, other extensions, or a compromised client may also expose plaintext. A strong, unique passphrase is important because anyone who gets the encrypted payload can make offline guesses. Lost passphrases cannot be recovered.

## Install

In EdgeEver, use **Plugin Marketplace** and install the repository from GitHub. The plugin package consists of `manifest.json`, `main.js`, and `styles.css`.

