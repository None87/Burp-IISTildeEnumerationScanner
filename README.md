# Burp IIS Tilde Enumeration Scanner
A Burp extension to check for the IIS Tilde Enumeration/IIS 8.3 Short Filename Disclosure vulnerability and to exploit it by enumerating all the short names in an IIS web server

Based on <a href="https://github.com/irsdl/IIS-ShortName-Scanner">IIS ShortName Scanner</a>

## Features
This extension will add an Active Scanner check for detecting IIS Tilde Enumeration vulnerability and add a new tab in the Burp UI to manually check and exploit the vulnerability

In the Burp UI tab you can:
* Check if a host is vulnerable without exploiting the vulnerability
* Exploit the vulnerability by enumerating every 8.3 short name in an IIS web server directory
* Configure the parameters used for the scan and customize them in any way you want
* Edit the base request performed (you can add headers, cookies, edit the User Agent, etc)
* Save the scan output to a file
* Create an Intruder Payload Set for guessing complete names from short names retrieved from scan results by using sitemap URLs or dedicated user-provided wordlists
* **(v3.0)** Export the discovered short names as a flat candidate wordlist — drop-in for `ffuf -w`, `feroxbuster -w`, `gobuster -w`
* **(v3.0)** Pick wordlists from the bundled set (`bundled:big`, `bundled:small`, `bundled:common`, `bundled:words_dictionary`, `bundled:extensions`, `bundled:extensions_ignore`) or from any local file path
* **(v3.0)** Opt into the `tildeGuess` reverse-search algorithm for harder-to-recover filenames
* **(v3.0)** **Fuzz Real Paths** — fire the candidate wordlist back at the target server inside Burp, multi-threaded, and surface only hits whose HTTP status code is in the configured success set (default `200,204,301,302,307,401,403`). One click does enumerate → expand → verify in a single flow

## Build
The extension uses the gradle wrapper, JDK 17+.
```bash
./gradlew test jar
```
The generated jar file lives at `./build/libs/iis-tilde-enum.jar`. The filename is
deliberately version-free — Burp pins extensions by absolute path, so the same
file can be overwritten across upgrades without re-adding it in the UI.
A legacy alias task `./gradlew fatJar` still works.

## Screenshots

### Scanner tab (1920x1080)
![1](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner/assets/35109470/288d26b6-32f1-4ceb-9a84-99212a633277)

### Configuration tab (1920x1080)
![2](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner/assets/35109470/a37d7488-d29c-40b6-9e53-b845476c8353)

## Changelog
* v3.0 — UI overhaul
  * **Three-tab layout**: `Scanner` / `Fuzz Hits (n)` / `Configuration`. The Fuzz Hits tab title shows a live count.
  * **Scanner tab redesign**: toolbar (target URL + threads + Scan / Save / Export / Fuzz buttons) on top; horizontal split below with the live log on the left and a **discovered-short-names table** on the right that populates in real time (poll-based, ~500 ms cadence). Status bar with progress bar at the bottom.
  * **Color-coded log** in the log pane: hits (green), errors (red), phase status (blue), info (default).
  * **Fuzz Hits tab**: sortable / filterable JTable with columns *Status · URL · Length · Time*. Right-click on a hit gives **Send to Repeater · Open in Browser · Copy URL**.
  * **Wordlist picker widget**: dropdown of bundled options (`bundled:big`, etc.) plus a **Browse…** button for arbitrary file paths. Replaces the old plain text fields.
  * **Configuration tab grouping** using titled borders — HTTP Request, Tilde Enumeration Magic Values, Filename Constraints, Performance & Detection, Fuzz Real Paths, Filename Guessing & Wordlists. No more 31-row flat grid.
  * **Progress bar feedback** during scan (indeterminate) and fuzz (deterministic, sent/total).

* v3.0
  * **Merged the standalone `iis_tilde_enum` Python tool** into this Burp extension. The ported algorithm now runs natively inside Burp.
  * **Dictionary Export**: new toolbar button on the Scanner tab generates a flat candidate wordlist from the current scan's short names and writes it to disk — drop-in for `ffuf`, `feroxbuster`, `gobuster`.
  * **Two-phase candidate generation** matching the upstream Python:
    * Phase 1 (high priority): dictionary words that share the recovered prefix × extensions that share the recovered short extension
    * Phase 2 (opt-in, `tildeGuess` checkbox): reverse-search rebuilds candidates from every suffix of the short name
  * **Auto-fuzz candidates against the live target** ("Fuzz Real Paths" button): the generated wordlist is requested inside Burp using the same request template as the scanner, results filtered against a configurable success-code set (default matches the Python tool's README). Second click on the same button stops a running fuzz mid-flight.
  * **Bundled wordlists** shipped inside the jar — no separate downloads required:
    * filename: `bundled:big` (the default, ~10K terms), `bundled:small`, `bundled:common`, `bundled:words_dictionary`
    * extensions: `bundled:extensions` (default), `bundled:extensions_ignore`
    * Custom file paths still work in the same field.
  * Project modernized: standard Maven layout, gradle wrapper, JDK 17, JUnit 5, 15 unit tests on the new dictionary engine.
  * Stable jar filename `iis-tilde-enum.jar` so future upgrades don't break Burp's saved extension path.

* v2.0
  * Completely refactored code (ate all the spaghetti, now it is fine ;) )
  * Upgraded threading system to a completely new and improved version to address threading-related bugs such as bruteforce running after stopping and issues with the scan/stop button not starting or stopping the scan correctly
  * Adjusted default configuration values and some active scan parameters to improve accuracy of detection
  * Enhanced dynamic values cleaning by utilizing double-request strip in detection mode to reduce false positive ratio and by incorporating more regexes in bruteforce mode to improve bruteforcing accuracy
  * Added dynamic content strip level configuration value to select level of dynamic content stripping with additional regexes
  * Added delay between requests configuration value to specify the delay between request in milliseconds
  * Added Intruder Payload Set Generator to guess complete file names from scan results using sitemap URLs
  * Improved match list building on complete filename guessing
  * Improved name and extension prefixes feature and fixed some bugs on it
  * Fixed duplicates with unfinished extension in results display
  * Fixed some syncronization issues with output and better UI handling on starting/stopping scan
  * Fixed wordlist fields height in UI
  * Fixed some typos and rephrased some parts
  * Changed detection confidence to "Firm" (there can be false positives, it is never certain!)
  * Changed issue references to the original research paper for issue background and Microsoft workaround for remediation background

* v1.1
  
  Added an Intruder Payload Set Generator for guessing complete names from short names retrieved from scan results (by using wordlists)

* v1.0
  
  First release
