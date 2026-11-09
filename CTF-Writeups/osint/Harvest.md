HARVEST

HARVEST
Category: OSINT
Points: 270
Approach & Validation: The objective of this challenge was to investigate a potential disinformation campaign. A regional Telegram channel claimed that an Mi-24 attack helicopter ("bort 34") delivered a sling-load cargo near Staroselye on 14 August at 19:42 MSK. We were tasked with determining the true destination and cargo using a provided intelligence cache from the 417th Separate Helicopter Squadron (aerodrome KORLEVO)[cite: 3].

Our workflow was divided into two phases: Logistics Correlation (OSINT) and Radio Decryption (SIGINT).

1. OSINT & Logistics Correlation: We began by analyzing the public claims (01_telegram_post.txt and 02_photo.png)[cite: 3]. To verify the flight, we cross-referenced the claimed time (19:42 MSK) and aircraft ("bort 34") against the squadron's internal records: the daily flight schedule (03_flight_schedule_14AUG.txt) and the logistics sheet (05_logistics_sheet_14AUG.txt)[cite: 3].

This cross-referencing revealed critical discrepancies. The internal logs proved that the Telegram post was inaccurate regarding the specific aircraft conducting the sling-load operation at that time. By tracing the actual logistics ledger, we successfully identified the correct callsign and aircraft responsible for the 14 August cargo delivery.

2. SIGINT & Cryptographic Analysis: Having identified the correct flight, we shifted focus to the intercepted radio traffic (06_intercepts_14AUG.txt)[cite: 3]. The transmissions were encrypted using the squadron's daily codes.

Using the provided signals instruction extract (04_signals_instruction_extract.txt)[cite: 3], we manually performed cryptanalysis on the intercepts. By applying the squadron's brevity matrices and daily trigraph tables to the raw radio text, we successfully decrypted the communications in plaintext.

3. Data Assembly: The decrypted radio intercepts yielded two critical pieces of operational ground truth that contradicted the public Telegram post:

The actual drop zone (designated as a specific Point Number).
The specific Codeword for the sling-load cargo.
We formatted these extracted values according to the required challenge format (CSCTF{PP-N_CODEWORD})[cite: 3].

Result: By exposing the Telegram disinformation through internal logistics correlation and decrypting the intercepted radio traffic, we identified the true cargo and destination, yielding the final flag: CSCTF{[REDACTED]}.
