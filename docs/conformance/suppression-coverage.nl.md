# Dekking van onderdrukkingen

Gegenereerd door `python scripts/suppression_oracle.py conformance` uit
`tests/fixtures/suppression_oracle_golden.json` (Python) en
`tests/fixtures/suppression_oracle_js_golden.json` (JavaScript en TypeScript).
`tests/test_suppression_oracle.py` en `tests/test_suppression_oracle_js.py` falen als dit bestand of
een golden-bestand verouderd is. Niet met de hand aanpassen.

## Wat is gecontroleerd

Het oordeel van Saikou bij wijzigingscontrole op Python-bestanden waarin een onderdrukkingsmarker
wordt toegevoegd aan code met een beveiligingsbevinding: 1697 before/after-paren (broken 126, comment-to-string 14, encoding 131, flag 14, legit-rewrite 4, moved 64, newline 120, position 648, reformatted 4, second-marker 32, spelling 360, string 140, string-nohash 12, string-to-comment 14, string-unchanged 14).
Per paar bepalen de referentietools of zij de nieuwe marker honoreren; daarna is het oordeel van
Saikou met het hunne vergeleken.

| referentietool | hoe |
|---|---|
| bandit 1.9.4 | uitgevoerd op elk paar, met en zonder `--ignore-nosec` |
| ruff 0.17.1 | uitgevoerd met de S-regels, met en zonder `--ignore-noqa` |
| semgrep 1.181.0 | uitgevoerd met een regel per sink, met en zonder `--disable-nosem` |
| flake8 7.4.1 | eigen markerpatroon, uit de release-wheel gelezen |
| sonar-python, CodeQL | markerpatronen uit hun gepubliceerde bronnen; niet uitgevoerd |

## Resultaat

| | paren |
|---|---|
| een referentietool honoreert de nieuwe marker | 879 |
| daarvan blokkeert Saikou | 873 |
| daarvan waarschuwt Saikou | 6 |
| daarvan meldt Saikou niets | 0 |
| geen referentietool honoreert de marker, Saikou blokkeert toch | 585 |

| referentietool | honoreert | Saikou blokkeert | Saikou waarschuwt | niet gemeld |
|---|---|---|---|---|
| bandit | 355 | 349 | 6 | 0 |
| flake8 | 158 | 158 | 0 | 0 |
| ruff | 153 | 148 | 5 | 0 |
| sonar-python | 302 | 302 | 0 | 0 |
| CodeQL | 184 | 184 | 0 | 0 |
| semgrep | 74 | 74 | 0 | 0 |

## Gemeld als waarschuwing in plaats van blokkade

flag/flag-continuation (1), flag/flag-multiline (1), flag/flag-paren (1), flag/flag-plain (1), flag/flag-spaces (1), flag/flag-zero (1).

Het sleutelwoord `usedforsecurity` op gegevens die geen wachtwoordmateriaal zijn is het
gedocumenteerde middel tegen een zwakke-hashbevinding; wijzigingscontrole meldt het daarom als
waarschuwing. Op wachtwoordmateriaal, en bij verificatie van een beweerde fix, blokkeert het. Een
stijlmarker buiten een beveiligingsaanroep is ook een waarschuwing; geen enkele referentietool
honoreert er daar een.

## Niet gemeld

geen.



## Geblokkeerd terwijl geen referentietool de marker honoreert

Elke marker die op een beveiligingsonderdrukking lijkt wordt als zodanig behandeld, waar hij ook
staat in de gewijzigde code, en code die de tools niet kunnen lezen ook.

- de markersyntaxis van een referentietool, maar op een andere regel dan de bevinding of voor een andere regel: 482 paren (position/codeql-id (64), position/NOSONAR (44), position/noqa-code (40), position/lgtm (36), position/lgtm-id (36), position/nosemgrep (36), en nog 39)
- de referentietools kunnen het bestand niet lezen: 85 paren (broken/NOSONAR (28), broken/lgtm (28), broken/nosec (28), encoding/cp037-ascii-bytes (1))
- een lookalike die geen referentietool herkent: 18 paren (position/lgtm (4), spelling/NOSONAR-colon (4), spelling/NOSONAR-dash (4), spelling/nosemgrep-tight (4), encoding/hidden-utf-7 (2))

## Niet gedekt (Python)

Andere talen dan Python, JavaScript en TypeScript. Andere versies van de referentietools dan
hierboven. Markervormen die niet onder de paren vallen. Gedrag van sonar-python en CodeQL buiten hun
gepubliceerde markerpatronen.

## JavaScript en TypeScript

Het oordeel van Saikou bij wijzigingscontrole op `.js`- en `.ts`-bestanden waarin een
onderdrukkingsmarker wordt toegevoegd aan code die een referentietool meldt: 761
before/after-paren (comment-to-string 10, encoding 34, legit-rewrite 2, moved 12, newline 56, position 345, reformatted 2, second-marker 12, spelling 218, string 60, string-to-comment 10). Referentietools, allemaal uitgevoerd: ESLint v9.39.5 (kernregels
en eslint-plugin-security, met en zonder inline-configuratie), de TypeScript-compiler 5.9.3
(een typefout met en zonder de directive) en semgrep 1.181.0 (een regel per sink, met en
zonder `--disable-nosem`).

| | paren |
|---|---|
| een referentietool honoreert de nieuwe marker | 186 |
| daarvan blokkeert Saikou | 174 |
| daarvan waarschuwt Saikou (een type-checker-directive) | 12 |
| daarvan meldt Saikou niets | 0 |
| geen referentietool honoreert de marker, Saikou blokkeert toch | 105 |
| marker van een tool die hier niet is uitgevoerd (SonarJS, CodeQL): Saikou blokkeert | 152 |
| marker van een tool die hier niet is uitgevoerd: Saikou blokkeert niet (binnen een string) | 4 |

| referentietool | honoreert | Saikou blokkeert | Saikou waarschuwt | niet gemeld |
|---|---|---|---|---|
| ESLint | 110 | 110 | 0 | 0 |
| TypeScript | 12 | 0 | 12 | 0 |
| semgrep | 64 | 64 | 0 | 0 |

Niet gemeld: geen.

Een ESLint-directive zonder regellijst zet alle regels uit en telt daarom als
beveiligingsonderdrukking waar hij een regel met een risicovolle aanroep dekt (`eval`,
`new Function`, child_process, `fs`, `vm`, `innerHTML`, een niet-letterlijke `require`, ...); op een
andere regel, of voor een andere regel, is het een waarschuwing. TypeScript-directives zijn
type-checkermarkers en worden als waarschuwing gemeld.

## JavaScript en TypeScript: geblokkeerd terwijl geen uitgevoerde tool de marker honoreert

- de markersyntaxis van een referentietool, maar op een andere regel dan de bevinding of voor een andere regel: 105 paren (position/eslint-line-rule (28), position/nosemgrep (20), string/eslint-block-file (10), position/eslint-block-file (8), string/nosemgrep (8), spelling/eslint-block-file (4), en nog 8)

## JavaScript en TypeScript: niet gedekt

SonarJS en CodeQL (hun markers worden geblokkeerd, maar hun gedrag is niet uitgevoerd).
ESLint-regels buiten de zes ingestelde. Aanroepen buiten de lijst met risicovolle aanroepen. Een
marker die binnen één meerregelige aanroep van regel wisselt. Markers binnen JavaScript-strings
tellen als marker (conservatief).
