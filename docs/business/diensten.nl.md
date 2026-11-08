# Diensten (gepland) - Nederlands

Status: **nog geen betaalde opdrachten.** Eerst de inschrijving als ondernemer (KvK).
Indicatieve prijzen zijn er om te beoordelen of het past; het zijn geen offertes.

## 1. AI-code securitybeoordeling

**Voor** een repository, of de pull requests van een team, waar AI-agents code of
beveiligingsfixes schreven, en iemand (een klant, een auditor, een bestuur) vraagt "hoe
weet je dat de fixes echt zijn?"

**Werkwijze.** De Saikou-engine draait over de wijzigingen (onderdrukking als witwasmiddel,
ongekoppelde guards, halve fixes op gedeelde sinks, weggelaten code, API-breuken,
verzwakte analyzer-config); daarna beoordeel ik wat gemeld wordt en wat de engine niet kan
beoordelen.

**Op te leveren**
- Schriftelijk rapport. Elke bevinding zegt hoe ze is vastgesteld (tool, parser of
  mechanisch). Een heldere lijst van wat *niet* is gecontroleerd.
- Fix-pull-requests voor wijzigingen die de verificatie doorstaan. Mislukte pogingen worden
  gemeld als afgekeurd, met reden.
- Machineleesbare resultaten (JSON en SARIF).

**Indicatieve prijs:** EUR 750-1.500 vast per repository-scope, vooraf afgesproken.
**Indicatieve doorlooptijd:** 3-5 werkdagen.

**Jij levert:** leestoegang tot de repository of pull requests; een contactpersoon die
vragen over de bedoeling kan beantwoorden.

**Niet inbegrepen:** penetratietests; audit van het hele systeem; alles oplossen wat
gevonden wordt; certificaten of compliance-uitspraken.

## 2. Externe kwetsbaarheidsscan (in voorbereiding)

**Voor** internetgerichte systemen die van jou zijn, als input voor kwetsbaarhedenbeheer.

**Op te leveren:** rapport met bevindingen en bewijs, gefilterd op valse meldingen, met een
expliciete verklaring wat wel en niet in scope was.

**Indicatieve prijs:** EUR 1.500-3.000 per opdracht.

**Voorwaarden, waarvan er nog geen bestaat:**
1. De scantooling dwingt zelf een afgesproken scope af en weigert elk ander doel.
2. Alleen echte scans; demonstratie- of voorbeelddata verschijnt nooit in een klantrapport.
3. Een getekende scope- en toestemmingsovereenkomst ([sjabloon](scope-overeenkomst.nl.md)).
4. Een beroepsaansprakelijkheidsverzekering is afgesloten.

## Hoe een opdracht verloopt

1. Scope op papier: wat erin zit, wat erbuiten valt, prijs, opleverdatum.
2. Getekende toestemming voordat er gescand of ingelogd wordt.
3. Je code blijft bij mij en mijn tools. De verificatie-engine draait lokaal. Er gaat niets
   naar een AI-aanbieder zonder jouw schriftelijke toestemming, en dan alleen naar de
   aanbieder die jij noemt.
4. Rapport en overdracht; vervolgvragen zitten in de prijs.

## Wat je niet krijgt

- Een certificaat, een score, of de uitspraak dat je "NIS2-compliant" bent. Compliance is
  een juridisch oordeel; dit is bewijsmateriaal daarvoor.
- Juridisch advies.
- Een garantie dat niets gemist is.

## Context

De Cyberbeveiligingswet is de Nederlandse uitwerking van NIS2 en geldt sinds 15 augustus
2026 voor ruim 8.000 organisaties ([NCSC](https://www.ncsc.nl/nieuws/cbw-en-wwke-vanaf-15-augustus-2026-van-kracht)).
Artikel 21, tweede lid, onder e, van de richtlijn betreft beveiliging bij het verwerven,
ontwikkelen en onderhouden van netwerk- en informatiesystemen, met inbegrip van het
omgaan met kwetsbaarheden ([EUR-Lex 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)).
Dit is context, geen juridisch advies.
