# Scope- en toestemmingsovereenkomst (sjabloon) - Nederlands

> **Conceptsjabloon. Geen juridisch advies en niet door een jurist beoordeeld.** Laat een
> jurist met kennis van Nederlands recht dit controleren en aanpassen voordat iemand wordt
> gevraagd te tekenen. De velden tussen haakjes zijn de feiten van één opdracht en worden
> door partijen ingevuld.

**Tussen**
1. **Opdrachtgever:** [juridische naam, adres, KvK-nummer, vertegenwoordiger]
   (“Opdrachtgever”), en
2. **Opdrachtnemer:** [juridische naam, adres, KvK-nummer, vertegenwoordiger]
   (“Opdrachtnemer”).

**Datum:** [datum]  **Kenmerk opdracht:** [kenmerk]

## 1. Doel

Opdrachtnemer voert voor Opdrachtgever de in Bijlage A omschreven werkzaamheden uit
(“Diensten”). Deze overeenkomst verplicht partijen niet tot verdere opdrachten.

## 2. Scope (Bijlage A)

2.1 De Diensten gelden **uitsluitend** voor de systemen, repositories en adressen in
Bijlage A (“In Scope”): [repositories / pull requests / domeinen / IP-bereiken].

2.2 Al het andere valt **buiten scope**, inclusief systemen van derden en elk systeem dat
niet is genoemd. Opdrachtnemer test, scant of benadert niets buiten scope en stelt zijn
tools zo in dat doelen buiten Bijlage A worden geweigerd.

2.3 Tijdvenster: [start] tot [einde], [tijdzone]. Contactpersonen voor vragen en om het
werk direct te stoppen: Opdrachtgever [naam, telefoon, e-mail]; Opdrachtnemer [naam,
telefoon, e-mail].

## 3. Toestemming (voorwaarde voor elke scan of toegang)

3.1 Opdrachtgever verklaart eigenaar te zijn van de systemen in scope of bevoegd te zijn
om de Diensten daarvoor toe te staan, en **geeft Opdrachtnemer toestemming de Diensten op
die systemen uit te voeren binnen het tijdvenster**.

3.2 Wanneer systemen in scope door derden worden gehost (cloud, hosting, CDN), is
Opdrachtgever verantwoordelijk voor de toestemming die die partijen vereisen en heeft die
vóór aanvang verkregen.

3.3 Blijken de verklaringen in 3.1 of 3.2 onjuist, dan mag Opdrachtnemer onmiddellijk
stoppen. Opdrachtgever vrijwaart Opdrachtnemer voor aanspraken van derden die daaruit
voortvloeien.

## 4. Toegestane methoden en grenzen

4.1 Bij kwetsbaarheidsscans: geen denial-of-service of stresstests; geen social
engineering of fysieke toegang; verzoeksnelheid beperkt tot [snelheid]; geen misbruik
verder dan nodig om een bevinding te onderbouwen; geen lezen, kopiëren of wijzigen van
productiegegevens voorbij dat minimum; geen persistentie of laterale beweging.

4.2 Bij code-beoordeling: alleen-lezen toegang tot de repositories in Bijlage A.
Opdrachtnemer stelt wijzigingen voor als pull requests en pusht niet naar beschermde
branches.

4.3 Opdrachtnemer stopt direct op verzoek van de contactpersoon van Opdrachtgever of bij
waarneming van gevolgen voor de beschikbaarheid.

## 5. Omgaan met gegevens

5.1 Opdrachtnemer behandelt alles wat hij over Opdrachtgever te weten komt als
vertrouwelijk en gebruikt het alleen voor de Diensten.

5.2 Code en bevindingen worden verwerkt op de eigen systemen van Opdrachtnemer. Ze worden
alleen met **voorafgaande schriftelijke toestemming van Opdrachtgever** naar een
AI-aanbieder gestuurd, waarbij die aanbieder wordt genoemd.

5.3 Persoonsgegevens die incidenteel worden aangetroffen, worden geminimaliseerd en niet
gekopieerd tenzij nodig als bewijs. Verwerkt Opdrachtnemer persoonsgegevens namens
Opdrachtgever, dan sluiten partijen vóór aanvang een verwerkersovereenkomst.

5.4 Opdrachtnemer verwijdert werkkopieën [30] dagen na oplevering van het rapport, tenzij
Opdrachtgever schriftelijk anders verzoekt.

## 6. Rapportage

6.1 Opdrachtnemer levert een schriftelijk rapport: bevindingen met hoe elke is vastgesteld,
de grenzen van het werk, en wat niet is gecontroleerd. Bevindingen met een onmiddellijk
ernstig risico worden zonder het rapport af te wachten aan de contactpersoon van
Opdrachtgever gemeld.

6.2 Het rapport is van Opdrachtgever. Opdrachtnemer mag een beschrijving van de methode
bewaren, zonder Opdrachtgever te noemen; de open-sourcetools blijven onder hun eigen
licenties.

## 7. Geen garantie, geen certificering

7.1 De Diensten leveren bewijsmateriaal over wat is gecontroleerd. Ze zijn geen
certificaat, geen verklaring van juridische compliance (bijvoorbeeld met de
Cyberbeveiligingswet of NIS2), geen juridisch advies en geen garantie dat niets is
gemist.

## 8. Vergoeding

8.1 Vast bedrag: EUR [bedrag] excl. btw, gefactureerd [bij oplevering / in twee delen];
betaalbaar binnen [14] dagen. Werk buiten Bijlage A wordt eerst schriftelijk afgesproken.

## 9. Aansprakelijkheid

9.1 De totale aansprakelijkheid van Opdrachtnemer onder deze overeenkomst is beperkt tot
de vergoeding die is betaald voor de opdracht waarin de schade ontstond, met een maximum
van EUR [bedrag], behalve bij opzet of bewuste roekeloosheid of voor zover de wet beperking
niet toestaat.

9.2 Opdrachtgever erkent dat testen, ondanks zorg, de beschikbaarheid van systemen kan
raken en heeft de back-ups en voorzorgsmaatregelen genomen die hij nodig acht.

## 10. Duur en beëindiging

10.1 De overeenkomst eindigt bij oplevering en acceptatie van het rapport. Elke partij kan
eerder schriftelijk beëindigen; vergoeding voor verricht werk blijft verschuldigd.

## 11. Toepasselijk recht en geschillen

11.1 Nederlands recht is van toepassing. Geschillen gaan naar de bevoegde Nederlandse
rechter.

---

**Namens Opdrachtgever** ____________________  Naam: ____________  Datum: __________

**Namens Opdrachtnemer** ___________________  Naam: ____________  Datum: __________

**Bijlage A - Diensten en In Scope:** [lijst]
