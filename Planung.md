&#x20;                ┌──────────────────────┐

&#x20;                │    Login-Webseite           │

&#x20;                └─────────────────────┘

&#x20;                           │

&#x20;                           ▼

&#x20;                ┌──────────────────────┐

&#x20;                │     Login-System     	   │

&#x20;                │ Benutzer + Passwort  	   │

&#x20;                └──────────┬───────────┘

&#x20;                           │

&#x20;                    Login-Ereignis

&#x20;                           │

&#x20;                           ▼

&#x20;                ┌──────────────────────┐

&#x20;                │     Security Log     	   │

&#x20;                │  Zeit/IP/User/Status 	   │

&#x20;                └──────────┬───────────┘

&#x20;                           │

&#x20;                           ▼

&#x20;                ┌──────────────────────┐

&#x20;                │  Security Analyzer          │

&#x20;                │      C#                     │

&#x20;                └──────────┬───────────┘

&#x20;                           │

&#x20;            ┌─────────────────────────────┐

&#x20;            ▼              ▼              ▼

&#x20;       Brute Force    Fehlversuche    Anomalien    │

&#x20;            │                                 

&#x20;            └─────────────────────────────┘

&#x20;                           ▼

&#x20;                   Analyse / Report

&#x20;                           │

&#x20;                           ▼

&#x20;                    Tests + Doku





Die erste funktionierende Version soll:



* einen Benutzer anmelden können
* erfolgreiche Logins erkennen
* fehlgeschlagene Logins erkennen
* Login-Ereignisse protokollieren
* die Logs einlesen können
* fehlgeschlagene Login-Versuche zählen
* ungewöhnlich viele Fehlversuche erkennen
* einfache Brute-Force-Muster erkennen
* verdächtige Login-Muster melden
* Testfälle ausführen können
* Ergebnisse dokumentieren können



Das ist unser Minimum Viable Product.

PHASE 1

                 Browser
                    │
                    ▼
          ┌──────────────────┐
          │   Login-Seite    │
          │                  │
          │ Benutzername     │
          │ [____________]   │
          │                  │
          │ Passwort         │
          │ [____________]   │
          │                  │
          │   [ Einloggen ]  │
          └────────┬─────────┘
                   │
                   ▼
             Login-System
                   │
             ┌─────┴─────┐
             ▼           ▼
          Erfolg       Fehler
             │           │
             └─────┬─────┘
                   ▼
                Logging




Security observability

Login-Ereignisse,
sichtbar gemacht.
Serverseitig protokollierte Anmeldeversuche mit einer kleinen, nachvollziehbaren Analyse.

Präsentationsansicht

Regelwerk und Auswertung
Diese Seite erklärt, welche Daten gesammelt werden und wann der Analyzer ein Ereignis als auffällig bewertet.

Zurück zum Dashboard
1. Vom Login zum Hinweis
Bei jedem Login-Versuch prüft das C#-Backend Benutzername und Passwort. Danach wird immer ein Ereignis in SQLite gespeichert, egal ob der Login erfolgreich war oder nicht.

Gespeichert werden Benutzername, Erfolg oder Misserfolg, Zeitpunkt, IP-Adresse, Browserinformationen und der Fehlergrund. Der Analyzer liest diese Ereignisse ein, gruppiert sie nach Benutzer und IP-Adresse und vergleicht sie mit den folgenden Regeln.

2. UserFailureCount
Auslöser: Mindestens 3 fehlgeschlagene Login-Versuche für denselben Benutzernamen.

Bedeutung: Der Benutzer ist auffällig, aber das ist noch kein sicherer Angriff. Es könnte auch ein vergessenes Passwort sein.

Beispiel: anna schlägt sich dreimal mit einem falschen Passwort an.

medium
3. UserBruteForce
Auslöser: Mindestens 5 Fehlversuche für denselben Benutzer innerhalb von 10 Minuten.

Bedeutung: Das Zeitfenster und die Anzahl sprechen für wiederholtes Passwort-Raten gegen ein bestimmtes Konto.

Beispiel: Der Benutzer anna erhält in kurzer Zeit fünf falsche Passwortversuche.

high
4. IpBruteForce
Auslöser: Mindestens 5 fehlgeschlagene Versuche von derselben IP innerhalb von 10 Minuten.

Bedeutung: Der Angriff wird anhand der Quelle erkannt, auch wenn verschiedene Benutzernamen verwendet werden.

Beispiel: Eine IP probiert wiederholt Passwörter gegen Konten aus.

high
5. IpUserSpray
Auslöser: Eine IP-Adresse versucht sich bei mindestens 3 verschiedenen Benutzern anzumelden.

Bedeutung: Das kann auf User-Spraying hindeuten: wenige Passwörter werden gegen viele Konten getestet.

Beispiel: Dieselbe IP versucht anna, ben und cara.

high
6. SuccessAfterFailures
Auslöser: Ein erfolgreicher Login folgt innerhalb von 10 Minuten auf mindestens 3 Fehlversuche von derselben IP.

Bedeutung: Das Passwort könnte erraten worden sein. Es ist ein Hinweis zur Untersuchung, kein Beweis für einen Angriff.

Beispiel: Drei falsche Versuche und danach ein erfolgreicher Login für denselben Benutzer.

high
7. Schweregrade
medium: Auffälligkeit, die beobachtet werden sollte, aber mehrere harmlose Ursachen haben kann.

high: Starkes Muster oder mehrere Indikatoren, die zeitnah untersucht werden sollten.

Mehrere Meldungen können dasselbe Ereignis beschreiben. Das bedeutet nicht automatisch mehrere Angriffe, sondern dass mehrere Regeln gleichzeitig erfüllt wurden.

8. Beispiel für die Präsentation
„Der Analyzer bewertet nicht nur, ob ein Login erfolgreich war. Er untersucht auch, wie oft, wie schnell, von welcher IP-Adresse und gegen wie viele Benutzer Anmeldeversuche stattfinden. Dadurch können wir zwischen einem einzelnen Tippfehler, Brute Force gegen ein Konto und User-Spraying gegen mehrere Konten unterscheiden.“

„Ein Benutzer wird ab drei Fehlversuchen als auffällig markiert. Fünf Fehlversuche innerhalb von zehn Minuten erhöhen die Einstufung auf ein hohes Risiko. Die IP-Regeln ergänzen die Benutzerregeln, damit Angriffe auch dann erkannt werden, wenn der Angreifer die Benutzernamen wechselt.“


dotnet run --project src\SecurityLogAnalyzer.Api