# VulnScope

VulnScope est un scanner de reconnaissance et d'analyse de vulnérabilités écrit en Python. Il automatise les premières étapes d'un audit en combinant l'énumération réseau, le fingerprinting des technologies, les vérifications de sécurité web et la recherche de CVE connues.

Le projet est conçu pour fournir une vue d'ensemble rapide d'une cible afin d'identifier les services exposés, les technologies utilisées et les vulnérabilités publiques associées.

---

# Fonctionnalités

## Reconnaissance

* Résolution automatique IP ↔ Nom de domaine
* Détection du nom d'hôte
* Scan DNS complet

  * A
  * AAAA
  * MX
  * NS
  * TXT
  * CNAME

## Analyse HTTP

* Détection HTTP / HTTPS
* Suivi des redirections
* Analyse des en-têtes HTTP
* Détection du serveur Web
* Analyse du code de réponse

## Découverte des services

* Scan Nmap
* Détection des ports ouverts
* Identification des services
* Détection des versions
* Identification des produits

## Fingerprinting

Fusion des informations provenant de plusieurs sources :

* Nmap
* En-têtes HTTP
* HTML
* Cookies
* Ressources CSS
* Ressources JavaScript
* Analyse JavaScript

Détection de nombreuses technologies telles que :

* Apache
* Nginx
* IIS
* OpenSSH
* PHP
* Node.js
* Cloudflare
* Vue.js
* Nuxt
* React
* Angular
* Next.js
* Bootstrap
* jQuery
* Axios
* Webpack

Les technologies détectées sont automatiquement fusionnées afin d'éviter les doublons et de conserver les meilleures informations disponibles.

## Analyse JavaScript

* Téléchargement automatique des fichiers JavaScript
* Détection des frameworks
* Détection des bibliothèques
* Recherche des versions lorsqu'elles sont disponibles
* Détection des fichiers Source Map
* Fusion avec les autres méthodes de fingerprinting

## Analyse de sécurité Web

Vérification automatique de nombreux points de sécurité :

### Security Headers

* Content-Security-Policy
* Strict-Transport-Security
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy

### Cookies

* HttpOnly
* Secure
* SameSite

### CORS

* Configuration CORS
* Wildcards
* Credentials

### HTTP Methods

* Vérification des méthodes HTTP exposées

### Sensitive Paths

Recherche de ressources publiques telles que :

* robots.txt
* sitemap.xml
* autres chemins connus

Chaque résultat contient :

* identifiant
* sévérité
* niveau de confiance
* catégorie
* URL
* preuve
* recommandation

## Recherche de CVE

Pour chaque technologie disposant d'une version précise :

* Recherche du CPE exact
* Correspondance avec la base NVD
* Recherche des CVE applicables
* Score CVSS
* Sévérité
* Description

Les technologies sans version exacte sont volontairement ignorées afin d'éviter les faux positifs.

---

# Installation

## Cloner le projet

```bash
git clone https://github.com/USERNAME/VulnScope.git
cd VulnScope
```

## Créer un environnement virtuel

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Installer les dépendances

```bash
pip install -r requirements.txt
```

## Installer Nmap

### Windows

Installer Nmap puis l'ajouter au PATH.

# Utilisation

Lancer VulnScope :

```bash
python main.py
```

Entrer une cible :

```text
google.com
```

ou

```text
8.8.8.8
```

---

# Exemple

```text
Target
        │
        ▼
DNS Enumeration
        │
        ▼
HTTP Analysis
        │
        ▼
Port & Service Discovery
        │
        ▼
Technology Fingerprinting
        │
        ▼
Web Security Analysis
        │
        ▼
CVE Analysis
        │
        ▼
Summary
```

---

# Résultats

À la fin du scan, VulnScope affiche notamment :

* Informations sur la cible
* Enregistrements DNS
* Services détectés
* Technologies identifiées
* Résultats des contrôles de sécurité
* CVE confirmées
* Résumé global

---

# Technologies utilisées

* Python 3
* Requests
* BeautifulSoup
* Nmap
* Colorama
* urllib3

---

# Objectifs

* Automatiser la phase de reconnaissance.
* Réduire le temps d'analyse initial.
* Corréler les technologies détectées avec les vulnérabilités publiques.
* Fournir des résultats lisibles directement en console.
* Limiter les faux positifs grâce à une corrélation basée sur les versions.

---

# Avertissement

VulnScope est destiné à être utilisé uniquement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation explicite. L'utilisateur est seul responsable de l'utilisation qu'il fait de cet outil.

---

# Licence

Ce projet est distribué sous licence MIT.
