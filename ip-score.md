# Rate My IP - Open Framework

## What does the value of the score mean?

The vulnerability score of a domain is directly related with its exposure level - **the higher the score, the higher the vulnerability/ exposure level**. Therefore, ideally the vulnerability score of a domain would be zero or close to zero.


## How does BinaryEdge compute the score of an IP address?

First, through [40fy](https://40fy.io), BinaryEdge scans an IP address with the intent to find which services are exposed to the internet. By using different [modules](https://github.com/binaryedge/api-publicdoc/tree/master/modules), we gather specific and detailed information about each service exposed.

From the data gathered, we selected the most relevant data points that influence the exposure of an IP address and grouped them into categories. Since these categories have different levels of importance in terms of security, they contribute with different weights to the vulnerability score. Therefore, the final score of an IP address is a normalized value of the weighted sum of the values given by each category.


## Categories

In order to determine the vulnerability score of an IP address, we've grouped the meaningful data points (parameters) into 7 different categories. These categories and their parameters are fixed so that we always use the same information to rate an IP address.

As mentioned above, these categories have different weights according to their importance from a security perspective:

| Category | Weight | Label |
| --- | --- | --- |
| Storage Technologies | 10 | *storage_max* |
| Remote Management Services | 10 | *rms_max* |
| Encryption | 6 | *encryption_max* |
| CVE | 3 | *cve_max* |
| Web | 3 | *web_max* |
| Attack Surface | 2 | *attack_surface_max* |
| Torrent Downloads | 1 | *torrents_max* ||

As their categories, the parameters also have different levels of importance, therefore, they will contribute in different ways to the vulnerability score of their category.

As the end user should know exactly what's affecting the score of their IP address, we've compiled a detailed list of all the categories and the parameters that affect each one

### 1. Storage Technologies

  * MongoDB
  * Redis
  * ElasticSearch
  * Memcached
  * MQTT
  * MySQL
  * PostgreSQL
  * MsSQL

We've selected 8 storage technologies that could expose data if not properly configured. Therefore, if an IP address has one of these technologies without authentication, its level of exposure (*storage_score*) is automatically considered extreme.

### 2. Remote Management Services

  * Use of telnet
  * RDP without proper firewalling
  * VNC without authentication
  * X11 without authentication

If an IP address is using telnet instead of SSH or has RDP, VNC and X11 without the correct configurations (proper firewalling of authentication for instance), one can consider that the level of exposure (*rms_score*) of that IP address is extreme.


### 3. Encryption

The use of unencrypted services, use of algorithms that are not recommended by security guidelines are only a few examples of what contributes to increase the vulnerability level of an IP address when it comes to encryption.

* **SSH insecure configuration** (*ssh_score*)
  * Presence of [Debian Weak Keys](https://github.com/binaryedge/debian-ssh)
  * Keys with key length inferior or equal to 1024 bytes
  * Kex Algorithms sha1
  * Mac Algorithms sha1, md5, md4, md2
  * Encryption Algorithms 3des-cbc, 'blowfish-cbc', 'cast128-cbc'

* **Weak SSL Configuration** (*ssl_score*)
  * Expired certificates
  * Self-signed certificates
  * No support for OCSP Stapling
  * Signature Algorithm md5withRSAEncryption or sha1withRSAEncryption
  * Vulnerable to Heartbleed
  * Vulnerable to CCS Injection
  * Vulnerable to logjam
  * Vulnerable to drown
  * Vulnerable to poodle
  * Vulnerable to crime
  * No support for Renegotiation

* **Weak Email Configuration** (*wec_score*)
  * Use of POP3 instead of POP3S
  * Use of IMAP instead of IMAPS
  * Use of SMTP instead of SMTPS

* **FTP** (*ftp_score*)
  * Use of FTP instead of FTPS

* **Lack of HTTPS across all services** (*http_score*)
  * Lack of HTTPS across all services


When it comes to encryption, if an IP address is using Debian Weak Keys, has any of the vulnerabilities listed for SSL, has weak email configurations, uses FTP instead of FTPS or lacks HTTPS across all services, then its level of exposure is classified as extreme. For all the other parameters analysed in this category, the level of exposure of an IP address will increase with the number of times one of those is present.


### 4. CVE

Common Vulnerabilities and Exposures (CVE) is measured by adding the values of [CVSS -Common Vulnerability Scoring System](https://www.first.org/cvss) of the combinations of products and versions detected (*cve_score*).

For example, if an IP address has multiple combinations of products and versions with low CVSS values or a few combinations but high CVSS values, then the vulnerability scoring for this parameter is going to be high.


### 5. Web

  * Lack of security headers in web services: Referrer-Policy, X-XSS-Protection, Content-Security-Policy, Public-Key-Pins, X-Content-Type-Options, X-Frame-Options and Strict-Transport-Security

The lack of at least one security header represents an extreme level of exposure (*web_score*).


### 6. Attack Surface

The attack surface is measured by the number of open ports of an IP address. The higher number of open ports, the higher the vulnerability level (*ports_score*).


### 7. Torrent Downloads

If an IP address is downloading torrents, the risk level (*torrents_score*) is considered extreme.


## Formulas

When a request is made to the API, the response contains different scores, although all of them are calculated based on the same information, and it's quite important to understand the difference between them.

First of all, the score of each category is calculated by adding up the individual scores of each parameter. For example, in order to compute the cve_score, we need to add up all the CVSS values of all the combinations of products and versions found.

**IP Score Detailed** is the minimum value between the IP Score Detailed value of each category and the maximum possible value of that category. If the category has more than one parameter (ex: Encryption), then the IP Score Detailed is computed by adding up the score of the parameters and finding the minimum between this value and the maximum of the category.

```math
ip_score_detailed(storage) = min(storage_score, storage_max)
ip_score_detailed(rms) = min(rms_score, rms_max)
ip_score_detailed(encryption) = min(ssh_score + ssl_score + wec_score + ftp_score + http_score, encryption_max)
ip_score_detailed(cve) = min(cve_score, cve_max)
ip_score_detailed(web) = min(web_score, web_max)
ip_score_detailed(attack_surface) = min(ports_score, attack_surface_max)
ip_score_detailed(torrents) = min(torrents_score, torrents_max)
```

*Note*:Under "results", it's possible to see each individual ip_score_detailed of each category as well as the parameters that originated that score.


**Normalized IP Score Detailed** is the result of the division of the IP Score Detailed of a category by the maximum value of that category. This result is then multiplied by 100, resulting in a percentage.

```math
storage = ip_score_detailed(storage) / storage_max * 100
rms = ip_score_detailed(rms) / rms_max * 100
encryption = ip_score_detailed(encryption) / encryption_max * 100
cve = ip_score_detailed(cve) / cve_max * 100
web = ip_score_detailed(web) / web_max * 100
attack_surface = ip_score_detailed(attack_surface) / attack_surface_max * 100
torrents = ip_score_detailed(torrents) / torrents_max * 100
```

**Normalized IP Score** is the weighted sum of the Normalized IP Score Detailed results, resulting in a final score for the IP address, also in percentage.

```math
total_max = storage_max + rms_max + encryption_max + cve_max + web_max + attack_surface_max + torrents_max
normalized_ip_score = (ip_score_detailed_storage + ip_score_detailed_rms + ip_score_detailed_encryption + ip_score_detailed_cve + ip_score_detailed_web + ip_score_detailed_attack_surface + ip_score_detailed_torrents) / total_max * 100
```
