# Rate My Domain - Open Framework

## What does the value of the score mean?

The vulnerability score of a domain is directly related with its exposure level - **the higher the score, the higher the vulnerability/ exposure level**. Therefore, ideally the vulnerability score of a domain would be zero or close to zero.


## How does BinaryEdge compute the score of a Domain?

First of all, we've previously selected the most relevant data points that influence the exposure of a domain and grouped them into categories. Since these categories have different levels of importance in terms of security, they contribute with different weights to the vulnerability score.

When someone asks for a score of a domain, a scan event is triggered on that domain and the relevant information is gathered. The final score of the domain is computed and it is presented as a normalized value of the weighted sum of the values given by each category.


## Categories

In order to determine the vulnerability score of a domain, we've grouped the meaningful data points (parameters) into 3 different categories. These categories have different weights according to their importance from a security perspective:

| Category | Weight |
| --- | --- |
| Cookies | 0.2 |
| SSL | 0.1 |
| Headers | 0.7 ||

Cookies and Security Headers are incredibly important parameters when configuring a domain. They ensure that the information is only transmitted via secure connections and that session IDs can't be stolen via XSS or Man-in-the-Middle attacks, for example.

As for SSL, we check if the domain allows for SSL connections and if so, if it is correctly configured (the information transmitted would be encrypted).


### 1. Cookies
(*cookies_score*)

  * Secure
  * HTTP only
  * SameSite
  * Domain/ Path Attributes
  * Expire/ Max-age Attributes


### 2. SSL
(*ssl_score*)

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


### 3. Headers
(*headers_score*)

Please refer to [IP Scoring - Web](https://github.com/balgan/ratemyip-openframework/blob/master/ip-score.md#5-web)



## Formulas

When a scoring request is made to the API, the response contains different scores, although all of them are calculated based on the same information, it's quite important to understand the difference between them.


**Domain Score Detailed** is the minimum value between the Domain Score Detailed value of each category and the maximum possible value of that category.

| category | max value | label |
| --- | --- | --- |
| cookies | 44 | *cookies_max* |
| ssl | 58 | *ssl_max* |
| headers | 53 | *headers_max* ||

```math
ip_score_detailed(cookies) = min(cookies_score, cookies_max)
ip_score_detailed(ssl) = min(ssl_score, ssl_max)
ip_score_detailed(headers) = min(headers_score, headers_max)
```

**Normalized Domain Score Detailed** is the result of the division of the Domain Score Detailed of a category by the maximum value of that category. This result is then multiplied by 100, resulting in a percentage.

```math
cookies = domain_score_detailed(cookies) / cookies_max * 100
ssl = domain_score_detailed(ssl) / ssl_max * 100
headers = domain_score_detailed(headers) / headers_max * 100
```

**Normalized IP Score** is the weighted sum of the Normalized Doman Score Detailed results, resulting in a final score for the Domain, also in percentage.

```math
normalized_domain_score = cookies * 0.2 + ssl * 0.1 + headers * 0.7
```
