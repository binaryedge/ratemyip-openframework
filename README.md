# Rate My Ip - Open Framework

# Intro

Rate my IP is a free service that was launched by BinaryEdge and can be found [HERE.](https://binaryedge.io/ratemyip.html)

<p align="center"><img src ="https://dl.dropboxusercontent.com/s/04ki2o7ih2sg2xk/rmip.png?dl=0" /></p>


For over two years we've been collecting internet data and watched as IP Addresses expose an ever growing number of services to the internet.
We've also seen over the last year a trend where insurance companies with products in cyber-insurance will create their own ratings. We started looking into these issues and by talking to the insurance companies we heard a common set of complaints:
* They don't know how to rate "cyber"
* They lack valuable data to calculate premiums
* There is a lack of standard on rating systems for "cyber", which makes life difficult for cyber-insurers

When we heard this, we felt there was a need for an open-framework, where the formula to calculate these ratings is exposed to the public, so that, both a standard can be created and people can understand exactly how they are being rated.

This is our first attempt at creating this open-framework.

# Formula and calculations

## How does BinaryEdge compute the score of an IP address?

First, through [40fy](https://40fy.io), BinaryEdge scans an IP address with the intent to find which services are exposed to the internet. By using different [modules](https://github.com/binaryedge/api-publicdoc/tree/master/modules), we gather specific and detailed information about each service exposed.

From the data gathered, we selected the most relevant data points that influence the exposure of an IP address and grouped them into categories. Since these categories have different levels of importance in terms of security, they contribute with different weights to the vulnerability score. Therefore, the final score of an IP address is a normalized value of the weighted sum of the values given by each category.


## Categories

In order to determine the vulnerability score of an IP address, we've grouped the meaningful data points (parameters) into 7 different categories. These categories and their parameters are fixed so that we always use the same information to rate an IP address.

As mentioned above, these categories have different weights according to their importance from a security perspective:

| Category | Weight |
| --- | --- |
| Storage Technologies | 10 |
| Remote Management Services | 10 |
| Encryption | 6 |
| CVE | 3 |
| Web | 3 |
| Attack Surface | 2 |
| Torrent Downloads | 1 ||

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


**IP Score Detailed** is the score of each category. If the category only has one parameter (ex: Storage Technologies), then the IP Score Detailed is equal to the IP Score for that category.

```math
ip_score_detailed(storage) = storage_score
ip_score_detailed(rms) = rms_score
ip_score_detailed(encryption) = ssh_score + ssl_score + wec_score + ftp_score + http_score
ip_score_detailed(cve) = cve_score
ip_score_detailed(web) = web_score
ip_score_detailed(attack_surface) = ports_score
ip_score_detailed(torrents) = torrents_score
```

*Note*:Under "results", it's possible to see each individual ip_score_detailed of each category as well as the parameters that originated that score.

**IP Score** is the sum of the score of each parameter in each category:

```math
ip_score = ip_score_detailed(storage) + ip_score_detailed(rms) + ip_score_detailed(encryption) + ip_score_detailed(cve) + ip_score_detailed(web) + ip_score_detailed(attack_surface) + ip_score_detailed(torrents)
```

**Weighted IP Score Detailed** is the minimum between the IP Score Detailed value of each category and the weight of that category.

```math
  weighted_ip_score_detailed(storage) = min(ip_score_detailed(storage), 10)
  weighted_ip_score_detailed(rms) = min(ip_score_detailed(rms), 10)
  weighted_ip_score_detailed(encryption) = min(ip_score_detailed(encryption), 6)
  weighted_ip_score_detailed(cve) = min(ip_score_detailed(cve), 3)
  weighted_ip_score_detailed(web) = min(ip_score_detailed(web), 3)
  weighted_ip_score_detailed(attack_surface) = min(ip_score_detailed(attack_surface), 2)
  weighted_ip_score_detailed(torrents) = min(ip_score_detailed(torrents), 1)
```

**Weighted IP Score** is the sum of the detailed weighted IP scores of each category.

```math
weighted_ip_score =  weighted_ip_score_detailed(cve) + weighted_ip_score_detailed(attack_surface) + weighted_ip_score_detailed(encryption) + weighted_ip_score_detailed(rms) + weighted_ip_score_detailed(storage) + weighted_ip_score_detailed(web) + weighted_ip_score_detailed(torrents)
```

**Weighted IP Score Normalized** is the product of the weighted IP score and 35 (the maximum value of sum of the weights), divided by 100.
```math
weighted_ip_score_norm = weighted_ip_score * 35 / 100
```


## Schema

```
{
  "weighted_ip_score": int,
  "weighted_ip_score_norm": int,
  "weighted_ip_score_detailed": {
    "cve": int,
    "attack_surface": int,
    "encryption": int,
    "rms": int,
    "storage": int,
    "web": int,
    "torrents": int
  },
  "ip_score": float,
  "ip_score_detailed": {
    "cve": float,
    "attack_surface": int,
    "encryption": int,
    "rms": int,
    "storage": int,
    "web": int,
    "torrents": int
  },
  "results_detailed": {
    "ports": {
      "open": [
        int
      ],
      "score": int
    },
    "cve": {
      "result": [
        {
          "port": int,
          "cve": [
            {
              "cpe": "string",
              "cve_list": [
                {
                  "cve": "string",
                  "cvss": float
                },
              ],
              "score": float
            }
          ],
          "score": float
        }
      ],
      "score": float
    },
    "ssh": {
      "result": [
        {
          "port": int,
          "algorithms": {
            "mac": {
              "mac": [
                "string",
              ],
              "score": [
                int,
              ]
            },
            "kex": {
              "kex": [
                "string"
              ],
              "score": [
                int
              ]
            },
            "encryption": {
              "encryption": [
                "string"
              ],
              "score": [
                int,
              ]
            }
          },
          "key_length": {
            "key_length": [
              int
            ],
            "key_score": [
              int
            ]
          },
          "debian_key": {
            "debian_key": [
              boolean
            ],
            "key_score": [
              int
            ]
          },
          "score": int
        }
      ],
      "score": int
    },
    "rms": {
      "result": [
        {
          "port": int,
          "rms": "string",
          "score": int
        },
      ],
      "score": int
    },
    "ssl": {
      "result": [
        {
          "port": int,
          "heartbleed": {
            "heartbleed": boolean,
            "score": int
          },
          "ccs": {
            "ccs": boolean,
            "score": int
          },
          "scsv": {
            "scsv": boolean,
            "score": int
          },
          "compression": {
            "compression": boolean,
            "score": int
          },
          "renegotiation": {
            "renegotiation": boolean,
            "score": int
          },
          "oscp": {
            "oscp": boolean,
            "score": int
          },
          "certificates_date": [
            {
              "date": "string",
              "status": "string",
              "score": int
            }
          ],
          "self_signed": {
            "self_signed": "string",
            "score": int
          },
          "signatures": [
            {
              "signature": "string",
              "score": int
            }
          ],
          "ciphers": [
            {
              "drown": boolean,
              "score": int
            },
            {
              "poodle": boolean,
              "score": int
            },
            {
              "crime": boolean,
              "score": int
            },
            {
              "logjam": boolean,
              "score": int
            }
          ],
          "score": int
        }
      ],
      "score": int
    },
    "wec": {
      "result": [
        {
          "port": int,
          "service": "string",
          "score": int
        }
      ],
      "score": int
    },
    "ftp": {
      "result": [
        {
          "port": int,
          "service": "string",
          "score": int
        }
      ],
      "score": int
    },
    "http": {
      "result": [
        {
          "port": int,
          "service": "string",
          "score": int
        },
        {
          "port": int,
          "service": "string",
          "score": int
        }
      ],
      "score": int
    },
    "storage": {
      "result": [
        {
          "port": int,
          "module": "string",
          "connected": boolean,
          "score": int
        },
        {
          "port": int,
          "module": "mongodb",
          "total_size": int,
          "score": int
        },
        {
          "port": int,
          "module": "redis",
          "used_memory": int,
          "score": int
        },
        {
          "port": int,
          "module": "memcached",
          "bytes": int,
          "score": int
        },
        {
          "port": int,
          "module": "elasticsearch",
          "contains_node_names": boolean,
          "score": int
        }
      ],
      "score": int
    },
    "web": {
      "result": [
        {
          "port": int,
          "headers_missing": boolean,
          "score": int
        }
      ],
      "score": int
    },
    "torrents": {
      "result": [
        {
          "torrents": boolean,
          "score": int
        }
      ],
      "score": int
    }
  },
  "ip_address": "string"
}
```

## Example

```
{
  "weighted_ip_score": 34,
  "weighted_ip_score_norm": 97.1,
  "weighted_ip_score_detailed": {
    "cve": 3,
    "attack_surface": 2,
    "encryption": 6,
    "rms": 10,
    "storage": 10,
    "web": 3,
    "torrents": 0
  },
  "ip_score": 367.6,
  "ip_score_detailed": {
    "cve": 165.6,
    "attack_surface": 16,
    "encryption": 107,
    "rms": 26,
    "storage": 50,
    "web": 3,
    "torrents": 0
  },
  "results_detailed": {
    "ports": {
      "open": [
        4991,
        22,
        443,
        3389,
        5901,
        23,
        80,
        1883,
        27017,
        6379,
        11211,
        9200,
        21,
        8080,
        25,
        3306
      ],
      "score": 16
    },
    "cve": {
      "result": [
        {
          "port": 4991,
          "cve": [
            {
              "cpe": "cpe:/a:igor_sysoev:nginx:1.2.6",
              "cve_list": [
                {
                  "cve": "CVE-2013-2070",
                  "cvss": 5.8
                },
                {
                  "cve": "CVE-2016-1247",
                  "cvss": 7.2
                },
                {
                  "cve": "CVE-2016-0747",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2016-0746",
                  "cvss": 7.5
                },
                {
                  "cve": "CVE-2016-0742",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2016-4450",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2014-3616",
                  "cvss": 4.3
                },
                {
                  "cve": "CVE-2013-4547",
                  "cvss": 7.5
                }
              ],
              "score": 47.3
            }
          ],
          "score": 47.3
        },
        {
          "port": 8080,
          "cve": [
            {
              "cpe": "cpe:/a:indy:httpd:13.2.3.2235",
              "cve_list": [],
              "score": 0
            }
          ],
          "score": 0
        },
        {
          "port": 25,
          "cve": {
            "cpe": [
              "cpe:/a:postfix:postfix"
            ],
            "cve_list": "no_version_provided",
            "score": 0
          },
          "score": 0
        },
        {
          "port": 3306,
          "cve": [
            {
              "cpe": "cpe:/a:mysql:mysql:5.5.47-mariadb",
              "cve_list": [
                {
                  "cve": "CVE-2017-3302",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2016-6662",
                  "cvss": 10
                },
                {
                  "cve": "CVE-2016-6663",
                  "cvss": 4.4
                },
                {
                  "cve": "CVE-2016-6664",
                  "cvss": 6.9
                },
                {
                  "cve": "CVE-2016-0610",
                  "cvss": 3.5
                },
                {
                  "cve": "CVE-2015-3152",
                  "cvss": 4.3
                },
                {
                  "cve": "CVE-2016-7412",
                  "cvss": 6.8
                },
                {
                  "cve": "CVE-2012-0496",
                  "cvss": 4.3
                },
                {
                  "cve": "CVE-2012-0495",
                  "cvss": 4
                },
                {
                  "cve": "CVE-2012-0494",
                  "cvss": 1.7
                },
                {
                  "cve": "CVE-2012-0493",
                  "cvss": 2.1
                },
                {
                  "cve": "CVE-2012-0491",
                  "cvss": 4
                },
                {
                  "cve": "CVE-2012-0489",
                  "cvss": 4
                },
                {
                  "cve": "CVE-2012-0488",
                  "cvss": 4
                },
                {
                  "cve": "CVE-2012-0487",
                  "cvss": 4
                },
                {
                  "cve": "CVE-2012-0486",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2012-0117",
                  "cvss": 3.5
                },
                {
                  "cve": "CVE-2005-0684",
                  "cvss": 10
                },
                {
                  "cve": "CVE-2005-0082",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2005-0081",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2004-0931",
                  "cvss": 5
                },
                {
                  "cve": "CVE-2009-4833",
                  "cvss": 5.8
                },
                {
                  "cve": "CVE-2005-1274",
                  "cvss": 10
                }
              ],
              "score": 118.3
            }
          ],
          "score": 118.3
        }
      ],
      "score": 165.6
    },
    "ssh": {
      "result": [
        {
          "port": 22,
          "algorithms": {
            "mac": {
              "mac": [
                "hmac-sha1-96",
                "hmac-sha1",
                "hmac-md5"
              ],
              "score": [
                2,
                2,
                2
              ]
            },
            "kex": {
              "kex": [
                "diffie-hellman-group1-sha1"
              ],
              "score": [
                2
              ]
            },
            "encryption": {
              "encryption": [
                "aes128-cbc",
                "3des-cbc",
                "aes256-cbc"
              ],
              "score": [
                0,
                2,
                0
              ]
            }
          },
          "key_length": {
            "key_length": [
              1024
            ],
            "key_score": [
              2
            ]
          },
          "debian_key": {
            "debian_key": [
              true
            ],
            "key_score": [
              8
            ]
          },
          "score": 20
        }
      ],
      "score": 20
    },
    "rms": {
      "result": [
        {
          "port": 3389,
          "rms": "rdp",
          "score": 8
        },
        {
          "port": 5901,
          "rms": "vnc",
          "score": 10
        },
        {
          "port": 23,
          "rms": "telnet",
          "score": 8
        }
      ],
      "score": 26
    },
    "ssl": {
      "result": [
        {
          "port": 443,
          "heartbleed": {
            "heartbleed": true,
            "score": 10
          },
          "ccs": {
            "ccs": true,
            "score": 6
          },
          "scsv": {
            "scsv": true,
            "score": 6
          },
          "compression": {
            "compression": true,
            "score": 6
          },
          "renegotiation": {
            "renegotiation": true,
            "score": 6
          },
          "oscp": {
            "oscp": true,
            "score": 3
          },
          "certificates_date": [
            {
              "date": "2016-07-14 09:48:15",
              "status": "expired",
              "score": 4
            }
          ],
          "self_signed": {
            "self_signed": "single-certificate",
            "score": 5
          },
          "signatures": [
            {
              "signature": "sha1WithRSAEncryption",
              "score": 5
            }
          ],
          "ciphers": [
            {
              "drown": true,
              "score": 6
            },
            {
              "poodle": true,
              "score": 6
            }
          ],
          "score": 63
        }
      ],
      "score": 63
    },
    "wec": {
      "result": [
        {
          "port": 25,
          "service": "smtp",
          "score": 6
        }
      ],
      "score": 6
    },
    "ftp": {
      "result": [
        {
          "port": 21,
          "service": "ftp",
          "score": 6
        }
      ],
      "score": 6
    },
    "http": {
      "result": [
        {
          "port": 4991,
          "service": "http",
          "score": 6
        },
        {
          "port": 8080,
          "service": "http",
          "score": 6
        }
      ],
      "score": 12
    },
    "storage": {
      "result": [
        {
          "port": 1883,
          "module": "mqtt",
          "connected": true,
          "score": 10
        },
        {
          "port": 27017,
          "module": "mongodb",
          "total_size": 1097728,
          "score": 10
        },
        {
          "port": 6379,
          "module": "redis",
          "used_memory": 1287840,
          "score": 10
        },
        {
          "port": 11211,
          "module": "memcached",
          "bytes": 58664843,
          "score": 10
        },
        {
          "port": 9200,
          "module": "elasticsearch",
          "contains_node_names": true,
          "score": 10
        }
      ],
      "score": 50
    },
    "web": {
      "result": [
        {
          "port": 80,
          "headers_missing": true,
          "score": 3
        }
      ],
      "score": 3
    },
    "torrents": {
      "result": [
        {
          "torrents": false,
          "score": 0
        }
      ],
      "score": 0
    }
  },
  "ip_address": "127.xxx.xxx.xxx"
}
```
