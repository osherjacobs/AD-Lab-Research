# Breaking (and Fixing) ADCSync in My Home Lab

Built an ADCS lab to test ESC1 exploitation tooling. Found [ADCSync](https://github.com/JPG0mez/ADCSync) - a Python wrapper that automates certificate abuse at scale.

It was completely broken.

## Three bugs that highlight the pitfalls of quick-and-dirty scripting:

- **Hash parsing**: hardcoded string split on wrong certipy output format
- **Domain lookups**: reused loop variable instead of dictionary key  
- **Zero error handling** when PKINIT auth fails

Fixed in 30 lines (Thanks Claude....). Now it works: bulk cert requests → PKINIT auth → NT hash extraction → domain dump.

## Then I checked the logs.

Event 4887 screams compromise:
- `lowpriv` requesting certs for Administrator, krbtgt, NT AUTHORITY  
- 19 requests in 8 minutes
- Subject mismatch (`CN=lowpriv`, `SAN=administrator@lab.local`)

Any competent SOC sees this immediately.

## Context matters

ADCSync is a 2021-era smash-and-grab tool - peak Certified Pre-Owned era stuff when nobody monitored ADCS. Still useful for understanding the attack surface, but operationally probably obsolete except maybe in really small immature orgs.

Real tradecraft: one target, spaced timing, blend with legitimate activity.

## The bigger lesson

Tools break, detections improve, techniques age out. Understanding *why* something worked matters more than running the script.

It's at times like this when you "get made" that you can really appreciate why we really might need a new hoover max extract pressure pro model 60...

<img width="628" height="606" alt="image" src="https://github.com/user-attachments/assets/c01ad561-66a6-4e68-a55c-334a9bbb8c3b" />


## Main message

Superfluous to say but if you're defending ADCS and not alerting on Event 4887 with SAN/subject mismatch — you're blind.
