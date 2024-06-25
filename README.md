# Burgerauth

Burgerauth is a free-and-open-source OAuth2 server.

## Ok, that's great, how do I host my own instance?

First, replace the domains in the source code and templates with your own (a domain is required, not just an IP). Second, copy config.ini.example to config.ini then tweak to your liking. Third, run `go build`, and fourth, run `./burgerauth`. Read ERRORS.md to see how to handle server errors.

## What if I am a developer?

The OAuth2 protocol should be fairly standard. Burgerauth comes with OpenID Connect discovery, and you should use that to find out the URL endpoints for the instance you are targeting, and you shouldn't really touch anything else. Burgerauth provides only authorization and not resource-delegation, and so doesn't issue refresh tokens.

## How long did this take to make?

Yes.