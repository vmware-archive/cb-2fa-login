# Example Flask based IdP for Carbon Black

This implements just enough of a SAML Identity Provider (IdP) to provide authentication services for Carbon Black.
This sample includes support for Duo Security 2FA and Google Authenticator.

## Requirements

Since this is a Proof-of-Concept, you have to piece this together a bit.

System Requirements:
* CentOS/RHEL 7.x
* The yum packages in yum-requirements.txt:
  * libffi-devel
  * openssl-devel
  * xmlsec1-devel

Install virtualenvwrapper of your choice, and then `pip install -r requirements.txt`.
You also have to install `cbapi` so clone that and install it as well.

## Setup/Configuration

* Set up keys _(TBD)_ that are unique to your IdP
* Set up Duo security API tokens _(TBD)_

Then you want to generate the IdP XML definition file:

`make_metadata.py idp_conf`

