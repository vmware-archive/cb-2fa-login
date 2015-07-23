# Example Flask based IdP for Carbon Black

This implements just enough of a SAML Identity Provider (IdP) to provide authentication services for Carbon Black.
This sample includes support for Duo Security 2FA.

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

### IdP
1. Clone this repository
2. Set up keys that are unique for your IdP: `./makekeys.sh`
3. Fill out the `secrets/secrets.ini` file:
   * Copy `secrets/secrets.ini.example` to `secrets/secrets.ini`
   * Generate a secret key for Flask - this should be a randomly generated string
   * Grab your API keys from your Duo Security admin portal
4. Edit the `idp_conf.py` file and change the BASE_URL section at the top of the file to match settings for your server
4. Initialize the idp database: `./run.py --init`
5. Run the server: `./run.py -v`

### Carbon Black

Now that the IdP is set up, you have to configure Carbon Black to talk to the IdP.
First, you will want to transfer the SAML metadata between the Cb servers and this IdP.
The metadata for the IdP is available at the path `/idp.xml` on your running server. You can `curl -O` that file
directly into `/etc/cb/sso` on your target Cb server.

Edit the `/etc/cb/sso/sso.conf` file and fill out the requisite sections. Important to change: `login_ui_sso_label`, 
`entityid`, `metadata`, `accepted_time_diff`, and the entire `idp` section. A sample `idp` section is below.

```
    "service": {
      "sp": {
        "idp": {
          # EntityId of the IDP
          "https://your-idp-server/idp.xml": {

            # URLs in this section MUST be updated to match the URLs defined by the
            # IdP you are integrating with
            "single_sign_on_service": {
              "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect": "http://your-idp-server/sso"
            },

            "single_logout_service": {
              "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect": "http://your-idp-server/logout"
            }
          }
        },

        # Set this flag to 'true' in order to allow IdP-initiated logins. Otherwise,
        # logins will only be allowed to be initiated from CB Server's Login form.
        "allow_unsolicited": true,

        # This section defines local end points exposed by the Carbon Black Enterprise
        # Server in its role as a SAML Service Provider. DO NOT modify the path portion
        # of the URL as those are the paths CB server will expect.
        #
        # TODO: IP address portions MUST be updated to reflect actual, public-facing
        # IP address(es) of the CB server.  Multiple entries can be specified within
        # xxx_service values if the machine is multi-homed (i.e. has multiple IP
        # addresses)
        "endpoints": {
          "assertion_consumer_service": {
              "https://your-cb-server/api/saml/assertion": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            }
        },

        "name": "Carbon Black Enterprise Server",

        "required_attributes": [
          "uid"
        ]
      }
    },
```

Enable SAML in `/etc/cb/cb.conf`:

```
SSOConfig=/etc/cb/sso/sso.conf
```

Restart cb-coreservices:

`service cb-coreservices restart`

You should now see a link to log in via your new SAML IdP on the logon page!
