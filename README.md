SAML2Authn
==========

Sample application that uses SAML2 (Web SSO Profile) to authenticate. 
I have used this to demo Web SSO by making a copy of the application and then modify some information 
like the host, port, certificate, key, metadata. 

Frameworks and 3rd Party Libraries
----------------------------------
Play! 1.2.4
Bootstrap
MySQL 5.5 Database (to store the users and their attributes)
Apache Commons
tagish JAAS
OpenSAML Stack:
- opensaml-2.5.3.jar
- openws-1.4.4.jar
- xmltooling-1.3.4.jar

Installation and Usage
----------------------
This application represents a Service Provider (SP) or Relying Party in the SAML2 Authentication process. 
To run it you need an Identity Provider. I used Shibboleth 2.3.6 for that. Note that most of the difficulties 
I encountered were related to configuration.
For simplicity I used play HTTP and did not bother with the SSL overlay, although in a production environment 
this would be required.

1. Install Shibboleth Idp. There are a number of guides for that on the internet. 
   Shibboleth IdP requires a Servlet container. In my tests I used Tomcat 6 for simplicity.
2. Configure Shibboleth Idp. (there are sample files in /setup to help with this task)
3. Install and configure users database (there is a sample SQL file in /setup/sso.sql to help this task).

Shibboleth IdP Configuration
----------------------------
In what follows, the values between "[" and "]" must be configured as per your environments.

1. Credentials.

    During installation of IdP a key and certificate for it will be generated. On the SP side you need your 
    own certificate so one must be generated. (sample key/certificate are provided in /public directory).

2. Configure JAAS authentication

    Shibboleth supports various authentication methods (LDAP being perhaps the most common). Since I wanted 
    something very simple and easy to control I opted to authenticate using a MySQL database. I used Tagish 
    JASS for this purpose. In shibboleth you need to configure conf/login-config file:
    
        com.tagish.auth.DBLogin required debug=true 
        dbDriver="com.mysql.jdbc.Driver" 
        dbURL=[your DB url] 
        dbUser=[your db user]
        dbPassword=[your db password]
        userTable="users" 
        roleMapTable="rolemap" 
        roleTable="roles";
     
3. Configure metadata in relying-party.xml
    Configure metadata providers for all applications participating in the SSO process. I used file backed provider
    because it is very simple. Here is an example
    
        <metadata:MetadataProvider id="MetadataSP1" xsi:type="FileBackedHTTPMetadataProvider" 
                        xmlns="urn:mace:shibboleth:2.0:metadata"
                        metadataURL="http://10.0.150.96:9000/public/metadataSP1.xml"
                        backingFile="[PATH_TO_IdP_DIR]/shib-idp/metadata/metadataSP1.xml" />

4. Configure attributes

    First you need to tell Shibboleth where and how to get the attributes. Edit conf/attribute-resolver.xml 
    and configure a data connector:
   
        <resolver:DataConnector id="mySIS" xsi:type="dc:RelationalDatabase">
            <dc:ApplicationManagedConnection jdbcDriver="com.mysql.jdbc.Driver"
                                             jdbcURL="[your DB url]" 
                                             jdbcUserName="[your db user]" 
                                             jdbcPassword="[your db password]" />
            <dc:QueryTemplate>
                <![CDATA[SELECT * FROM users WHERE username = '$requestContext.principalName']]>
            </dc:QueryTemplate>
            <dc:Column columnName="userid" attributeID="uid" />
            <dc:Column columnName="username" attributeID="username" />
            <dc:Column columnName="mail" attributeID="email" />
            <dc:Column columnName="homePhone" attributeID="homePhone" />
        </resolver:DataConnector>
     
    Then you need to define the attributes in the same file:

        <resolver:AttributeDefinition xsi:type="ad:Simple" id="uid" sourceAttributeID="uid">
            <resolver:Dependency ref="mySIS" />
            <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:uid" />
            <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:0.9.2342.19200300.100.1.1"
                friendlyName="uid" />
        </resolver:AttributeDefinition>
        <resolver:AttributeDefinition xsi:type="ad:Simple" id="username" sourceAttributeID="username">
            <resolver:Dependency ref="mySIS" />
            <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:mail" />
            <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:2.5.4.41" 
                friendlyName="username" />
        </resolver:AttributeDefinition>
        <resolver:AttributeDefinition xsi:type="ad:Simple" id="email" sourceAttributeID="email">
            <resolver:Dependency ref="mySIS" />
            <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:mail" />
            <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:1.2.840.113549.1.9.1" 
                friendlyName="email" /> 
        </resolver:AttributeDefinition>
        <resolver:AttributeDefinition xsi:type="ad:Simple" id="homePhone" sourceAttributeID="homePhone">
            <resolver:Dependency ref="mySIS" />
            <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:homePhone" />
            <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:0.9.2342.19200300.100.1.20" 
                friendlyName="homePhone" />
        </resolver:AttributeDefinition>
    
    Make sure the transientId attribute is persistent (it is configured as transient by default):
    
        <resolver:AttributeDefinition id="transientId" xsi:type="ad:TransientId">
            <resolver:AttributeEncoder xsi:type="enc:SAML1StringNameIdentifier" nameFormat="urn:mace:shibboleth:1.0:nameIdentifier"/>
            <resolver:AttributeEncoder xsi:type="enc:SAML2StringNameID" nameFormat="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
        </resolver:AttributeDefinition>

    Finally you need to make the attributes visible. Edit conf/attribute-filter.xml:

        <afp:AttributeFilterPolicy id="releaseTransientIdToAnyone">
            <afp:PolicyRequirementRule xsi:type="basic:ANY"/>
            <afp:AttributeRule attributeID="transientId">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
            <afp:AttributeRule attributeID="uid">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
            <afp:AttributeRule attributeID="username">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
            <afp:AttributeRule attributeID="email">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
            <afp:AttributeRule attributeID="homePhone">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
        </afp:AttributeFilterPolicy>

    
Issues and Notes
-----------------

1. Decrypting the response - need to get PKCS8 encoding of the private key. Here is how to make DER file from PEM key:

openssl pkcs8 -topk8 -in keytwo.pem -inform pem -out twokey.der -outform der -nocrypt
 
 