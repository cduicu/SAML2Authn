//==========================================================================
// $Id: SAMLUtil.java,v 0.1 Apr 11, 2012 1:37:26 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.PostMethod;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.core.impl.AttributeQueryBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.transport.OutputStreamOutTransportAdapter;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptedKeyResolver;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import controllers.Application;

import play.Logger;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Apr 11, 2012 $
 */
public class SAMLUtil {

    private static SAMLUtil instance;
    private ParserPool parserPool;
    private XMLObjectBuilderFactory builderFactory;
    private MarshallerFactory marshallerFactory;
    private UnmarshallerFactory unmarshallerFactory;
    public static final String SOAP_URL =
            "http://torvm-core12.sigmasys.net:8080/idp/profile/SAML2/SOAP/AttributeQuery";

    private SAMLUtil() {
    }

    public static final SAMLUtil getInstance() {
        if (instance == null) {
            synchronized (SAMLUtil.class) {
                instance = new SAMLUtil();
                try {
                    instance.init();
                } catch (ConfigurationException e) {
                    Logger.error(e, "Can't initialize openSAML!");
                }
            }
        }
        return instance;
    }

    private void init() throws ConfigurationException {
        DefaultBootstrap.bootstrap();
        parserPool = new BasicParserPool();
        builderFactory = Configuration.getBuilderFactory();
        marshallerFactory = Configuration.getMarshallerFactory();
        unmarshallerFactory = Configuration.getUnmarshallerFactory();
    }

    public String buildAuthnRequest(String issuerUrl, String assertionConsumerServiceUrl) {
        SAMLObjectBuilder authnRequestBuilder = (SAMLObjectBuilder) builderFactory
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        // Create an issuer Object
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");
        issuer.setValue(issuerUrl);

        // Create NameIDPolicy
        NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        // nameIdPolicy.setSchemaLocation("urn:oasis:names:tc:SAML:2.0:protocol");
        nameIdPolicy.setFormat(NameID.PERSISTENT);
        nameIdPolicy.setSPNameQualifier(issuerUrl);
        nameIdPolicy.setAllowCreate(true);

        // Create AuthnContextClassRef
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(
                "urn:oasis:names:tc:SAML:2.0:assertion", "AuthnContextClassRef", "saml");
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);

        // Create RequestedAuthnContext
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        DateTime issueInstant = new DateTime();
        // AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        // AuthnRequest authRequest =
        // authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
        // "AuthnRequest", "samlp");
        AuthnRequest authRequest = (AuthnRequest) authnRequestBuilder.buildObject();
        authRequest.setForceAuthn(false);
        authRequest.setIsPassive(false);
        authRequest.setIssueInstant(issueInstant);
        authRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authRequest.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
        authRequest.setIssuer(issuer);
        authRequest.setNameIDPolicy(nameIdPolicy);
        authRequest.setRequestedAuthnContext(requestedAuthnContext);
        authRequest.setID(java.util.UUID.randomUUID().toString());
        authRequest.setVersion(SAMLVersion.VERSION_20);

        // Now we must build our representation to put into the html form to be submitted to the idp
        Marshaller marshaller = marshallerFactory.getMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);
        org.w3c.dom.Element authDOM = null;
        try {
            authDOM = marshaller.marshall(authRequest);
        } catch (MarshallingException e) {
            Logger.info(e, "Failed marshalling the xml");
            return null;
        }
        StringWriter rspWrt = new StringWriter();
        XMLHelper.writeNode(authDOM, rspWrt);
        String messageXML = rspWrt.toString();
        saveToFile("AuthnRequest.xml", messageXML);
        return Base64.encodeBytes(messageXML.getBytes());
    }

    public List<Assertion> decodeAssertions(Response resp) {
        ArrayList<Assertion> assertions = new ArrayList<Assertion>();
        try {
            Logger.info("AuthnResponse Assertions=" + resp.getAssertions().size() + "; EncryptedAssertions="
                    + resp.getEncryptedAssertions().size());
            for (Assertion assertion : resp.getAssertions()) {
                assertions.add(assertion);
            }
            int i = 0;
            for (EncryptedAssertion encryptedAssertion : resp.getEncryptedAssertions()) {
                Assertion assertion = decodeAssertion(encryptedAssertion);
                assertions.add(assertion);
                saveToFile("DecodedAuthnAssertion" + i++ + ".xml", assertion);
            }
        } catch (Exception e) {
            Logger.info(e, "failed decoding SAMLResponse");
        }
        return assertions;
    }

    public Response decodeSAMLResponse(String samlResponse) {
        try {
            byte[] decodedBytes = Base64.decode(samlResponse);
            ByteArrayInputStream bytesIn = new ByteArrayInputStream(decodedBytes);
            //InflaterInputStream inflater = new InflaterInputStream(bytesIn, new Inflater());
            saveToFile("AuthnResponse.xml", decodedBytes);
            Document messageDoc = parserPool.parse(bytesIn);
            Element messageElem = messageDoc.getDocumentElement();
            //Logger.info("DOM was:\n{}", XMLHelper.nodeToString(messageElem));
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(messageElem);
            if (unmarshaller == null) {
                Logger.info("Unable to unmarshall message, no unmarshaller registered for message element "
                        + XMLHelper.getNodeQName(messageElem));
            }
            Response resp = (Response) unmarshaller.unmarshall(messageElem);
            Logger.info("AuthnResponse StatusCode:" + resp.getStatus().getStatusCode().getValue());
            return resp;
        } catch (Exception e) {
            Logger.info(e, "failed decoding SAMLResponse");
        }
        return null;
    }

    public Assertion decodeAssertion(EncryptedAssertion encryptedAssertion) {
        try {
            Credential decryptionCredential = getCredential();
            StaticKeyInfoCredentialResolver skicr = new StaticKeyInfoCredentialResolver(decryptionCredential);
            Decrypter samlDecrypter = new Decrypter(null, skicr, new InlineEncryptedKeyResolver());
            return samlDecrypter.decrypt(encryptedAssertion);
        } catch (Exception e) {
            Logger.info(e, "failed decrypting assertion!");
        }
        return null;
    }

    private Credential getCredential() {
        BasicX509Credential credential = null;
        try {
            // read private key
            File privateKeyFile = new File(Application.DER_FILE);
            FileInputStream inputStreamPrivateKey = new FileInputStream(privateKeyFile);
            byte[] encodedPrivateKey = new byte[(int) privateKeyFile.length()];
            inputStreamPrivateKey.read(encodedPrivateKey);
            inputStreamPrivateKey.close();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
            // read the certificate
            InputStream inStream = new FileInputStream(Application.PEM_FILE);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
            // create credential
            credential = new BasicX509Credential();
            credential.setEntityCertificate(cert);
            credential.setPrivateKey(privateKey);
        } catch (Exception e) {
            Logger.info(e, "failed getting credential!");
        }
        return credential;
    }

    public static String readInputStreamAsString(InputStream in) throws IOException {
        BufferedInputStream bis = new BufferedInputStream(in);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int result = bis.read();
        while (result != -1) {
            byte b = (byte) result;
            buf.write(b);
            result = bis.read();
        }
        return buf.toString();
    }

    public static String getXMLAsString(XMLObject obj) {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(obj);
        StringWriter rspWrt = new StringWriter();
        try {
            org.w3c.dom.Element domEl = marshaller.marshall(obj);
            XMLHelper.writeNode(domEl, rspWrt);
        } catch (MarshallingException e) {
            Logger.info(e, "Failed marshalling the XMLObject!");
        }
        return rspWrt.toString();
    }

    public AttributeQuery buildAttributeQuery(String name) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(NameID.ENTITY);
        issuer.setValue(Application.APP_ID);

        SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(name);

        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);

        SAMLObjectBuilder<AttributeQuery> attributeQueryBuilder = (SAMLObjectBuilder<AttributeQuery>) builderFactory
                .getBuilder(AttributeQuery.DEFAULT_ELEMENT_NAME);
        AttributeQuery query = attributeQueryBuilder.buildObject();
        query.setID(java.util.UUID.randomUUID().toString());
        query.setIssueInstant(new DateTime());
        query.setIssuer(issuer);
        query.setSubject(subject);
        query.setVersion(SAMLVersion.VERSION_20);

        // Apparently I should not request specific attributes ... ???
//        AttributeBuilder attrBuilder = new AttributeBuilder();
//        Attribute attr = attrBuilder.buildObject();
//        attr.setFriendlyName("uid");
//        attr.setNameFormat(NameID.TRANSIENT);
//        query.getAttributes().add(attr);
//
//        attr = attrBuilder.buildObject();
//        attr.setFriendlyName("homePhone");
//        attr.setNameFormat(NameID.TRANSIENT);
//        query.getAttributes().add(attr);
//
//        attr = attrBuilder.buildObject();
//        attr.setFriendlyName("email");
//        attr.setNameFormat(NameID.PERSISTENT);
//        query.getAttributes().add(attr);

        return query;
    }

    public String getSOAPMessage(AttributeQuery query) throws MarshallingException {
        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
                .getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(query);

        SOAPObjectBuilder<Envelope> envelopeBuilder = (SOAPObjectBuilder<Envelope>) builderFactory
                .getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envelopeBuilder.buildObject();
        envelope.setBody(body);

        Marshaller marshaller = marshallerFactory.getMarshaller(envelope);
        Element envelopeElem = marshaller.marshall(envelope);

        StringWriter writer = new StringWriter();
        XMLHelper.writeNode(envelopeElem, writer);
        return writer.toString();
    }

    public Response attributeQuery(String nameId) {
        try {
            AttributeQuery query = buildAttributeQuery(nameId);
            signRequest(query);
            String soapRequest = getSOAPMessage(query);
            saveToFile("AttrQueryRequest.xml", soapRequest);
            SendSoapMsg sender = new SendSoapMsg(SOAP_URL);
            String soapResponse = sender.sendMsg(soapRequest);
            saveToFile("AttrQueryResponse.xml", soapResponse);

            ByteArrayInputStream bytes = new ByteArrayInputStream(soapResponse.getBytes());
            Document messageDoc = parserPool.parse(bytes);
            Element messageElem = messageDoc.getDocumentElement();

            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(messageElem);
            Envelope envelope = (Envelope) unmarshaller.unmarshall(messageElem);
            Response resp = (Response) envelope.getBody().getOrderedChildren().get(0);
            return resp;
        } catch (Exception e) {
            Logger.info(e, "Failed retrieving attributes!");
        }
        return null;
    }

    public List<Attribute> getAttributesFromAssertions(List<Assertion> assertions) {
        ArrayList<Attribute> attrs = new ArrayList<Attribute>();
        for (Assertion assertion : assertions) {
            attrs.addAll(getAttributesFromAssertion(assertion));
        }
        return attrs;
    }

    public List<Attribute> getAttributesFromAssertion(Assertion assertion) {
        ArrayList<Attribute> attrs = new ArrayList<Attribute>();
        for (AttributeStatement stmt : assertion.getAttributeStatements()) {
            attrs.addAll(stmt.getAttributes());
        }
        return attrs;
    }

    private void saveToFile(String fileNm, String fileContent) {
        saveToFile(fileNm, fileContent.getBytes());
    }

    private void saveToFile(String fileNm, byte[] fileContent) {
        try {
            File f = new File(Application.XML_SAMPLES + fileNm);
            if (f.exists()) {
                f.delete();
            }
            f.createNewFile();
            FileOutputStream fi = new FileOutputStream(f);
            fi.write(fileContent);
            fi.flush();
            fi.close();
        } catch (Exception e) {
            Logger.info(e, "Can't save to file");
        }
    }

    private void saveToFile(String fileNm, XMLObject obj) {
        Marshaller marshaller = marshallerFactory.getMarshaller(obj);
        org.w3c.dom.Element authDOM = null;
        try {
            authDOM = marshaller.marshall(obj);
        } catch (MarshallingException e) {
            Logger.info(e, "Failed marshalling the xml");
            return;
        }
        StringWriter rspWrt = new StringWriter();
        XMLHelper.writeNode(authDOM, rspWrt);
        String messageXML = rspWrt.toString();
        saveToFile(fileNm, messageXML.getBytes());
    }

    private void signRequest(SignableXMLObject obj) {
        Credential credential = getCredential();
        Signature signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);

        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        try {
            SecurityHelper.prepareSignatureParams(signature, credential, secConfig, null);
            obj.setSignature(signature);
            Configuration.getMarshallerFactory().getMarshaller(obj).marshall(obj);
            Signer.signObject(signature);
        } catch (Exception e) {
            Logger.info(e, "Can't prepare signature");
        }
    }

    public void logAttributes(List<Attribute> attrs) {
        for(Attribute attr : attrs) {
            String s ="Attribute name=" + attr.getName() +
                    "; friendlyName=" + attr.getFriendlyName() +
                    "; nameFormat=" + attr.getNameFormat() +
                    "; values=" + attr.getAttributeValues().size() + " [";
            for (XMLObject val : attr.getAttributeValues()) {
                s += "{qname:" + val.getElementQName() + ", qVal:" + val.getDOM().getNodeValue() + "}";
            }
            s += "]";
            Logger.info(s);
        }
    }

    public boolean processConditions(Conditions conditions) {
        // TODO
        return true;
    }

    public Map<String, String> getAttributeValue(Response authnResp, String nameId, String attrName) {
        HashMap<String, String> attributes = new HashMap<String, String>();
        ArrayList<Attribute> attrs = new ArrayList<Attribute>();

        attrs.addAll(getAttributesFromAssertions(authnResp.getAssertions()));
        int i = 0;
        for (EncryptedAssertion encryptedAssertion : authnResp.getEncryptedAssertions()) {
            Assertion assertion = decodeAssertion(encryptedAssertion);
            saveToFile("DecodedAttrQueryAssertion" + i++ + ".xml", assertion);
            attrs.addAll(getAttributesFromAssertion(assertion));
        }
        Logger.info("Found " + attrs.size() + " attributes in the AuthnResponse");

        for (Attribute attr : attrs) {
            attributes.put(attr.getFriendlyName(), attr.getAttributeValues().get(0).getDOM().getTextContent());
        }
        if (attributes.containsKey(attrName)) {
            return attributes;
        }

        Logger.info("Attribute not found in AuthnResponse, make an AttributeQuery ...");
        Response resp = attributeQuery(nameId);
        String statusCode = resp.getStatus().getStatusCode().getValue();
        Logger.info("AttrQuery StatusCode:" + statusCode);
        if (!statusCode.equals(StatusCode.SUCCESS_URI)) {
            String statusMsg = resp.getStatus().getStatusMessage().getMessage();
            Logger.info("AttrQuery FAILED! " + statusMsg);
        } else {
            Logger.info("AttrQuery Assertions=" + resp.getAssertions().size() + "; EncryptedAssertions="
                    + resp.getEncryptedAssertions().size());
            attrs.addAll(getAttributesFromAssertions(resp.getAssertions()));
            for (EncryptedAssertion encryptedAssertion : resp.getEncryptedAssertions()) {
                Assertion assertion = decodeAssertion(encryptedAssertion);
                attrs.addAll(getAttributesFromAssertion(assertion));
            }
            Logger.info("Received " + attrs.size() + " attributes from AttributeQuery response");
        }

        for (Attribute attr : attrs) {
            attributes.put(attr.getFriendlyName(), attr.getAttributeValues().get(0).getDOM().getTextContent());
        }
        return attributes;
    }

//  private Credential getCredential(String fileName, String password, String certificateAliasName) {
//  try {
//      KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//      FileInputStream fis = new FileInputStream(fileName);
//      ks.load(fis, password.toCharArray());
//      fis.close();
//      KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(
//              certificateAliasName, new KeyStore.PasswordProtection(password.toCharArray()));
//      PrivateKey pk = pkEntry.getPrivateKey();
//      X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
//      BasicX509Credential credential = new BasicX509Credential();
//      credential.setEntityCertificate(certificate);
//      credential.setPrivateKey(pk);
//      return credential;
//  } catch (Exception e) {
//      Logger.info(e, "Failed getting the credential from KeyStore: " + fileName);
//  }
//  return null;
//}

    public static void main(String[] args) {
        SAMLUtil u = SAMLUtil.getInstance();
    }

}
