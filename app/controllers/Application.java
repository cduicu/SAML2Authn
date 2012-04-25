package controllers;

import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;

import play.Logger;
import play.cache.Cache;
import play.i18n.Messages;
import play.mvc.Controller;
import util.SAMLUtil;
import util.SendSoapMsg;

/**
 *
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Apr 11, 2012 $
 */
public class Application extends Controller {

    public static final String  HOST                   = "10.0.150.96";
    public static final String  PORT                   = "9000";
    public static final String  APP_ID                 = "http://app.one.com/shibboleth";
    private static final String APP_USER_NAME          = "email";
    public static final String  PRJ_HOME               = "C:\\home\\sso1";
    public static final String  DER_FILE               = PRJ_HOME + "\\public\\onekey.der";
    public static final String  PEM_FILE               = PRJ_HOME + "\\public\\certone.pem";

    public static final String  XML_SAMPLES            = PRJ_HOME + "\\public\\xmlSample\\";
    private static final String ASSERTION_CONSUMER_URL = "http://" + HOST + ":" + PORT + "/authn/SAML2/POST";

    public static void index() {
        render();
    }

    public static void myResource() {
        if (session.get("username") == null) {
            startSSO();
        }
        render();
    }

    public static void startSSO() {
        // issuerURL must match the entityID from the SP's metadata description
        String issuerUrl = APP_ID;
        // assertionConsumerServiceUrl must match the <AssertionConsumerService>
        String assertionConsumerServiceUrl = ASSERTION_CONSUMER_URL;
        flash.put("SAMLRequest", SAMLUtil.getInstance().buildAuthnRequest(issuerUrl, assertionConsumerServiceUrl));
        flash.put("RelayState", "/application/myResource");

        render();
    }

    public static void authnResponse() {
        SAMLUtil util = SAMLUtil.getInstance();
        String samlResponse = request.params.get("SAMLResponse");
        String relayState = request.params.get("RelayState");
        Response resp = util.decodeSAMLResponse(samlResponse);
        List<Assertion> assertions = util.decodeAssertions(resp);
        Subject subject = null;
        if (assertions.size() != 1) {
            Logger.warn("FAILURE! Expected 1 assertion back; received: " + assertions.size());
            index();
            return;
        }
        // I expect only one assertion here actually
        Assertion a = assertions.get(0);
        subject = a.getSubject();
        if (subject == null) {
            Logger.warn("FAILURE! Subject is not present in assertion!");
            index();
            return;
        }

        if (!util.processConditions(a.getConditions())) {
            Logger.warn("FAILURE! User does not match IdP conditions!");
            index();
            return;
        }

        String username = subject.getNameID().getValue();
        Logger.info("User " + username + " successfully authenticated by IdP!");

        String myAppUsername = APP_USER_NAME;
        Map<String, String> attrs = util.getAttributeValue(resp, username, myAppUsername);

        String myUsrName = attrs.get(myAppUsername);
        if (myUsrName == null) {
            Logger.warn("FAILURE! Could not find value for attribute" + myAppUsername + "!");
            index();
            return;
        }
        Logger.info("Logging in " + myUsrName + "...");
        // TODO: here you do the actual application login
        Logger.info("User " + myUsrName + " successfully logged in!");
        session.put("username", myUsrName);
        Cache.set("attributes", attrs);
        // redirect to relaystate
        redirect(relayState);
    }

    public static void logout() {
        Logger.info("Logging out user" + session.get("username"));
        session.clear();
        Cache.clear();
        index();
    }

}