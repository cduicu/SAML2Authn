//==========================================================================
// $Id: SecureWithSAML2.java,v 0.1 Apr 27, 2012 12:58:53 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package controllers;

import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;

import play.Logger;
import play.cache.Cache;
import play.mvc.Controller;
import util.SAMLUtil;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Apr 27, 2012 $
 */
public class SecureWithSAML2 extends Controller {

    public static void startSSO() {
        // issuerURL must match the entityID from the SP's metadata description
        String issuerUrl = Application.APP_ID;
        // assertionConsumerServiceUrl must match the <AssertionConsumerService>
        String assertionConsumerServiceUrl = Application.ASSERTION_CONSUMER_URL;

        boolean forceAuthn = false;
        if (session.get("username") == null) {
            forceAuthn = true;
        }
        flash.put("SAMLRequest",
                SAMLUtil.getInstance().buildAuthnRequest(issuerUrl, assertionConsumerServiceUrl, forceAuthn));
        // TODO: relaystate should be from URL
        flash.put("RelayState", "/appcontroller/myResource");
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
            Application.index();
            return;
        }
        // I expect only one assertion here actually
        Assertion a = assertions.get(0);
        subject = a.getSubject();
        if (subject == null) {
            Logger.warn("FAILURE! Subject is not present in assertion!");
            Application.index();
            return;
        }

        if (!util.processConditions(a.getConditions())) {
            Logger.warn("FAILURE! User does not match IdP conditions!");
            Application.index();
            return;
        }

        String username = subject.getNameID().getValue();
        Logger.info("User " + username + " successfully authenticated by IdP!");

        String myAppUsername = Application.APP_USER_NAME;
        Map<String, String> attrs = util.getAttributeValue(resp, username, myAppUsername);

        String myUsrName = attrs.get(myAppUsername);
        if (myUsrName == null) {
            Logger.warn("FAILURE! Could not find value for attribute" + myAppUsername + "!");
            Application.index();
            return;
        }
        Logger.info("Logging in " + myUsrName + "...");
        // TODO: here you do the actual application login
        session.put("username", myUsrName);
        Cache.set("attributes", attrs);

        Logger.info("User " + myUsrName + " successfully logged in! Redirecting to " + relayState);
        redirect(relayState);
    }

}
