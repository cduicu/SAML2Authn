package controllers;

import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;

import play.Logger;
import play.Play;
import play.cache.Cache;
import play.i18n.Messages;
import play.mvc.Controller;
import play.mvc.With;
import play.server.Server;
import util.SAMLUtil;
import util.SendSoapMsg;

/**
 *
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Apr 11, 2012 $
 */
public class Application extends Controller {

    // this should match SP's metadata configuration
    public static final String APP_ID                 = "http://app.one.com/shibboleth";
    // choose one of the attributes from the metadata
    public static final String APP_USER_NAME          = "email";

    public static final String PRJ_HOME               = new File(".").getAbsolutePath();
    public static final String DER_FILE               = PRJ_HOME + "\\public\\onekey.der";
    public static final String PEM_FILE               = PRJ_HOME + "\\public\\certone.pem";
    public static final String XML_SAMPLES            = PRJ_HOME + "\\public\\xmlSample\\";
    public static int          PORT                   = 9000; // default Play port
    public static String       HOST                   = "torlp-cristiand";
    public static String       ASSERTION_CONSUMER_URL = "";
    static {
        try {
            HOST = InetAddress.getLocalHost().getHostName().toLowerCase();
            PORT = Server.httpPort;
            ASSERTION_CONSUMER_URL = "http://" + HOST + ":" + PORT + "/authn/SAML2/POST";
        } catch (UnknownHostException e) {
            Logger.error(e, "Failed getting host address!");
        }
    }

    public static void index() {
        Logger.info(ASSERTION_CONSUMER_URL);
        render();
    }

}