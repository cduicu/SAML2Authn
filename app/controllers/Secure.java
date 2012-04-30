//==========================================================================
// $Id: Secure.java,v 0.1 Apr 27, 2012 12:28:26 PM cristiand Exp $
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
import play.mvc.Before;
import play.mvc.Controller;
import util.SAMLUtil;

/**
 * To ensure the request is authenticated you need to use <code>&#64;With(Secure.class)</code> in your controller.
 * Example:
 * <pre>
 * &#64;With(Secure.class)
 * public class MyClass extends Controller {
 *    ...
 * }
 * </pre>
 *
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Apr 27, 2012 $
 */
public class Secure extends Controller {

    @Before
    static void checkAuthenticated() {
        if(!session.contains("username")) {
            SecureWithSAML2.startSSO();
        }
    }

    public static void logout() {
        Logger.info("Logging out user " + session.get("username"));
        session.clear();
        Cache.clear();
        Application.index();
    }

}
