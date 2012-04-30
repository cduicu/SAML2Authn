//==========================================================================
// $Id: AppController.java,v 0.1 Apr 27, 2012 12:50:39 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package controllers;

import play.mvc.Controller;
import play.mvc.With;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Apr 27, 2012 $
 */
@With(Secure.class)
public class AppController extends Controller {

    public static void myResource() {
      render();
  }

}
