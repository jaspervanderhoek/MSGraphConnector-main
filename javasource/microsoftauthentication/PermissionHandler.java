package microsoftauthentication;

import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.mendix.core.Core;
import com.mendix.externalinterface.connector.RequestHandler;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;

import microsoftauthentication.proxies.ClientConfiguration;

public class PermissionHandler extends RequestHandler {

	private static boolean _isInitialized = false;
	private ILogNode _logNode = Core.getLogger("AdminConsent");
	
	private PermissionHandler() {
	}
	
	@Override
	protected void processRequest(IMxRuntimeRequest request, IMxRuntimeResponse response, String path) throws Exception {
		HttpServletRequest servletRequest =  request.getHttpServletRequest();
		Core.getLogger("OauthCallback").trace("Received process request event");
		try {
			_logNode.debug("Request URI: "+ servletRequest.getRequestURI());

			String 	state = request.getParameter("state"),
					tenant = request.getParameter("tenant"), 
					admin_consent = request.getParameter("admin_consent"),
					code = request.getParameter("code"); 
//					session_state = request.getParameter("session_state");
			
			IContext context = Core.createSystemContext();
			List<IMendixObject> result = Core.retrieveXPathQuery(context, "//" + ClientConfiguration.entityName + "[" + ClientConfiguration.MemberNames.InternalId + "=" + state + "]");
			if( result.size() > 0 ) {
				IMendixObject obj = result.get(0);
				
				if( path != null && path.startsWith("consent") ) {
					obj.setValue(context, ClientConfiguration.MemberNames.HasUserConsent.toString(), true );
					obj.setValue(context, ClientConfiguration.MemberNames.AdminConsentAquiredOn.toString(), new Date() );
					obj.setValue(context, ClientConfiguration.MemberNames.AuthenticationCode.toString(), code );
					Core.commit(context, obj);
					
					microsoftauthentication.proxies.microflows.Microflows.mB_RequestTokenFromConsentCode(context, ClientConfiguration.initialize(context, obj));
					
					response.getHttpServletResponse().sendRedirect( Core.getConfiguration().getApplicationRootUrl() );
				}
				//Admin consent callback
				else if( path != null && path.startsWith("permissions") ) {
					String internalId = String.valueOf( (Long) obj.getValue(context, ClientConfiguration.MemberNames.InternalId.toString()) );					
					if( internalId.equals(state) ) {
						boolean consent = ( "true".equalsIgnoreCase(admin_consent) );
						obj.setValue(context, ClientConfiguration.MemberNames.HasAdminConsent.toString(), consent );
						if( consent )
							obj.setValue(context, ClientConfiguration.MemberNames.AdminConsentAquiredOn.toString(), new Date() );
						else
							obj.setValue(context, ClientConfiguration.MemberNames.AdminConsentAquiredOn.toString(), null );
						
						Core.commit(context, obj);
						
						response.getHttpServletResponse().sendRedirect( Core.getConfiguration().getApplicationRootUrl() );
					}
					else {
						_logNode.warn("Incorrect tenant info. [tenant " + tenant + ", state " + state + ", " + admin_consent +"]");
						response.sendError("Incorect tenant information");
					}
				}
				else {
					_logNode.warn("Unsupported url. Path: " + path );
					response.sendError("Unknown url");
				}
			}
			else {
				_logNode.warn("Unknown tenant info. [tenant " + tenant + ", state " + state + ", " + admin_consent +"]");
				response.sendError("Unknown tenant");
			}
		} catch (Exception ex) {
			_logNode.error("Exception occurred while processing request "+ex);
			response.sendError("Exception occurred while processing request");
		}
		
	}

	public static synchronized void _initialize() {
		if( !PermissionHandler._isInitialized  ) {
			Core.addRequestHandler(microsoftauthentication.proxies.constants.Constants.getRequestHandler() + "/", new PermissionHandler());
			PermissionHandler._isInitialized = true;
		}
	}
}
