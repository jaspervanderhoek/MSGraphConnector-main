// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package o365authentication.actions;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import o365authentication.PermissionHandler;
import com.mendix.systemwideinterfaces.core.IMendixObject;

public class Initialize extends CustomJavaAction<java.lang.Boolean>
{
	private IMendixObject __ClientConfig;
	private o365authentication.proxies.ClientConfiguration ClientConfig;

	public Initialize(IContext context, IMendixObject ClientConfig)
	{
		super(context);
		this.__ClientConfig = ClientConfig;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		this.ClientConfig = __ClientConfig == null ? null : o365authentication.proxies.ClientConfiguration.initialize(getContext(), __ClientConfig);

		// BEGIN USER CODE

		PermissionHandler._initialize();

		return true;
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "Initialize";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
