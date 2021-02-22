package com.github.thomasdarimont.keycloak.auth.requiregroup;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.authentication.AuthenticationFlowError;

import javax.ws.rs.core.Response;

/**
 * Simple {@link Authenticator} that checks of a user is member of a given {@link GroupModel Group}.
 */
public class RequireGroupAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(RequireGroupAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {

	ClientModel client = context.getAuthenticationSession().getClient();
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        String groupPath = configModel.getConfig().get(RequireGroupAuthenticatorFactory.GROUP);
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        if (!isMemberOfGroup(realm, user, groupPath)) {

            LOG.debugf("Access denied because of missing group membership. realm=%s username=%s groupPath=%s", realm.getName(), user.getUsername(), groupPath);
	
            context.getEvent().user(user);
            context.getEvent().error(Errors.NOT_ALLOWED);

            // TODO make fallback client configurable
            // ClientModel fallbackClientForBacklink = realm.getClientByClientId("account");

            LoginFormsProvider loginFormsProvider = context.form();
            /* TODO set an attribute here to allow overriding fallback client URL.
               Note that this requires a custom error.ftl.
            */

            Response errorForm = loginFormsProvider
                .setError("Access Denied: " + client.getClientId())
                .createErrorPage(Response.Status.FORBIDDEN);

            context.forceChallenge(errorForm);
            
            return;
        }

        context.success();
    }

    private boolean isMemberOfGroup(RealmModel realm, UserModel user, String groupPath) {

        if (groupPath == null) {
            return false;
        }

        GroupModel group = KeycloakModelUtils.findGroupByPath(realm, groupPath);

        return user.isMemberOf(group);
    }


    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public void close() {
        // NOOP
    }
}
