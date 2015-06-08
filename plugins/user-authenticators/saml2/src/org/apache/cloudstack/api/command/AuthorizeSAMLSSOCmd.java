package org.apache.cloudstack.api.command;

import com.cloud.user.Account;
import com.cloud.user.User;
import org.apache.cloudstack.api.APICommand;
import org.apache.cloudstack.api.ApiConstants;
import org.apache.cloudstack.api.BaseCmd;
import org.apache.cloudstack.api.Parameter;
import org.apache.cloudstack.api.response.IdpResponse;
import org.apache.cloudstack.api.response.SuccessResponse;
import org.apache.cloudstack.api.response.UserResponse;
import org.apache.cloudstack.context.CallContext;
import org.apache.cloudstack.saml.SAML2AuthManager;
import org.apache.log4j.Logger;

import javax.inject.Inject;

@APICommand(name = "authorizeSamlSso", description = "Allow or disallow a user to use SAML SSO", responseObject = SuccessResponse.class, requestHasSensitiveInfo = true, responseHasSensitiveInfo = true)
public class AuthorizeSAMLSSOCmd extends BaseCmd {
    public static final Logger s_logger = Logger.getLogger(AuthorizeSAMLSSOCmd.class.getName());

    private static final String s_name = "authorizesamlssoresponse";

    @Inject
    SAML2AuthManager _samlAuthManager;

    /////////////////////////////////////////////////////
    //////////////// API parameters /////////////////////
    /////////////////////////////////////////////////////

    @Parameter(name = ApiConstants.ID, type = CommandType.UUID, entityType = UserResponse.class, required = true, description = "User uuid")
    private Long id;

    @Parameter(name = ApiConstants.ENABLE, type = CommandType.BOOLEAN, required = true, description = "If true, authorizes user to be able to use SAML for Single Sign. If False, disable user to user SAML SSO.")
    private Boolean enable;

    public Boolean getEnable() {
        return enable;
    }

    public String getEntityId() {
        return entityId;
    }

    @Parameter(name = ApiConstants.ENTITY_ID, type = CommandType.STRING, entityType = IdpResponse.class, description = "The Identity Provider ID the user is allowed to get single signed on from")
    private String entityId;

    public Long getId() {
        return id;
    }

    @Override
    public String getCommandName() {
        return s_name;
    }

    @Override
    public long getEntityOwnerId() {
        User user = _entityMgr.findById(User.class, getId());
        if (user != null) {
            return user.getAccountId();
        }

        return Account.ACCOUNT_ID_SYSTEM;
    }

    @Override
    public void execute() {
        CallContext.current().setEventDetails("UserId: " + getId());
        SuccessResponse response = new SuccessResponse();
        Boolean status = false;
        if (_samlAuthManager.authorizeUser(getId(), getEntityId(), getEnable())) {
            status = true;
        }
        response.setResponseName(getCommandName());
        response.setSuccess(status);
        setResponseObject(response);
    }
}