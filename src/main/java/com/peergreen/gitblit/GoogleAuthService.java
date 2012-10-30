package com.peergreen.gitblit;

import com.gitblit.GitBlit;
import com.gitblit.GitblitUserService;
import com.gitblit.IStoredSettings;
import com.gitblit.IUserService;
import com.gitblit.LdapUserService;
import com.gitblit.models.UserModel;
import com.gitblit.utils.ArrayUtils;
import com.gitblit.utils.StringUtils;
import com.google.gdata.client.GoogleService;
import com.google.gdata.client.calendar.CalendarService;
import com.google.gdata.util.AuthenticationException;
import java.io.File;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GoogleAuthService extends GitblitUserService implements IUserService {
    public static final Logger logger = LoggerFactory.getLogger(LdapUserService.class);

    public void setup(IStoredSettings settings) {
        String file = settings.getString("realm.ldap.backingUserService", "users.conf");
        File realmFile = GitBlit.getFileOrFolder(file);

        this.serviceImpl = createUserService(realmFile);
        logger.info("Google AUTH User Service backed by " + this.serviceImpl.toString());
    }

    public boolean supportsCredentialChanges() {
        return false;
    }

    public boolean supportsDisplayNameChanges() {
        return false;
    }

    public boolean supportsEmailAddressChanges() {
        return false;
    }

    public boolean supportsTeamMembershipChanges() {
        return false;
    }

    protected String getPeergreenUsername(String username) {
        int lastArobase = username.lastIndexOf('@');
        if (lastArobase != -1) {
            return username;
        }

        return username.concat("@peergreen.com");
    }

    protected String getSimpleUsername(String username) {
        int lastArobase = username.lastIndexOf('@');
        if (lastArobase != -1) {
            return username.substring(0, lastArobase);
        }

        return username;
    }

    public UserModel authenticate(String username, char[] password) {

        UserModel user = null;

        // For jenkins ?
        if ("jenkins".equals(username) && "jenkinspass".equals(new String(password))) {
            user = getUserModel("jenkins");
            if (user == null) {
                user = new UserModel("jenkins");
            }
        } else {

            String peergreenUsername = getPeergreenUsername(username);

            if ((peergreenUsername != null) && (!peergreenUsername.endsWith("@peergreen.com"))) {
                logger.error("Trying to logged with user = " + peergreenUsername);
                return null;
            }

            GoogleService service = new CalendarService("test");
            try {
                service.setUserCredentials(peergreenUsername, new String(password));
            } catch (AuthenticationException e) {
                logger.error("Invalid login/password on google for user '" + peergreenUsername + "'", e);
                return null;
            }

            String simpleUserName = getSimpleUsername(username);

            user = getUserModel(simpleUserName);
            if (user == null) {
                user = new UserModel(simpleUserName);
            }
        }

        if ((StringUtils.isEmpty(user.cookie)) && (!ArrayUtils.isEmpty(password))) {
            user.cookie = StringUtils.getSHA1(user.username + new String(password));
        }

        super.updateUserModel(user);

        return user;
    }
}