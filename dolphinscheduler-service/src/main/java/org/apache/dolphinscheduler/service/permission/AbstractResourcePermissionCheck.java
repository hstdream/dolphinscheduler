package org.apache.dolphinscheduler.service.permission;

import org.apache.dolphinscheduler.common.enums.AuthorizationType;
import org.apache.dolphinscheduler.common.enums.UserType;
import org.apache.dolphinscheduler.dao.entity.User;
import org.apache.dolphinscheduler.service.process.ProcessService;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

/**
 * AbstractResourcePermissionCheck
 */
public abstract class AbstractResourcePermissionCheck implements ResourcePermissionCheckService<Object> {

    @Autowired
    private ProcessService processService;

    @Override
    public boolean resourcePermissionCheck(AuthorizationType authorizationType, Object[] needChecks, int userId, Logger logger) {
        return false;
    }

    @Override
    public <T> Set<T> userOwnedResourceIdsAcquisition(AuthorizationType authorizationType, int userId, Logger logger) {
        return null;
    }

    @Override
    public boolean operationPermissionCheck(AuthorizationType authorizationType, int userId, String sourceUrl, Logger logger) {
        return false;
    }

    protected Boolean operationPermissionCommonCheck(int userId, Logger logger){
        User user = processService.getUserById(userId);
        if (user == null){
            logger.error("user id {} doesn't exist", userId);
            return Boolean.FALSE;
        }
        return user.getUserType().equals(UserType.ADMIN_USER);
    }

}
