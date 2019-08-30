package com.qcmoke.service;

import com.qcmoke.entity.Role;
import com.qcmoke.entity.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SysUserDetailsService implements UserDetailsService {

    private static final List<User> userList = new ArrayList<>();

    /**
     * 假设为数据库数据
     */
    static {
        Role user = new Role(1L, "ROLE_user", "ROLE_user");
        Role admin = new Role(2L, "ROLE_admin", "ROLE_admin");

        List<Role> adminRoles = new ArrayList<>();
        adminRoles.add(admin);
        userList.add(new User("admin", "123", adminRoles));
        List<Role> sangRoles = new ArrayList<>();
        sangRoles.add(user);
        userList.add(new User("sang", "456", sangRoles));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findUserbyUserName(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return user;
    }


    private User findUserbyUserName(String username) {
        for (User user : userList) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }
}
