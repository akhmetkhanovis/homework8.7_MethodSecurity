package com.example;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@RestController
public class Controller {

    @GetMapping("hello-read")
    @Secured("ROLE_READ")
    public String helloRead() {
        return "Hello, User with role READ!";
    }

    @GetMapping("hello-write")
    @RolesAllowed("ROLE_WRITE")
    public String helloWrite() {
        return "Hello, User with role WRITE!";
    }

    @GetMapping("hello-pre")
    @PreAuthorize("hasRole('WRITE') or hasRole('DELETE')")
    public String helloPreAuthorized() {
        return "Hello, User with roles WRITE or DELETE!";
    }

    @GetMapping("hello-post")
    @PostAuthorize("returnObject.contains(authentication.principal.username)")
    public String helloPostAuthorized(String name) {
        return "Hello, " + name;
    }
}
