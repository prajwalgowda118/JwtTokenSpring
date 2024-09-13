package com.scaler.springsecurity.jwtspring.DemoCOntroller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")

public class AdminController {


    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public String get() {
        return "get:: Admin controller";

    }
    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public String post() {
        return "post:: Admin controller";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    public String put() {
        return "put:: Admin controller";
    }
    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public String delete() {
        return "delete:: Admin controller";
    }
}
