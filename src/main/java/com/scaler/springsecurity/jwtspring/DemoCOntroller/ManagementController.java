package com.scaler.springsecurity.jwtspring.DemoCOntroller;


import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/management")
public class ManagementController {


    @GetMapping
    public String get() {
        return "get:: Management controller";

    }
    @PostMapping
    public String post() {
        return "post:: Management controller";
    }

    @PutMapping
    public String put() {
        return "put:: Management controller";
    }
    @DeleteMapping
    public String delete() {
        return "delete:: Management controller";
    }
}
