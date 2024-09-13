package com.scaler.springsecurity.jwtspring.Config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.tags.Tag;

@OpenAPIDefinition(
        info = @Info(
                title = "JWT Spring Project",
                version = "1.0",
                description = "Open API documentation for Spring Security with JWT",
                termsOfService = "https://www.yourwebsite.com/terms",
                contact = @Contact(
                        name = "Prajwal Gowda",
                        email = "prajwal7683@gmail.com",
                        url = "https://www.linkedin.com/in/prajwalgowdakr/"
                ),
                license = @License(
                        name = "Your License Name",
                        url = "https://www.yourwebsite.com/license"
                )
        ),
        servers = {
                @Server(
                        description = "Local Development Environment",
                        url = "http://localhost:8080"
                )
        },
        tags = {
                @Tag(name = "Authentication", description = "Endpoints related to user authentication"),
                @Tag(name = "User Management", description = "Endpoints related to user management")
        },
        security = {

        }
)
@SecurityScheme(
        name="jwt bearer",
        description = "jwt auth authentication",
        scheme="bearer" ,
        type= SecuritySchemeType.HTTP,
        bearerFormat="jwt",
        in=SecuritySchemeIn.HEADER

)
public class OpenApiConfig {


}
