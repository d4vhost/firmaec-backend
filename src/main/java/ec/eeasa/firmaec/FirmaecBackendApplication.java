package ec.eeasa.firmaec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class FirmaecBackendApplication extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(FirmaecBackendApplication.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(FirmaecBackendApplication.class, args);
    }

}