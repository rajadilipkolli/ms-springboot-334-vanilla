package io.fusion.air.microservice.server.config;
// Spring
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Configuration;

/**
 * Springboot 2.7.x to 3.0 Migration
 *
 * Response Header Size
 * The property server.max.http.header.size is deprecated in favour of server.max-http-request-header-size, which
 * checks only the size of the request header.
 *
 * To define a limit also for the response header, let's define a new bean.
 *
 * @author: Araf Karsh Hamid
 * @version:
 * @date:
 */
@Configuration
public class WebServerConfig implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        factory.addConnectorCustomizers(connector ->
                connector.setProperty("maxHttpResponseHeaderSize", "100000")
        );
    }

    /**
     * The Following code is converted into a Lambda
     * @param factory
     */
    /**
     * Shown here only for the demo purpose.
    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        factory.addConnectorCustomizers(new TomcatConnectorCustomizer() {
            @Override
            public void customize(Connector connector) {
                connector.setProperty("maxHttpResponseHeaderSize", "100000");
            }
        });
    }
    */
}
