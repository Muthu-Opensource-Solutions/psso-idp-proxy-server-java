package com.muthuopensource.utils;

import jakarta.ws.rs.ext.Provider;
import org.glassfish.jersey.server.monitoring.ApplicationEvent;
import org.glassfish.jersey.server.monitoring.ApplicationEventListener;
import org.glassfish.jersey.server.monitoring.RequestEvent;
import org.glassfish.jersey.server.monitoring.RequestEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.util.logging.LogManager;

/**
 * Runs one-time application bootstrap on server startup via Jersey's {@link ApplicationEventListener}
 * SPI, and shuts down the scheduled executor on server shutdown.
 * <p>
 * {@code @Provider} alone (as used previously) is not sufficient - Jersey only eagerly instantiates
 * {@code @Provider} classes that implement one of its recognized extension contracts (Feature,
 * ExceptionMapper, ContextResolver, ApplicationEventListener, etc). {@link ApplicationEventListener}
 * is such a contract: Jersey's package scan (see {@code jersey.config.server.provider.packages} in
 * web.xml) discovers this class, instantiates it as a singleton, and invokes
 * {@link #onEvent(ApplicationEvent)} with {@link ApplicationEvent.Type#INITIALIZATION_FINISHED}
 * exactly once, right after the application has finished initializing.
 */
@Provider
public class ServerStartupUtil implements ApplicationEventListener {

    private static Logger logger = LoggerFactory.getLogger(ServerStartupUtil.class);

    @Override
    public void onEvent(ApplicationEvent event) {
        switch (event.getType()) {
            case INITIALIZATION_FINISHED -> {
                logger.info("Invoking ServerStartupUtil INITIALIZATION_FINISHED, Build Version : beta-development");
                ServerUtils.registerBC();
                ServerUtils.generateServerSigningKey();
                ServerUtils.registerOIDCMetaDataSyncTask();
                LogManager.getLogManager().reset();
                SLF4JBridgeHandler.removeHandlersForRootLogger();
                SLF4JBridgeHandler.install();
                logger.info("Closing ServerStartupUtil INITIALIZATION_FINISHED");
            }
            case DESTROY_FINISHED -> ServerUtils.executor.shutdown();
            default -> {
                // no-op for other lifecycle phases
            }
        }
    }

    @Override
    public RequestEventListener onRequest(RequestEvent requestEvent) {
        // Not tracking per-request events here.
        return null;
    }
}

