package com.graylog2.inputs.mongoprofiler.input.mongodb;

import com.codahale.metrics.MetricSet;
import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.ImmutableMap;
import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;
import com.mongodb.MongoCredential;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.ServerAddress;
import com.mongodb.MongoSocketException;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.*;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.MisfireException;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.CodecAggregator;
import org.graylog2.plugin.inputs.transports.ThrottleableTransport;
import org.graylog2.plugin.inputs.transports.Transport;
import org.graylog2.plugin.lifecycles.Lifecycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.lang.StringBuffer;

import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;

/**
 * @author Lennart Koopmann <lennart@torch.sh>
 */
public class MongoDBProfilerTransport implements Transport {

  private static final Logger LOG = LoggerFactory.getLogger(MongoDBProfilerTransport.class);

  private static final ImmutableMap<String, String> authMechChoices = ImmutableMap.of("MONGO-CR",
                                                                                      MongoCredential.MONGODB_CR_MECHANISM.toString(),
                                                                                      "SCRAM-SHA-1",
                                                                                      MongoCredential.SCRAM_SHA_1_MECHANISM.toString());

  private static final String CK_MONGO_HOST = "mongo_host";
  private static final String CK_MONGO_PORT = "mongo_port";
  private static final String CK_MONGO_DB = "mongo_db";
  private static final String CK_MONGO_USE_AUTH = "mongo_use_auth";
  private static final String CK_MONGO_USE_SSL = "mongo_use_ssl";
  private static final String CK_MONGO_AUTH_MECH = "mongo_auth_mech";
  private static final String CK_MONGO_USER = "mongo_user";
  private static final String CK_MONGO_PW = "mongo_password";

  private final EventBus serverEventBus;
  private final ServerStatus serverStatus;

  private ProfileSubscriber subscriber;

  private final LocalMetricRegistry localRegistry;

  private static SSLContext trustAllSSLContext = null;
  private static TrustManager[] trustAllCerts;

  // used in case of ssl enabled to trust all certificates
  public static class TrustAllManager implements X509TrustManager {
    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String authType) {
      // No-op, to trust all certs
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String authType) {
      // No-op, to trust all certs
    }
  }




  @AssistedInject
  public MongoDBProfilerTransport(@Assisted final Configuration configuration,
                                  final EventBus serverEventBus,
                                  final LocalMetricRegistry localRegistry,
                                  final ServerStatus serverStatus) {
    this.localRegistry = localRegistry;
    this.serverEventBus = serverEventBus;
    this.serverStatus = serverStatus;
  }

  @Override
  public void setMessageAggregator(CodecAggregator codecAggregator) {
    // Not supported.
  }

  @Subscribe
  public void lifecycleStateChange(Lifecycle lifecycle) {
    LOG.info("Lifecycle changed to {}", lifecycle);
    switch (lifecycle) {
      case PAUSED:
      case FAILED:
      case HALTING:
        if (subscriber != null) {
          subscriber.terminate();
        }
        break;
      default:
        if (subscriber != null) {
          subscriber.terminate();
        }
        break;
    }
  }

  @Override
  public void launch(MessageInput input) throws MisfireException {
    serverStatus.awaitRunning(new Runnable() {
        @Override
        public void run() {
          lifecycleStateChange(Lifecycle.RUNNING);
        }
      });

    serverEventBus.register(this);

    LOG.info("Launching MongoDB profiler reader.");
    LOG.info("trustStore: " + System.getProperty("javax.net.ssl.trustStore"));

    Configuration configuration = input.getConfiguration();
    String mongoHost = configuration.getString(CK_MONGO_HOST);

    LOG.info("Dump configuration: ");
    LOG.info("CK_MONGO_HOST: "+ configuration.getString(CK_MONGO_HOST));
    LOG.info("CK_MONGO_PORT: "+ configuration.getInt(CK_MONGO_PORT));
    LOG.info("CK_MONGO_USER: "+ configuration.getString(CK_MONGO_USER));
    LOG.info("CK_MONGO_PW: "+ configuration.getString(CK_MONGO_PW));
    LOG.info("CK_MONGO_DB: "+ configuration.getString(CK_MONGO_DB));
    LOG.info("CK_MONGO_USE_SSL: "+ configuration.getBoolean(CK_MONGO_USE_SSL));
    LOG.info("CK_MONGO_USE_AUTH: "+ configuration.getBoolean(CK_MONGO_USE_AUTH));
    LOG.info("CK_MONGO_AUTH_MECH: "+ configuration.getString(CK_MONGO_AUTH_MECH));


    MongoClientURI mongoURI;
    MongoClient mongoClient;
    try {
      StringBuffer uri = new StringBuffer(new String("mongodb://"));


      if (configuration.getBoolean(CK_MONGO_USE_AUTH)) {
        uri.append(configuration.getString(CK_MONGO_USER));
        uri.append(":");
        uri.append(configuration.getString(CK_MONGO_PW).toCharArray());
        uri.append("@");
      }

      if(mongoHost.contains(",")) {
        LOG.info("connect to replica set");
        String[] hosts = mongoHost.split(",");
        List<ServerAddress> replicaHosts = Lists.newArrayList();
        for(String host : hosts) {
          replicaHosts.add(new ServerAddress(host, configuration.getInt(CK_MONGO_PORT)));
        }
        String replicaHostsString = Joiner.on(",").join(replicaHosts);
        uri.append(replicaHostsString);

      } else {
        LOG.info("connect to single host");
        ServerAddress serverAddress = new ServerAddress(
                                                        mongoHost,
                                                        configuration.getInt(CK_MONGO_PORT)
                                                        );
        uri.append(serverAddress.toString());
      }

      uri.append("/" + configuration.getString(CK_MONGO_DB));
      if (configuration.getBoolean(CK_MONGO_USE_SSL)) {
        uri.append("?ssl=true");

        if (trustAllCerts == null) {
          trustAllCerts = new TrustManager[] {
            new TrustAllManager()
          };
        }

        try {
          if (trustAllSSLContext == null) {
            try {
              trustAllSSLContext = SSLContext.getInstance("TLS");
              trustAllSSLContext.init(null, trustAllCerts, null);
            } catch (Exception e) {
              LOG.error("ERROR: "+ e);
              throw e;
            }
          }

          if (trustAllSSLContext != SSLContext.getDefault()) {
            try {
              SSLContext.setDefault(trustAllSSLContext);
            } catch (Exception e) {
              LOG.error("ERROR: "+ e);
              throw e;
            }
          }
        } catch (Exception e) {
          LOG.error("ERROR: "+ e);
          throw new MisfireException("Could not setup SSL context for trusting certs.", e);
        }

      } else {
        uri.append("?ssl=false");
      }
      if (configuration.getBoolean(CK_MONGO_USE_AUTH)) {
        uri.append("&authMechanism=" + configuration.getString(CK_MONGO_AUTH_MECH));
        uri.append("&authSource=" + configuration.getString(CK_MONGO_DB));
      }

      LOG.info("before new MongoClient: uri: " + uri);
      mongoURI = new MongoClientURI(uri.toString());
      LOG.info("after new MongoClientURI: " + mongoURI);
      mongoClient = new MongoClient(mongoURI);
      LOG.info("after new MongoClient");

    } catch (MongoSocketException e) {
      throw new MisfireException("Could not connect to MongoDB.", e);
    }

    // Try the connection.
    try {
      mongoClient.getDB(configuration.getString(CK_MONGO_DB)).getStats();
    } catch (Exception e) {
      throw new MisfireException("Could not verify MongoDB profiler connection.", e);
    }

    subscriber = new ProfileSubscriber(
                                       mongoClient,
                                       configuration.getString(CK_MONGO_DB),
                                       input,
                                       localRegistry
                                       );

    LOG.info("MongoDB subscriber starting");
    subscriber.start();
    LOG.info("MongoDB subscriber started");
  }

  @Override
  public void stop() {
    LOG.info("MongoDB subscriber stopping");
    if(subscriber != null) {
      subscriber.terminate();
    }

    serverEventBus.unregister(this);
    LOG.info("MongoDB subscriber stopped and EventBus unregistered");
  }

  @FactoryClass
  public interface Factory extends Transport.Factory<MongoDBProfilerTransport> {
    @Override
    MongoDBProfilerTransport create(Configuration configuration);

    @Override
    Config getConfig();
  }

  @ConfigClass
  public static class Config extends ThrottleableTransport.Config {
    @Override
    public ConfigurationRequest getRequestedConfiguration() {
      final ConfigurationRequest request = super.getRequestedConfiguration();

      request.addField(
                       new TextField(
                                     CK_MONGO_HOST,
                                     "MongoDB hostname",
                                     "localhost",
                                     "The hostname or IP address of the MongoDB instance to connect to. You can also supply comma separated hosts when using a replica set.",
                                     ConfigurationField.Optional.NOT_OPTIONAL)
                       );

      request.addField(
                       new NumberField(
                                       CK_MONGO_PORT,
                                       "MongoDB port",
                                       27017,
                                       "Port of the MongoDB instance to connect to.",
                                       ConfigurationField.Optional.NOT_OPTIONAL,
                                       NumberField.Attribute.IS_PORT_NUMBER
                                       )
                       );

      request.addField(
                       new TextField(
                                     CK_MONGO_DB,
                                     "MongoDB database",
                                     "",
                                     "The name of the profiled MongoDB database.",
                                     ConfigurationField.Optional.NOT_OPTIONAL)
                       );

      request.addField(
                       new BooleanField(
                                        CK_MONGO_USE_SSL,
                                        "Use SSL?",
                                        false,
                                        "Use SSL encryption?"
                                        )
                       );

      request.addField(
                       new BooleanField(
                                        CK_MONGO_USE_AUTH,
                                        "Use authentication?",
                                        false,
                                        "Use MongoDB authentication?"
                                        )
                       );

      request.addField(
                       new DropdownField(
                                         CK_MONGO_AUTH_MECH,
                                         "MongoDB authentication mechanism",
                                         MongoCredential.MONGODB_CR_MECHANISM,
                                         authMechChoices,
                                         "MongoDB authentication mechanism. Only used if authentication is enabled.",
                                         ConfigurationField.Optional.OPTIONAL)
                       );

      request.addField(
                       new TextField(
                                     CK_MONGO_USER,
                                     "MongoDB user",
                                     "",
                                     "MongoDB username. Only used if authentication is enabled.",
                                     ConfigurationField.Optional.OPTIONAL)
                       );

      request.addField(
                       new TextField(
                                     CK_MONGO_PW,
                                     "MongoDB password",
                                     "",
                                     "MongoDB password. Only used if authentication is enabled. Note that this is stored unencrypted",
                                     ConfigurationField.Optional.OPTIONAL,
                                     TextField.Attribute.IS_PASSWORD
                                     )
                       );

      return request;
    }
  }

  @Override
  public MetricSet getMetricSet() {
    return localRegistry;
  }

}
