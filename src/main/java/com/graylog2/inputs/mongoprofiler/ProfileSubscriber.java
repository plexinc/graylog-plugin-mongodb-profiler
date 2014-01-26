/**
 * Copyright 2014 TORCH GmbH <hello@torch.sh>
 *
 * This file is part of Graylog2 Enterprise.
 *
 */
package com.graylog2.inputs.mongoprofiler;

import com.codahale.metrics.Meter;
import com.mongodb.*;
import org.graylog2.plugin.InputHost;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.buffers.Buffer;
import org.graylog2.plugin.inputs.MessageInput;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * @author Lennart Koopmann <lennart@torch.sh>
 */
public class ProfileSubscriber extends Thread {

    private static final Logger LOG = LoggerFactory.getLogger(ProfileSubscriber.class);

    private final MongoClient mongoClient;
    private final DB db;
    private final DBCollection profile;

    private final Parser parser;

    private final MessageInput sourceInput;
    private final Buffer targetBuffer;
    private final InputHost graylogServer;

    private final Meter newCursors;
    private final Meter cursorReads;

    private boolean stopRequested = false;

    public ProfileSubscriber(MongoClient mongoClient, String dbName, Buffer targetBuffer, MessageInput sourceInput, InputHost graylogServer) {
        LOG.info("Connecting ProfileSubscriber.");

        this.mongoClient = mongoClient;

        this.db = mongoClient.getDB(dbName);
        this.profile = db.getCollection("system.profile");

        parser = new Parser(graylogServer.metrics(), sourceInput);

        this.targetBuffer = targetBuffer;
        this.sourceInput = sourceInput;
        this.graylogServer = graylogServer;

        String metricName = sourceInput.getUniqueReadableId();
        this.cursorReads = graylogServer.metrics().meter(name(metricName, "cursorReads"));
        this.newCursors = graylogServer.metrics().meter(name(metricName, "newCursors"));
    }

    @Override
    public void run() {
        // Wait until the collection is ready. (It is capped after profiling is turned on)
        if(!this.profile.isCapped()) {
            LOG.debug("Profiler collection is not capped. Please enable profiling for database [{}]", this.db.getName());
            while(true) {
                if(this.profile.isCapped()) {
                    LOG.info("Profiler collection is capped. Moving on.");
                    break;
                } else {
                    LOG.debug("Profiler collection is not capped.");
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) { return; }
                }
            }
        }

        while(!stopRequested) {
            try {
                LOG.info("Building new cursor.");
                newCursors.mark();

                DBCursor cursor = profile.find(query())
                        .sort(new BasicDBObject("$natural", 1))
                        .addOption(Bytes.QUERYOPTION_TAILABLE)
                        .addOption(Bytes.QUERYOPTION_AWAITDATA);

                try {
                    while(mongoClient.getConnector().isOpen() && cursor.hasNext()) {
                        cursorReads.mark();

                        if (stopRequested) {
                            LOG.info("Stop requested.");
                            return;
                        }

                        try {
                            Message message = parser.parse(cursor.next());

                            targetBuffer.insertCached(message, sourceInput);
                        } catch(Parser.UnparsableException e) {
                            LOG.error("Cannot parse profile info.", e);
                            continue;
                        } catch(Exception e) {
                            LOG.error("Error when trying to parse profile info.", e);
                            continue;
                        }
                    }
                } finally {
                    if (cursor != null && mongoClient.getConnector().isOpen()) {
                        cursor.close();
                    }
                }
            } catch (Exception e) {
                LOG.error("Error when reading MongoDB profile information. Retrying.", e);
            }

            // Something broke if we get here. Retry soonish.
            try {
                if(!stopRequested) { Thread.sleep(2500); }
            } catch (InterruptedException e) { break; }
        }
    }

    public void terminate() {
        stopRequested = true;

        if(mongoClient != null) {
            mongoClient.close();
        }
    }

    public DBObject query() {
        return QueryBuilder
                .start("ts").greaterThan(DateTime.now(DateTimeZone.UTC).toDate())
                .and("ns").notEquals(db.getName() + ".system.profile")
                .get();

    }

}
