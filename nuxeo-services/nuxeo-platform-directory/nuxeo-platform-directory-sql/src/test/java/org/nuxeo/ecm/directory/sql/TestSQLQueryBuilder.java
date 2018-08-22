/*
 * (C) Copyright 2018 Nuxeo (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Florent Guillaume
 */
package org.nuxeo.ecm.directory.sql;

import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;

import javax.inject.Inject;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.nuxeo.ecm.core.query.sql.model.MultiExpression;
import org.nuxeo.ecm.core.query.sql.model.Predicates;
import org.nuxeo.ecm.core.query.sql.model.QueryBuilder;
import org.nuxeo.ecm.directory.Directory;
import org.nuxeo.ecm.directory.Session;
import org.nuxeo.ecm.directory.api.DirectoryService;
import org.nuxeo.ecm.directory.sql.SQLSession.SQLQueryBuilder;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;

@RunWith(FeaturesRunner.class)
@Features(SQLDirectoryFeature.class)
@Deploy("org.nuxeo.ecm.directory.sql.tests:test-sql-directories-schema-override.xml")
@Deploy("org.nuxeo.ecm.directory.sql.tests:test-sql-directories-bundle.xml")
public class TestSQLQueryBuilder {

    protected static final String USER_DIR = "userDirectory";

    @Inject
    protected DirectoryService directoryService;

    public Session getSession() throws Exception {
        return directoryService.open(USER_DIR);
    }

    public Directory getDirectory() throws Exception {
        return directoryService.getDirectory(USER_DIR);
    }

    @Test
    public void testQueryBuilder() throws Exception {
        Calendar cal = new GregorianCalendar(2010, 0, 1, 12, 34, 56);
        try (Session session = getSession()) {
            QueryBuilder queryBuilder = new QueryBuilder().predicates( //
                    Predicates.not(Predicates.or(Predicates.eq("username", "user_1"),
                            Predicates.eq("username", "Administrator"))), //
                    Predicates.gt("intField", Long.valueOf(123)), //
                    Predicates.noteq("booleanField", Long.valueOf(1)), //
                    Predicates.between("intField", Long.valueOf(123), Long.valueOf(456)), //
                    Predicates.like("firstName", "jo%n"), //
                    Predicates.notlike("firstName", "bob"), //
                    Predicates.ilike("lastName", "smith"), //
                    Predicates.gte("dateField", cal), //
                    Predicates.lt("doubleField", Double.valueOf(3.14)), //
                    Predicates.in("company", "c1", "c2"), //
                    Predicates.notin("company", "c3", "c4"), //
                    Predicates.isnull("username") //
            );
            SQLQueryBuilder builder = ((SQLSession) session).new SQLQueryBuilder();
            builder.visitMultiExpression((MultiExpression) queryBuilder.predicate());
            assertEquals("((NOT ((\"username\" = ?) OR (\"username\" = ?)))" //
                    + " AND (\"intField\" > ?)" //
                    + " AND (\"booleanField\" <> ?)" //
                    + " AND (\"intField\" BETWEEN ? AND ?)" //
                    + " AND (\"firstName\" LIKE ?)" //
                    + " AND (\"firstName\" NOT LIKE ?)" //
                    + " AND (LOWER(\"lastName\") LIKE LOWER(?))" //
                    + " AND (\"dateField\" >= ?)" //
                    + " AND (\"doubleField\" < ?)" //
                    + " AND (\"company\" IN (?, ?))" //
                    + " AND (\"company\" NOT IN (?, ?))" //
                    + " AND (\"username\" IS NULL ))", //
                    builder.clause.toString());
            assertEquals(Arrays.asList( //
                    "user_1", "Administrator", //
                    Long.valueOf(123), //
                    Boolean.TRUE, //
                    Long.valueOf(123), Long.valueOf(456), //
                    "jo%n", //
                    "bob", //
                    "smith", //
                    cal, //
                    Double.valueOf(3.14), //
                    "c1", "c2", //
                    "c3", "c4" //
            ), builder.params.stream().map(cv -> cv.value).collect(toList()));
        }
    }

    @Test
    public void testQueryBuilderEmpty() throws Exception {
        try (Session session = getSession()) {
            QueryBuilder queryBuilder = new QueryBuilder();
            SQLQueryBuilder builder = ((SQLSession) session).new SQLQueryBuilder();
            builder.visitMultiExpression((MultiExpression) queryBuilder.predicate());
            assertEquals("", builder.clause.toString());
            assertEquals(Collections.emptyList(), builder.params.stream().map(cv -> cv.value).collect(toList()));
        }
    }

}
