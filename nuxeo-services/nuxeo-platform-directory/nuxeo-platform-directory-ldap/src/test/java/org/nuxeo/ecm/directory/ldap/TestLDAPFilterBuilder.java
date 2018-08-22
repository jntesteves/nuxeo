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
package org.nuxeo.ecm.directory.ldap;

import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;

import javax.inject.Inject;

import org.junit.Test;
import org.nuxeo.ecm.core.query.sql.model.Predicates;
import org.nuxeo.ecm.core.query.sql.model.QueryBuilder;
import org.nuxeo.ecm.directory.Directory;
import org.nuxeo.ecm.directory.Session;
import org.nuxeo.ecm.directory.api.DirectoryService;
import org.nuxeo.ecm.directory.ldap.LDAPSession.LDAPFilterBuilder;

public class TestLDAPFilterBuilder extends LDAPDirectoryTestCase {

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
                    Predicates.gte("dateField", cal), //
                    Predicates.lt("doubleField", Double.valueOf(3.14)), //
                    Predicates.in("company", "c1", "c2"), //
                    Predicates.notin("company", "c3", "c4"), //
                    Predicates.isnull("username") //
            );
            LDAPFilterBuilder builder = ((LDAPSession) session).new LDAPFilterBuilder();
            builder.walk(queryBuilder.predicate());
            assertEquals("(&" //
                    + "(!(|(uid={0})(uid={1})))" //
                    + "(intField>{2})" //
                    + "(!(booleanField={3}))" //
                    + "(&(intField>={4})(intField<={5}))" //
                    + "(givenName={6}*{7})" //
                    + "(!(givenName={8}))" //
                    + "(dateField>={9})" //
                    + "(doubleField<{10})" //
                    + "(|(o={11})(o={12}))" //
                    + "(!(|(o={13})(o={14})))" //
                    + "(!(uid=*))" //
                    + ")", //
                    builder.filter.toString());
            assertEquals(Arrays.asList( //
                    "user_1", "Administrator", //
                    Long.valueOf(123), //
                    Boolean.TRUE, //
                    Long.valueOf(123), Long.valueOf(456), //
                    "jo", "n", //
                    "bob", //
                    cal, //
                    Double.valueOf(3.14), //
                    "c1", "c2", //
                    "c3", "c4" //
            ), builder.params.stream().collect(toList()));
        }
    }

    @Test
    public void testQueryBuilderEmpty() throws Exception {
        try (Session session = getSession()) {
            QueryBuilder queryBuilder = new QueryBuilder();
            LDAPFilterBuilder builder = ((LDAPSession) session).new LDAPFilterBuilder();
            builder.walk(queryBuilder.predicate());
            assertEquals("", builder.filter.toString());
            assertEquals(Collections.emptyList(), builder.params.stream().collect(toList()));
        }
    }

}
