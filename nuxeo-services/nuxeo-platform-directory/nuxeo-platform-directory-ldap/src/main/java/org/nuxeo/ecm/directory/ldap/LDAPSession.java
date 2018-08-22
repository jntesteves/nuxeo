/*
 * (C) Copyright 2006-2018 Nuxeo (http://nuxeo.com/) and others.
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
 *     Nuxeo - initial API and implementation
 *
 */

package org.nuxeo.ecm.directory.ldap;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

import java.io.IOException;
import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.SimpleTimeZone;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.naming.Context;
import javax.naming.LimitExceededException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.Blobs;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.core.api.PropertyException;
import org.nuxeo.ecm.core.api.RecoverableClientException;
import org.nuxeo.ecm.core.api.impl.DocumentModelListImpl;
import org.nuxeo.ecm.core.api.security.SecurityConstants;
import org.nuxeo.ecm.core.query.QueryParseException;
import org.nuxeo.ecm.core.query.sql.model.BooleanLiteral;
import org.nuxeo.ecm.core.query.sql.model.DateLiteral;
import org.nuxeo.ecm.core.query.sql.model.DefaultQueryVisitor;
import org.nuxeo.ecm.core.query.sql.model.DoubleLiteral;
import org.nuxeo.ecm.core.query.sql.model.Expression;
import org.nuxeo.ecm.core.query.sql.model.Function;
import org.nuxeo.ecm.core.query.sql.model.IntegerLiteral;
import org.nuxeo.ecm.core.query.sql.model.Literal;
import org.nuxeo.ecm.core.query.sql.model.LiteralList;
import org.nuxeo.ecm.core.query.sql.model.MultiExpression;
import org.nuxeo.ecm.core.query.sql.model.Operand;
import org.nuxeo.ecm.core.query.sql.model.Operator;
import org.nuxeo.ecm.core.query.sql.model.OrderByExpr;
import org.nuxeo.ecm.core.query.sql.model.OrderByList;
import org.nuxeo.ecm.core.query.sql.model.Predicates;
import org.nuxeo.ecm.core.query.sql.model.QueryBuilder;
import org.nuxeo.ecm.core.query.sql.model.Reference;
import org.nuxeo.ecm.core.query.sql.model.StringLiteral;
import org.nuxeo.ecm.core.schema.types.Field;
import org.nuxeo.ecm.core.schema.types.ListType;
import org.nuxeo.ecm.core.schema.types.SimpleTypeImpl;
import org.nuxeo.ecm.core.schema.types.Type;
import org.nuxeo.ecm.core.schema.types.primitives.BooleanType;
import org.nuxeo.ecm.core.schema.types.primitives.DateType;
import org.nuxeo.ecm.core.storage.ExpressionEvaluator;
import org.nuxeo.ecm.core.storage.QueryOptimizer.PrefixInfo;
import org.nuxeo.ecm.core.storage.sql.jdbc.db.Column;
import org.nuxeo.ecm.core.utils.SIDGenerator;
import org.nuxeo.ecm.directory.BaseSession;
import org.nuxeo.ecm.directory.DirectoryException;
import org.nuxeo.ecm.directory.DirectoryFieldMapper;
import org.nuxeo.ecm.directory.EntryAdaptor;
import org.nuxeo.ecm.directory.PasswordHelper;
import org.nuxeo.ecm.directory.BaseSession.PasswordFieldDetector;

import com.mongodb.QueryOperators;

/**
 * This class represents a session against an LDAPDirectory.
 *
 * @author Olivier Grisel <ogrisel@nuxeo.com>
 */
public class LDAPSession extends BaseSession {

    protected static final String MISSING_ID_LOWER_CASE = "lower";

    protected static final String MISSING_ID_UPPER_CASE = "upper";

    private static final Log log = LogFactory.getLog(LDAPSession.class);

    // set to false for debugging
    private static final boolean HIDE_PASSWORD_IN_LOGS = true;

    protected DirContext dirContext;

    protected final String idAttribute;

    protected final String idCase;

    protected final String searchBaseDn;

    protected final Set<String> emptySet = Collections.emptySet();

    protected final String sid;

    protected final String rdnAttribute;

    protected final String rdnField;

    protected final String passwordHashAlgorithm;

    public LDAPSession(LDAPDirectory directory) {
        super(directory, LDAPReference.class);
        DirectoryFieldMapper fieldMapper = directory.getFieldMapper();
        idAttribute = fieldMapper.getBackendField(getIdField());
        LDAPDirectoryDescriptor descriptor = directory.getDescriptor();
        idCase = descriptor.getIdCase();
        sid = String.valueOf(SIDGenerator.next());
        searchBaseDn = descriptor.getSearchBaseDn();
        substringMatchType = descriptor.getSubstringMatchType();
        rdnAttribute = descriptor.getRdnAttribute();
        rdnField = directory.getFieldMapper().getDirectoryField(rdnAttribute);
        passwordHashAlgorithm = descriptor.passwordHashAlgorithm;
        permissions = descriptor.permissions;
    }

    @Override
    public LDAPDirectory getDirectory() {
        return (LDAPDirectory) directory;
    }

    public DirContext getContext() {
        if (dirContext == null) {
            // Initialize directory context lazily
            LDAPDirectory ldapDirectory = (LDAPDirectory) directory;
            ContextProvider testServer = ldapDirectory.getTestServer();
            DirContext context = testServer == null ? ldapDirectory.createContext() : testServer.getContext();
            dirContext = LdapRetryHandler.wrap(context, ldapDirectory.getServer().getRetries());
        }
        return dirContext;
    }

    @Override
    protected DocumentModel createEntryWithoutReferences(Map<String, Object> fieldMap) {
        // Make a copy of fieldMap to avoid modifying it
        fieldMap = new HashMap<>(fieldMap);

        LDAPDirectoryDescriptor descriptor = getDirectory().getDescriptor();
        List<String> referenceFieldList = new LinkedList<>();
        try {
            String dn = String.format("%s=%s,%s", rdnAttribute, fieldMap.get(rdnField), descriptor.getCreationBaseDn());
            Attributes attrs = new BasicAttributes();
            Attribute attr;

            List<String> mandatoryAttributes = getMandatoryAttributes();
            for (String mandatoryAttribute : mandatoryAttributes) {
                attr = new BasicAttribute(mandatoryAttribute);
                attr.add(" ");
                attrs.put(attr);
            }

            String[] creationClasses = descriptor.getCreationClasses();
            if (creationClasses.length != 0) {
                attr = new BasicAttribute("objectclass");
                for (String creationClasse : creationClasses) {
                    attr.add(creationClasse);
                }
                attrs.put(attr);
            }

            for (String fieldId : fieldMap.keySet()) {
                String backendFieldId = getDirectory().getFieldMapper().getBackendField(fieldId);
                if (fieldId.equals(getPasswordField())) {
                    attr = new BasicAttribute(backendFieldId);
                    String password = (String) fieldMap.get(fieldId);
                    password = PasswordHelper.hashPassword(password, passwordHashAlgorithm);
                    attr.add(password);
                    attrs.put(attr);
                } else if (getDirectory().isReference(fieldId)) {
                    List<org.nuxeo.ecm.directory.Reference> references = directory.getReferences(fieldId);
                    if (references.size() > 1) {
                        // not supported
                    } else {
                        org.nuxeo.ecm.directory.Reference reference = references.get(0);
                        if (reference instanceof LDAPReference) {
                            attr = new BasicAttribute(((LDAPReference) reference).getStaticAttributeId());
                            attr.add(descriptor.getEmptyRefMarker());
                            attrs.put(attr);
                        }
                    }
                    referenceFieldList.add(fieldId);
                } else if (LDAPDirectory.DN_SPECIAL_ATTRIBUTE_KEY.equals(backendFieldId)) {
                    // ignore special DN field
                    log.warn(String.format("field %s is mapped to read only DN field: ignored", fieldId));
                } else {
                    Object value = fieldMap.get(fieldId);
                    if ((value != null) && !value.equals("") && !Collections.emptyList().equals(value)) {
                        attrs.put(getAttributeValue(fieldId, value));
                    }
                }
            }

            if (log.isDebugEnabled()) {
                Attributes logAttrs;
                if (HIDE_PASSWORD_IN_LOGS && attrs.get(getPasswordField()) != null) {
                    logAttrs = (Attributes) attrs.clone();
                    logAttrs.put(getPasswordField(), "********"); // hide password in logs
                } else {
                    logAttrs = attrs;
                }
                String idField = getIdField();
                log.debug(String.format("LDAPSession.createEntry(%s=%s): LDAP bind dn='%s' attrs='%s' [%s]", idField,
                        fieldMap.get(idField), dn, logAttrs, this));
            }
            getContext().bind(dn, null, attrs);

            String dnFieldName = getDirectory().getFieldMapper()
                                               .getDirectoryField(LDAPDirectory.DN_SPECIAL_ATTRIBUTE_KEY);
            if (getDirectory().getSchemaFieldMap().containsKey(dnFieldName)) {
                // add the DN special attribute to the fieldmap of the new
                // entry
                fieldMap.put(dnFieldName, dn);
            }
        } catch (NamingException e) {
            handleException(e, "createEntry failed");
            return null;
        }

        return fieldMapToDocumentModel(fieldMap);
    }

    @Override
    protected List<String> updateEntryWithoutReferences(DocumentModel docModel) {
        List<String> updateList = new ArrayList<>();
        List<String> referenceFieldList = new LinkedList<>();
        Map<String, Field> schemaFieldMap = directory.getSchemaFieldMap();
        try {
            for (String fieldName : schemaFieldMap.keySet()) {
                if (!docModel.getPropertyObject(schemaName, fieldName).isDirty()) {
                    continue;
                }
                if (getDirectory().isReference(fieldName)) {
                    referenceFieldList.add(fieldName);
                } else {
                    updateList.add(fieldName);
                }
            }

            if (!isReadOnlyEntry(docModel) && !updateList.isEmpty()) {
                Attributes attrs = new BasicAttributes();
                SearchResult ldapEntry = getLdapEntry(docModel.getId());
                if (ldapEntry == null) {
                    throw new DirectoryException(docModel.getId() + " not found");
                }
                Attributes oldattrs = ldapEntry.getAttributes();
                String dn = ldapEntry.getNameInNamespace();
                Attributes attrsToDel = new BasicAttributes();
                for (String f : updateList) {
                    Object value = docModel.getProperty(schemaName, f);
                    String backendField = getDirectory().getFieldMapper().getBackendField(f);
                    if (LDAPDirectory.DN_SPECIAL_ATTRIBUTE_KEY.equals(backendField)) {
                        // skip special LDAP DN field that is readonly
                        log.warn(String.format("field %s is mapped to read only DN field: ignored", f));
                        continue;
                    }
                    if (value == null || value.equals("")) {
                        Attribute objectClasses = oldattrs.get("objectClass");
                        Attribute attr;
                        if (getMandatoryAttributes(objectClasses).contains(backendField)) {
                            attr = new BasicAttribute(backendField);
                            // XXX: this might fail if the mandatory attribute
                            // is typed integer for instance
                            attr.add(" ");
                            attrs.put(attr);
                        } else if (oldattrs.get(backendField) != null) {
                            attr = new BasicAttribute(backendField);
                            attr.add(oldattrs.get(backendField).get());
                            attrsToDel.put(attr);
                        }
                    } else if (f.equals(getPasswordField())) {
                        // The password has been updated, it has to be encrypted
                        Attribute attr = new BasicAttribute(backendField);
                        attr.add(PasswordHelper.hashPassword((String) value, passwordHashAlgorithm));
                        attrs.put(attr);
                    } else {
                        attrs.put(getAttributeValue(f, value));
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug(
                            String.format(
                                    "LDAPSession.updateEntry(%s): LDAP modifyAttributes dn='%s' "
                                            + "mod_op='REMOVE_ATTRIBUTE' attr='%s' [%s]",
                                    docModel, dn, attrsToDel, this));
                }
                getContext().modifyAttributes(dn, DirContext.REMOVE_ATTRIBUTE, attrsToDel);

                if (log.isDebugEnabled()) {
                    log.debug(String.format("LDAPSession.updateEntry(%s): LDAP modifyAttributes dn='%s' "
                            + "mod_op='REPLACE_ATTRIBUTE' attr='%s' [%s]", docModel, dn, attrs, this));
                }
                getContext().modifyAttributes(dn, DirContext.REPLACE_ATTRIBUTE, attrs);
            }
        } catch (NamingException e) {
            handleException(e, "updateEntry failed:");
        }
        return referenceFieldList;
    }

    @Override
    public void deleteEntryWithoutReferences(String id) {
        try {
            SearchResult result = getLdapEntry(id, false);

            if (log.isDebugEnabled()) {
                log.debug(String.format("LDAPSession.deleteEntry(%s): LDAP destroySubcontext dn='%s' [%s]", id,
                        result.getNameInNamespace(), this));
            }
            getContext().destroySubcontext(result.getNameInNamespace());
        } catch (NamingException e) {
            handleException(e, "deleteEntry failed for: " + id);
        }
    }

    @Override
    public boolean hasEntry(String id) {
        try {
            // TODO: check directory cache first
            return getLdapEntry(id) != null;
        } catch (NamingException e) {
            throw new DirectoryException("hasEntry failed: " + e.getMessage(), e);
        }
    }

    protected SearchResult getLdapEntry(String id) throws NamingException {
        return getLdapEntry(id, false);
    }

    protected SearchResult getLdapEntry(String id, boolean fetchAllAttributes) throws NamingException {
        if (StringUtils.isEmpty(id)) {
            log.warn("The application should not " + "query for entries with an empty id " + "=> return no results");
            return null;
        }
        String filterExpr;
        String baseFilter = getDirectory().getBaseFilter();
        if (baseFilter.startsWith("(")) {
            filterExpr = String.format("(&(%s={0})%s)", idAttribute, baseFilter);
        } else {
            filterExpr = String.format("(&(%s={0})(%s))", idAttribute, baseFilter);
        }
        String[] filterArgs = { id };
        SearchControls scts = getDirectory().getSearchControls(fetchAllAttributes);

        if (log.isDebugEnabled()) {
            log.debug(String.format(
                    "LDAPSession.getLdapEntry(%s, %s): LDAP search base='%s' filter='%s' "
                            + " args='%s' scope='%s' [%s]",
                    id, fetchAllAttributes, searchBaseDn, filterExpr, id, scts.getSearchScope(), this));
        }
        NamingEnumeration<SearchResult> results;
        try {
            results = getContext().search(searchBaseDn, filterExpr, filterArgs, scts);
        } catch (NameNotFoundException nnfe) {
            // sometimes ActiveDirectory have some query fail with: LDAP:
            // error code 32 - 0000208D: NameErr: DSID-031522C9, problem
            // 2001 (NO_OBJECT).
            // To keep the application usable return no results instead of
            // crashing but log the error so that the AD admin
            // can fix the issue.
            log.error("Unexpected response from server while performing query: " + nnfe.getMessage(), nnfe);
            return null;
        }

        if (!results.hasMore()) {
            log.debug("Entry not found: " + id);
            return null;
        }
        SearchResult result = results.next();
        try {
            String dn = result.getNameInNamespace();
            if (results.hasMore()) {
                result = results.next();
                String dn2 = result.getNameInNamespace();
                String msg = String.format(
                        "Unable to fetch entry for '%s': found more than one match," + " for instance: '%s' and '%s'",
                        id, dn, dn2);
                log.error(msg);
                // ignore entries that are ambiguous while giving enough info
                // in the logs to let the LDAP admin be able to fix the issue
                return null;
            }
            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "LDAPSession.getLdapEntry(%s, %s): LDAP search base='%s' filter='%s' "
                                + " args='%s' scope='%s' => found: %s [%s]",
                        id, fetchAllAttributes, searchBaseDn, filterExpr, id, scts.getSearchScope(), dn, this));
            }
        } catch (UnsupportedOperationException e) {
            // ignore unsupported operation thrown by the Apache DS server in
            // the tests in embedded mode
        }
        return result;
    }

    protected void handleException(Exception e, String message) {
        LdapExceptionProcessor processor = getDirectory().getDescriptor().getExceptionProcessor();

        RecoverableClientException userException = processor.extractRecoverableException(e);
        if (userException != null) {
            throw userException;
        }
        throw new DirectoryException(message + " " + e.getMessage(), e);

    }

    @Override
    public void deleteEntry(String id, Map<String, String> map) {
        log.warn("Calling deleteEntry extended on LDAP directory");
        deleteEntry(id);
    }

    @Override
    public DocumentModel getEntryFromSource(String id, boolean fetchReferences) {
        try {
            SearchResult result = getLdapEntry(id, false);
            if (result == null) {
                return null;
            }
            return ldapResultToDocumentModel(result, id, fetchReferences);
        } catch (NamingException e) {
            throw new DirectoryException("getEntry failed: " + e.getMessage(), e);
        }
    }

    @Override
    public DocumentModelList query(Map<String, Serializable> filter, Set<String> fulltext, Map<String, String> orderBy,
            boolean fetchReferences, int limit, int offset) {
        if (!hasPermission(SecurityConstants.READ)) {
            return new DocumentModelListImpl();
        }
        try {
            // building the query using filterExpr / filterArgs to
            // escape special characters and to fulltext search only on
            // the explicitly specified fields
            String[] filters = new String[filter.size()];
            String[] filterArgs = new String[filter.size()];

            if (fulltext == null) {
                fulltext = Collections.emptySet();
            }

            int index = 0;
            for (String fieldName : filter.keySet()) {
                if (getDirectory().isReference(fieldName)) {
                    log.warn(fieldName + " is a reference and will be ignored as a query criterion");
                    continue;
                }

                String backendFieldName = getDirectory().getFieldMapper().getBackendField(fieldName);
                Object fieldValue = filter.get(fieldName);

                StringBuilder currentFilter = new StringBuilder();
                currentFilter.append("(");
                if (fieldValue == null) {
                    currentFilter.append("!(").append(backendFieldName).append("=*)");
                } else if ("".equals(fieldValue)) {
                    if (fulltext.contains(fieldName)) {
                        currentFilter.append(backendFieldName).append("=*");
                    } else {
                        currentFilter.append("!(").append(backendFieldName).append("=*)");
                    }
                } else {
                    currentFilter.append(backendFieldName).append("=");
                    if (fulltext.contains(fieldName)) {
                        switch (substringMatchType) {
                        case subinitial:
                            currentFilter.append("{").append(index).append("}*");
                            break;
                        case subfinal:
                            currentFilter.append("*{").append(index).append("}");
                            break;
                        case subany:
                            currentFilter.append("*{").append(index).append("}*");
                            break;
                        }
                    } else {
                        currentFilter.append("{").append(index).append("}");
                    }
                }
                currentFilter.append(")");
                filters[index] = currentFilter.toString();
                if (fieldValue != null && !"".equals(fieldValue)) {
                    if (fieldValue instanceof Blob) {
                        // filter arg could be a sequence of \xx where xx is the
                        // hexadecimal value of the byte
                        log.warn("Binary search is not supported");
                    } else {
                        // XXX: what kind of Objects can we get here? Is
                        // toString() enough?
                        filterArgs[index] = fieldValue.toString();
                    }
                }
                index++;
            }
            String filterExpr = "(&" + getDirectory().getBaseFilter() + StringUtils.join(filters) + ')';
            SearchControls scts = getDirectory().getSearchControls(true);

            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "LDAPSession.query(...): LDAP search base='%s' filter='%s' args='%s' scope='%s' [%s]",
                        searchBaseDn, filterExpr, StringUtils.join(filterArgs, ","), scts.getSearchScope(), this));
            }
            try {
                NamingEnumeration<SearchResult> results = getContext().search(searchBaseDn, filterExpr, filterArgs,
                        scts);
                DocumentModelList entries = ldapResultsToDocumentModels(results, fetchReferences);

                if (orderBy != null && !orderBy.isEmpty()) {
                    getDirectory().orderEntries(entries, orderBy);
                }
                return applyQueryLimits(entries, limit, offset);
            } catch (NameNotFoundException nnfe) {
                // sometimes ActiveDirectory have some query fail with: LDAP:
                // error code 32 - 0000208D: NameErr: DSID-031522C9, problem
                // 2001 (NO_OBJECT).
                // To keep the application usable return no results instead of
                // crashing but log the error so that the AD admin
                // can fix the issue.
                log.error("Unexpected response from server while performing query: " + nnfe.getMessage(), nnfe);
                return new DocumentModelListImpl();
            }
        } catch (LimitExceededException e) {
            throw new org.nuxeo.ecm.directory.SizeLimitExceededException(e);
        } catch (NamingException e) {
            throw new DirectoryException("executeQuery failed", e);
        }
    }

    @Override
    public DocumentModelList query(QueryBuilder queryBuilder, boolean fetchReferences, boolean countTotal) {
        if (!hasPermission(SecurityConstants.READ)) {
            return new DocumentModelListImpl();
        }
        if (PasswordFieldDetector.hasPasswordField(queryBuilder.predicate(), getPasswordField())) {
            throw new DirectoryException("Cannot filter on password");
        }
        if (isMultiTenant()) {
            // filter entries on the tenantId field also
            String tenantId = getCurrentTenantId();
            if (!StringUtils.isEmpty(tenantId)) {
                // TODO don't modify passed-in value
                queryBuilder.addAndPredicate(Predicates.eq(TENANT_ID_FIELD, tenantId));
            }
        }

        // build where clause from query
        LDAPFilterBuilder builder = new LDAPFilterBuilder();
        builder.walk(queryBuilder.predicate());
        // get resulting clause
        String filter = builder.filter.toString();
        // add static filters
        filter = getDirectory().addBaseFilter(filter);

        int limit = Math.max(0, (int) queryBuilder.limit());
        int offset = Math.max(0, (int) queryBuilder.offset());
        // TODO orderby

        Select select = new Select(table);
        select.setWhat(getReadColumnsSQL());
        select.setFrom(table.getQuotedName());
        select.setWhere(whereClause);

        StringBuilder orderBy = new StringBuilder();
        OrderByList orders = queryBuilder.orders();
        if (!orders.isEmpty()) {
            for (OrderByExpr ob : orders) {
                if (orderBy.length() != 0) {
                    orderBy.append(", ");
                }
                orderBy.append(dialect.openQuote());
                orderBy.append(ob.reference.name);
                orderBy.append(dialect.closeQuote());
                if (ob.isDescending) {
                    orderBy.append(" DESC");
                }
            }
            select.setOrderBy(orderBy.toString());
        }

        String query = select.getStatement();
        if (limit != 0 || offset != 0) {
            if (!dialect.supportsPaging()) {
                throw new QueryParseException("Cannot use limit/offset, not supported by database");
            }
            query = dialect.addPagingClause(query, limit, offset);
        }

        if (logger.isLogEnabled()) {
            List<Serializable> values = builder.params.stream()
                                                      .map(ColumnAndValue::getValue)
                                                      .collect(Collectors.toList());
            logger.logSQL(query, values);
        }

        // execute the query and create a documentModel list
        DocumentModelListImpl list = new DocumentModelListImpl();
        try (PreparedStatement ps = sqlConnection.prepareStatement(query)) {
            int i = 1;
            for (ColumnAndValue columnAndValue : builder.params) {
                setFieldValue(ps, i++, columnAndValue.column, columnAndValue.value);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    // fetch values for stored fields
                    Map<String, Object> map = new HashMap<>();
                    for (Column column : getReadColumns()) {
                        Object o = getFieldValue(rs, column);
                        map.put(column.getKey(), o);
                    }
                    DocumentModel docModel = fieldMapToDocumentModel(map);
                    // fetch the reference fields
                    if (fetchReferences) {
                        Map<String, List<String>> targetIdsMap = new HashMap<>();
                        for (org.nuxeo.ecm.directory.Reference reference : directory.getReferences()) {
                            List<String> targetIds = reference.getTargetIdsForSource(docModel.getId());
                            String fieldName = reference.getFieldName();
                            targetIdsMap.computeIfAbsent(fieldName, key -> new ArrayList<>()).addAll(targetIds);
                        }
                        for (Entry<String, List<String>> en : targetIdsMap.entrySet()) {
                            String fieldName = en.getKey();
                            List<String> targetIds = en.getValue();
                            docModel.setProperty(schemaName, fieldName, targetIds);
                        }
                    }
                    list.add(docModel);
                }
            }
        }

        if (limit != 0 || offset != 0) {
            int count;
            if (countTotal) {
                // count the total number of results
                Select selectCount = new Select(table);
                selectCount.setWhat("COUNT(*)");
                selectCount.setFrom(table.getQuotedName());
                selectCount.setWhere(whereClause);
                String countQuery = selectCount.getStatement();
                if (logger.isLogEnabled()) {
                    List<Serializable> values = builder.params.stream()
                                                              .map(ColumnAndValue::getValue)
                                                              .collect(Collectors.toList());
                    logger.logSQL(countQuery, values);
                }
                try (PreparedStatement ps = sqlConnection.prepareStatement(countQuery)) {
                    int i = 1;
                    for (ColumnAndValue columnAndValue : builder.params) {
                        setFieldValue(ps, i++, columnAndValue.column, columnAndValue.value);
                    }
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        count = rs.getInt(1);
                        if (logger.isLogEnabled()) {
                            logger.logCount(count);
                        }
                    }
                }
            } else {
                count = -2; // unknown
            }
            list.setTotalSize(count);
        }

        return list;
    }

    public class LDAPFilterBuilder {

        protected static final String DATE_CAST = "DATE";

        public StringBuilder filter = new StringBuilder();

        public int paramIndex = 0;

        public final List<Serializable> params = new ArrayList<>();

        public void walk(Expression expression) {
            if (expression instanceof MultiExpression && ((MultiExpression) expression).values.isEmpty()) {
                // special-case empty query
                return;
            } else {
                walkExpression(expression);
            }
        }

        public void walkExpression(Expression expr) {
            Operator op = expr.operator;
            Operand lvalue = expr.lvalue;
            Operand rvalue = expr.rvalue;
            Reference ref = lvalue instanceof Reference ? (Reference) lvalue : null;
            String name = ref != null ? ref.name : null;
            String cast = ref != null ? ref.cast : null;
            if (DATE_CAST.equals(cast)) {
                checkDateLiteralForCast(op, rvalue, name);
            }
            if (op == Operator.SUM) {
                throw new UnsupportedOperationException("SUM");
            } else if (op == Operator.SUB) {
                throw new UnsupportedOperationException("SUB");
            } else if (op == Operator.MUL) {
                throw new UnsupportedOperationException("MUL");
            } else if (op == Operator.DIV) {
                throw new UnsupportedOperationException("DIV");
            } else if (op == Operator.LT) {
                walkLt(lvalue, rvalue);
            } else if (op == Operator.GT) {
                walkGt(lvalue, rvalue);
            } else if (op == Operator.EQ) {
                walkEq(lvalue, rvalue);
            } else if (op == Operator.NOTEQ) {
                walkNotEq(lvalue, rvalue);
            } else if (op == Operator.LTEQ) {
                walkLtEq(lvalue, rvalue);
            } else if (op == Operator.GTEQ) {
                walkGtEq(lvalue, rvalue);
            } else if (op == Operator.AND) {
                if (expr instanceof MultiExpression) {
                    walkAndMultiExpression((MultiExpression) expr);
                } else {
                    walkAnd(expr);
                }
            } else if (op == Operator.NOT) {
                walkNot(lvalue);
            } else if (op == Operator.OR) {
                if (expr instanceof MultiExpression) {
                    walkOrMultiExpression((MultiExpression) expr);
                } else {
                    walkOr(expr);
                }
            } else if (op == Operator.LIKE) {
                walkLike(lvalue, rvalue, true, false);
            } else if (op == Operator.ILIKE) {
                walkLike(lvalue, rvalue, true, true);
            } else if (op == Operator.NOTLIKE) {
                walkLike(lvalue, rvalue, false, false);
            } else if (op == Operator.NOTILIKE) {
                walkLike(lvalue, rvalue, false, true);
            } else if (op == Operator.IN) {
                walkIn(lvalue, rvalue, true);
            } else if (op == Operator.NOTIN) {
                walkIn(lvalue, rvalue, false);
            } else if (op == Operator.ISNULL) {
                walkIsNull(lvalue);
            } else if (op == Operator.ISNOTNULL) {
                walkIsNotNull(lvalue);
            } else if (op == Operator.BETWEEN) {
                walkBetween(lvalue, rvalue, true);
            } else if (op == Operator.NOTBETWEEN) {
                walkBetween(lvalue, rvalue, false);
            } else {
                throw new QueryParseException("Unknown operator: " + op);
            }
        }

        protected void checkDateLiteralForCast(Operator op, Operand value, String name) {
            if (op == Operator.BETWEEN || op == Operator.NOTBETWEEN) {
                LiteralList l = (LiteralList) value;
                checkDateLiteralForCast(l.get(0), name);
                checkDateLiteralForCast(l.get(1), name);
            } else {
                checkDateLiteralForCast(value, name);
            }
        }

        protected void checkDateLiteralForCast(Operand value, String name) {
            if (value instanceof DateLiteral && !((DateLiteral) value).onlyDate) {
                throw new QueryParseException("DATE() cast must be used with DATE literal, not TIMESTAMP: " + name);
            }
        }

        public void walkNot(Operand value) {
            filter.append("(!");
            walkOperand(value);
            filter.append(')');
        }

        public void walkIsNull(Operand value) {
            filter.append("(!");
            walkIsNotNull(value);
            filter.append(')');
        }

        public void walkIsNotNull(Operand value) {
            filter.append('(');
            walkReference(value);
            filter.append("=*)");
        }

        public void walkAndMultiExpression(MultiExpression expr) {
            walkMulti("&", expr.values);
        }

        public void walkAnd(Expression expr) {
            walkMulti("&", Arrays.asList(expr.lvalue, expr.rvalue));
        }

        public void walkOrMultiExpression(MultiExpression expr) {
            walkMulti("|", expr.values);
        }

        public void walkOr(Expression expr) {
            walkMulti("|", Arrays.asList(expr.lvalue, expr.rvalue));
        }

        protected void walkMulti(String op, List<Operand> values) {
            if (values.size() == 1) {
                walkOperand(values.get(0));
            } else {
                filter.append('(');
                filter.append(op);
                for (Operand value : values) {
                    walkOperand(value);
                }
                filter.append(')');
            }
        }

        public void walkEq(Operand lvalue, Operand rvalue) {
            walkBinOp("=", lvalue, rvalue);
        }

        public void walkNotEq(Operand lvalue, Operand rvalue) {
            filter.append("(!");
            walkEq(lvalue, rvalue);
            filter.append(')');
        }

        public void walkLt(Operand lvalue, Operand rvalue) {
            walkBinOp("<", lvalue, rvalue);
        }

        public void walkGt(Operand lvalue, Operand rvalue) {
            walkBinOp(">", lvalue, rvalue);
        }

        public void walkLtEq(Operand lvalue, Operand rvalue) {
            walkBinOp("<=", lvalue, rvalue);
        }

        public void walkGtEq(Operand lvalue, Operand rvalue) {
            walkBinOp(">=", lvalue, rvalue);
        }

        protected void walkBinOp(String op, Operand lvalue, Operand rvalue) {
            filter.append('(');
            Field field = walkReference(lvalue);
            filter.append(op);
            if (field.getType() instanceof BooleanType) {
                rvalue = makeBoolean(rvalue);
            }
            walkLiteral(rvalue);
            filter.append(')');
        }

        protected Operand makeBoolean(Operand rvalue) {
            if (rvalue instanceof BooleanLiteral) {
                return rvalue;
            }
            long v;
            if (!(rvalue instanceof IntegerLiteral) || ((v = ((IntegerLiteral) rvalue).value) != 0 && v != 1)) {
                throw new QueryParseException(
                        "Boolean expressions require boolean or literal 0 or 1 as right argument");
            }
            return new BooleanLiteral(v == 1);
        }

        public void walkBetween(Operand lvalue, Operand rvalue, boolean positive) {
            LiteralList list = (LiteralList) rvalue;
            Literal left = list.get(0);
            Literal right = list.get(1);
            if (!positive) {
                filter.append("(!");
            }
            filter.append("(&");
            walkGtEq(lvalue, left);
            walkLtEq(lvalue, right);
            filter.append(')');
            if (!positive) {
                filter.append(')');
            }
        }

        public void walkIn(Operand lvalue, Operand rvalue, boolean positive) {
            if (!positive) {
                filter.append("(!");
            }
            filter.append("(|");
            for (Literal value : (LiteralList) rvalue) {
                walkEq(lvalue, value);
            }
            filter.append(')');
            if (!positive) {
                filter.append(')');
            }
        }

        public void walkLike(Operand lvalue, Operand rvalue, boolean positive, boolean caseInsensitive) {
            if (caseInsensitive) {
                throw new QueryParseException("Invalid ILIKE for LDAP directory");
            }
            if (!(rvalue instanceof StringLiteral)) {
                throw new QueryParseException("Invalid LIKE, right hand side must be a string: " + rvalue);
            }
            String like = ((StringLiteral) rvalue).value;

            if (!positive) {
                filter.append("(!");
            }
            filter.append('(');
            walkReference(lvalue);
            filter.append('=');
            walkLikeWildcard(like);
            filter.append(')');
            if (!positive) {
                filter.append(')');
            }
        }

        /**
         * Turns a NXQL LIKE pattern into an LDAP wildcard.
         * <p>
         * % and _ are standard wildcards, and \ escapes them.
         *
         * @since 7.4
         */
        public void walkLikeWildcard(String like) {
            StringBuilder param = new StringBuilder();
            char[] chars = like.toCharArray();
            boolean escape = false;
            for (int i = 0; i < chars.length; i++) {
                char c = chars[i];
                boolean escapeNext = false;
                if (escape) {
                    param.append(c);
                } else {
                    switch (c) {
                    case '%':
                        if (param.length() != 0) {
                            addFilterParam(param.toString());
                            param.setLength(0);
                        }
                        filter.append('*');
                        break;
                    case '_':
                        throw new QueryParseException("Cannot use _ wildcard in LIKE for LDAP directory");
                    case '\\':
                        escapeNext = true;
                        break;
                    default:
                        param.append(c);
                        break;
                    }
                }
                escape = escapeNext;
            }
            if (escape) {
                throw new QueryParseException("Invalid LIKE parameter ending with escape character");
            }
            if (param.length() != 0) {
                addFilterParam(param.toString());
            }
        }

        public void walkOperand(Operand operand) {
            if (operand instanceof Literal) {
                walkLiteral((Literal) operand);
            } else if (operand instanceof Function) {
                walkFunction((Function) operand);
            } else if (operand instanceof Expression) {
                walkExpression((Expression) operand);
            } else if (operand instanceof Reference) {
                walkReference((Reference) operand);
            } else {
                throw new QueryParseException("Unknown operand: " + operand);
            }
        }

        public void walkLiteral(Operand operand) {
            if (!(operand instanceof Literal)) {
                throw new QueryParseException("Requires literal instead of: " + operand);
            }
            Literal lit = (Literal) operand;
            if (lit instanceof BooleanLiteral) {
                walkBooleanLiteral((BooleanLiteral) lit);
            } else if (lit instanceof DateLiteral) {
                walkDateLiteral((DateLiteral) lit);
            } else if (lit instanceof DoubleLiteral) {
                walkDoubleLiteral((DoubleLiteral) lit);
            } else if (lit instanceof IntegerLiteral) {
                walkIntegerLiteral((IntegerLiteral) lit);
            } else if (lit instanceof StringLiteral) {
                walkStringLiteral((StringLiteral) lit);
            } else {
                throw new QueryParseException("Unknown literal: " + lit);
            }
        }

        public void walkBooleanLiteral(BooleanLiteral lit) {
            addFilterParam(Boolean.valueOf(lit.value));
        }

        public void walkDateLiteral(DateLiteral lit) {
            if (lit.onlyDate) {
                throw new QueryParseException("Cannot use only date in LDAP query: " + lit);
            }
            addFilterParam(lit.toCalendar()); // let LDAP library serialize it
        }

        public void walkDoubleLiteral(DoubleLiteral lit) {
            addFilterParam(Double.valueOf(lit.value));
        }

        public void walkIntegerLiteral(IntegerLiteral lit) {
            addFilterParam(Long.valueOf(lit.value));
        }

        public void walkStringLiteral(StringLiteral lit) {
            addFilterParam(lit.value);
        }

        protected void addFilterParam(Serializable value) {
            filter.append('{');
            filter.append(paramIndex++);
            filter.append('}');
            params.add(value);
        }

        public Object walkFunction(Function func) {
            throw new UnsupportedOperationException(func.name);
        }

        public Field walkReference(Operand value) {
            if (!(value instanceof Reference)) {
                throw new QueryParseException("Invalid query, left hand side must be a property: " + value);
            }
            String name = ((Reference) value).name;
            if (getDirectory().isReference(name)) {
                throw new QueryParseException("Column: " + name
                        + " is a reference and cannot be queried for directory: " + getDirectory().getName());
            }
            Field field = getDirectory().getSchemaFieldMap().get(name);
            if (field == null) {
                throw new QueryParseException(
                        "No column: " + name + " for directory: " + getDirectory().getName());
            }
            String backend = getDirectory().getFieldMapper().getBackendField(name);
            filter.append(backend);
            return field;
        }

    }

    @Override
    public void close() {
        try {
            getContext().close();
        } catch (NamingException e) {
            throw new DirectoryException("close failed", e);
        } finally {
            getDirectory().removeSession(this);
        }
    }

    protected DocumentModel fieldMapToDocumentModel(Map<String, Object> fieldMap) {
        String id = String.valueOf(fieldMap.get(getIdField()));
        try {
            DocumentModel docModel = BaseSession.createEntryModel(sid, schemaName, id, fieldMap, isReadOnly());
            EntryAdaptor adaptor = getDirectory().getDescriptor().getEntryAdaptor();
            if (adaptor != null) {
                docModel = adaptor.adapt(directory, docModel);
            }
            return docModel;
        } catch (PropertyException e) {
            log.error(e, e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    protected Object getFieldValue(Attribute attribute, String fieldName, String entryId, boolean fetchReferences) {

        Field field = directory.getSchemaFieldMap().get(fieldName);
        Type type = field.getType();
        if (type instanceof SimpleTypeImpl) {
            // type with constraint
            type = type.getSuperType();
        }
        Object defaultValue = field.getDefaultValue();
        String typeName = type.getName();
        if (attribute == null) {
            return defaultValue;
        }
        Object value;
        try {
            value = attribute.get();
        } catch (NamingException e) {
            throw new DirectoryException("Could not fetch value for " + attribute, e);
        }
        if (value == null) {
            return defaultValue;
        }
        String trimmedValue = value.toString().trim();
        if ("string".equals(typeName)) {
            return trimmedValue;
        } else if ("integer".equals(typeName) || "long".equals(typeName)) {
            if ("".equals(trimmedValue)) {
                return defaultValue;
            }
            try {
                return Long.valueOf(trimmedValue);
            } catch (NumberFormatException e) {
                log.error(String.format(
                        "field %s of type %s has non-numeric value found on server: '%s' (ignoring and using default value instead)",
                        fieldName, typeName, trimmedValue));
                return defaultValue;
            }
        } else if (type.isListType()) {
            List<String> parsedItems = new LinkedList<>();
            NamingEnumeration<Object> values = null;
            try {
                values = (NamingEnumeration<Object>) attribute.getAll();
                while (values.hasMore()) {
                    parsedItems.add(values.next().toString().trim());
                }
                return parsedItems;
            } catch (NamingException e) {
                log.error(String.format(
                        "field %s of type %s has non list value found on server: '%s' (ignoring and using default value instead)",
                        fieldName, typeName, values != null ? values.toString() : trimmedValue));
                return defaultValue;
            } finally {
                if (values != null) {
                    try {
                        values.close();
                    } catch (NamingException e) {
                        log.error(e, e);
                    }
                }
            }
        } else if ("date".equals(typeName)) {
            if ("".equals(trimmedValue)) {
                return defaultValue;
            }
            try {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
                dateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
                Date date = dateFormat.parse(trimmedValue);
                Calendar cal = Calendar.getInstance();
                cal.setTime(date);
                return cal;
            } catch (ParseException e) {
                log.error(String.format(
                        "field %s of type %s has invalid value found on server: '%s' (ignoring and using default value instead)",
                        fieldName, typeName, trimmedValue));
                return defaultValue;
            }
        } else if ("content".equals(typeName)) {
            return Blobs.createBlob((byte[]) value);
        } else {
            throw new DirectoryException("Field type not supported in directories: " + typeName);
        }
    }

    @SuppressWarnings("unchecked")
    protected Attribute getAttributeValue(String fieldName, Object value) {
        Attribute attribute = new BasicAttribute(getDirectory().getFieldMapper().getBackendField(fieldName));
        Field field = directory.getSchemaFieldMap().get(fieldName);
        if (field == null) {
            String message = String.format("Invalid field name '%s' for directory '%s' with schema '%s'", fieldName,
                    directory.getName(), directory.getSchema());
            throw new DirectoryException(message);
        }
        Type type = field.getType();
        if (type instanceof SimpleTypeImpl) {
            // type with constraint
            type = type.getSuperType();
        }
        String typeName = type.getName();

        if ("string".equals(typeName)) {
            attribute.add(value);
        } else if ("integer".equals(typeName) || "long".equals(typeName)) {
            attribute.add(value.toString());
        } else if (type.isListType()) {
            Collection<String> valueItems;
            if (value instanceof String[]) {
                valueItems = Arrays.asList((String[]) value);
            } else if (value instanceof Collection) {
                valueItems = (Collection<String>) value;
            } else {
                throw new DirectoryException(String.format("field %s with value %s does not match type %s", fieldName,
                        value.toString(), type.getName()));
            }
            for (String item : valueItems) {
                attribute.add(item);
            }
        } else if ("date".equals(typeName)) {
            Calendar cal = (Calendar) value;
            Date date = cal.getTime();
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            dateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
            attribute.add(dateFormat.format(date));
        } else if ("content".equals(typeName)) {
            try {
                attribute.add(((Blob) value).getByteArray());
            } catch (IOException e) {
                throw new DirectoryException("Failed to get ByteArray value", e);
            }
        } else {
            throw new DirectoryException("Field type not supported in directories: " + typeName);
        }

        return attribute;
    }

    protected DocumentModelList ldapResultsToDocumentModels(NamingEnumeration<SearchResult> results,
            boolean fetchReferences) throws NamingException {
        DocumentModelListImpl list = new DocumentModelListImpl();
        try {
            while (results.hasMore()) {
                SearchResult result = results.next();
                DocumentModel entry = ldapResultToDocumentModel(result, null, fetchReferences);
                if (entry != null) {
                    list.add(entry);
                }
            }
        } catch (SizeLimitExceededException e) {
            if (list.isEmpty()) {
                // the server did no send back the truncated results set,
                // re-throw the exception to that the user interface can display
                // the error message
                throw e;
            }
            // mark the collect results as a truncated result list
            log.debug("SizeLimitExceededException caught," + " return truncated results. Original message: "
                    + e.getMessage() + " explanation: " + e.getExplanation());
            list.setTotalSize(-2);
        } finally {
            results.close();
        }
        log.debug("LDAP search returned " + list.size() + " results");
        return list;
    }

    protected DocumentModel ldapResultToDocumentModel(SearchResult result, String entryId, boolean fetchReferences)
            throws NamingException {
        Attributes attributes = result.getAttributes();
        String passwordFieldId = getPasswordField();
        Map<String, Object> fieldMap = new HashMap<>();

        Attribute attribute = attributes.get(idAttribute);
        // NXP-2461: check that id field is filled + NXP-2730: make sure that
        // entry id is the one returned from LDAP
        if (attribute != null) {
            Object entry = attribute.get();
            if (entry != null) {
                entryId = entry.toString();
            }
        }
        // NXP-7136 handle id case
        entryId = changeEntryIdCase(entryId, idCase);

        if (entryId == null) {
            // don't bother
            return null;
        }
        for (String fieldName : directory.getSchemaFieldMap().keySet()) {
            List<org.nuxeo.ecm.directory.Reference> references = directory.getReferences(fieldName);
            if (references != null && references.size() > 0) {
                if (fetchReferences) {
                    Map<String, List<String>> referencedIdsMap = new HashMap<>();
                    for (org.nuxeo.ecm.directory.Reference reference : references) {
                        // reference resolution
                        List<String> referencedIds;
                        if (reference instanceof LDAPReference) {
                            // optim: use the current LDAPSession directly to
                            // provide the LDAP reference with the needed backend entries
                            LDAPReference ldapReference = (LDAPReference) reference;
                            referencedIds = ldapReference.getLdapTargetIds(attributes);
                        } else if (reference instanceof LDAPTreeReference) {
                            // TODO: optimize using the current LDAPSession
                            // directly to provide the LDAP reference with the
                            // needed backend entries (needs to implement getLdapTargetIds)
                            LDAPTreeReference ldapReference = (LDAPTreeReference) reference;
                            referencedIds = ldapReference.getTargetIdsForSource(entryId);
                        } else {
                            referencedIds = reference.getTargetIdsForSource(entryId);
                        }
                        referencedIds = new ArrayList<>(referencedIds);
                        Collections.sort(referencedIds);
                        if (referencedIdsMap.containsKey(fieldName)) {
                            referencedIdsMap.get(fieldName).addAll(referencedIds);
                        } else {
                            referencedIdsMap.put(fieldName, referencedIds);
                        }
                    }
                    fieldMap.put(fieldName, referencedIdsMap.get(fieldName));
                }
            } else {
                // manage directly stored fields
                String attributeId = getDirectory().getFieldMapper().getBackendField(fieldName);
                if (attributeId.equals(LDAPDirectory.DN_SPECIAL_ATTRIBUTE_KEY)) {
                    // this is the special DN readonly attribute
                    try {
                        fieldMap.put(fieldName, result.getNameInNamespace());
                    } catch (UnsupportedOperationException e) {
                        // ignore ApacheDS partial implementation when running
                        // in embedded mode
                    }
                } else {
                    // this is a regular attribute
                    attribute = attributes.get(attributeId);
                    if (fieldName.equals(passwordFieldId)) {
                        // do not try to fetch the password attribute
                        continue;
                    } else {
                        fieldMap.put(fieldName, getFieldValue(attribute, fieldName, entryId, fetchReferences));
                    }
                }
            }
        }
        // check if the idAttribute was returned from the search. If not
        // set it anyway, maybe changing its case if it's a String instance
        String fieldId = getDirectory().getFieldMapper().getDirectoryField(idAttribute);
        Object obj = fieldMap.get(fieldId);
        if (obj == null) {
            fieldMap.put(fieldId, changeEntryIdCase(entryId, getDirectory().getDescriptor().getMissingIdFieldCase()));
        } else if (obj instanceof String) {
            fieldMap.put(fieldId, changeEntryIdCase((String) obj, idCase));
        }
        return fieldMapToDocumentModel(fieldMap);
    }

    protected String changeEntryIdCase(String id, String idFieldCase) {
        if (MISSING_ID_LOWER_CASE.equals(idFieldCase)) {
            return id.toLowerCase();
        } else if (MISSING_ID_UPPER_CASE.equals(idFieldCase)) {
            return id.toUpperCase();
        }
        // returns the unchanged id
        return id;
    }

    @Override
    public boolean authenticate(String username, String password) {

        if (password == null || "".equals(password.trim())) {
            // never use anonymous bind as a way to authenticate a user in
            // Nuxeo EP
            return false;
        }

        // lookup the user: fetch its dn
        SearchResult entry;
        try {
            entry = getLdapEntry(username);
        } catch (NamingException e) {
            throw new DirectoryException("failed to fetch the ldap entry for " + username, e);
        }
        if (entry == null) {
            // no such user => authentication failed
            return false;
        }
        String dn = entry.getNameInNamespace();
        Properties env = (Properties) getDirectory().getContextProperties().clone();
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, password);

        InitialLdapContext authenticationDirContext = null;
        try {
            // creating a context does a bind
            log.debug(String.format("LDAP bind dn='%s'", dn));
            authenticationDirContext = new InitialLdapContext(env, null);
            // force reconnection to prevent from using a previous connection
            // with an obsolete password (after an user has changed his
            // password)
            authenticationDirContext.reconnect(null);
            log.debug("Bind succeeded, authentication ok");
            return true;
        } catch (NamingException e) {
            log.debug("Bind failed: " + e.getMessage());
            // authentication failed
            return false;
        } finally {
            try {
                if (authenticationDirContext != null) {
                    authenticationDirContext.close();
                }
            } catch (NamingException e) {
                log.error("Error closing authentication context when biding dn " + dn, e);
            }
        }
    }

    @Override
    public boolean isAuthenticating() {
        return directory.getSchemaFieldMap().containsKey(getPasswordField());
    }

    public boolean rdnMatchesIdField() {
        return getDirectory().getDescriptor().rdnAttribute.equals(idAttribute);
    }

    @SuppressWarnings("unchecked")
    protected List<String> getMandatoryAttributes(Attribute objectClassesAttribute) {
        try {
            List<String> mandatoryAttributes = new ArrayList<>();

            DirContext schema = getContext().getSchema("");
            List<String> objectClasses = new ArrayList<>();
            if (objectClassesAttribute == null) {
                // use the creation classes as reference schema for this entry
                objectClasses.addAll(Arrays.asList(getDirectory().getDescriptor().getCreationClasses()));
            } else {
                // introspec the objectClass definitions to find the mandatory
                // attributes for this entry
                NamingEnumeration<Object> values = null;
                try {
                    values = (NamingEnumeration<Object>) objectClassesAttribute.getAll();
                    while (values.hasMore()) {
                        objectClasses.add(values.next().toString().trim());
                    }
                } catch (NamingException e) {
                    throw new DirectoryException(e);
                } finally {
                    if (values != null) {
                        values.close();
                    }
                }
            }
            objectClasses.remove("top");
            for (String creationClass : objectClasses) {
                Attributes attributes = schema.getAttributes("ClassDefinition/" + creationClass);
                Attribute attribute = attributes.get("MUST");
                if (attribute != null) {
                    NamingEnumeration<String> values = (NamingEnumeration<String>) attribute.getAll();
                    try {
                        while (values.hasMore()) {
                            String value = values.next();
                            mandatoryAttributes.add(value);
                        }
                    } finally {
                        values.close();
                    }
                }
            }
            return mandatoryAttributes;
        } catch (NamingException e) {
            throw new DirectoryException("getMandatoryAttributes failed", e);
        }
    }

    protected List<String> getMandatoryAttributes() {
        return getMandatoryAttributes(null);
    }

    @Override
    // useful for the log function
    public String toString() {
        return String.format("LDAPSession '%s' for directory %s", sid, directory.getName());
    }

    @Override
    public DocumentModel createEntry(DocumentModel entry) {
        Map<String, Object> fieldMap = entry.getProperties(directory.getSchema());
        Map<String, Object> simpleNameFieldMap = new HashMap<>();
        for (Map.Entry<String, Object> fieldEntry : fieldMap.entrySet()) {
            String fieldKey = fieldEntry.getKey();
            if (fieldKey.contains(":")) {
                fieldKey = fieldKey.split(":")[1];
            }
            simpleNameFieldMap.put(fieldKey, fieldEntry.getValue());
        }
        return createEntry(simpleNameFieldMap);
    }

}
