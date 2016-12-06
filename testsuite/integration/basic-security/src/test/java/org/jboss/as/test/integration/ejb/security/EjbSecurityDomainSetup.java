/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.test.integration.ejb.security;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.*;

import java.io.File;
import java.util.LinkedList;
import java.util.List;

import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.OperationBuilder;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.dmr.ModelNode;
import org.jboss.logging.Logger;
import org.wildfly.extension.elytron.ElytronExtension;

/**
 * Utility methods to create/remove simple security domains
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class EjbSecurityDomainSetup implements ServerSetupTask {

    private static final Logger LOGGER = Logger.getLogger(EjbSecurityDomainSetup.class);

    private static PathAddress realmAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, ElytronExtension.SUBSYSTEM_NAME)
            .append("properties-realm", "UsersRoles");

    private static PathAddress domainAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, ElytronExtension.SUBSYSTEM_NAME)
            .append("security-domain", "EjbDomain");

    private static PathAddress saslAuthenticationAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, ElytronExtension.SUBSYSTEM_NAME)
            .append("sasl-authentication-factory", "ejb3-tests-auth-fac");

    private static PathAddress remotingConnectorAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, "remoting")
            .append("http-connector", "ejb3-tests-connector");

    private static PathAddress ejbDomainAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, "ejb3")
            .append("application-security-domain", "ejb3-tests");

    private static PathAddress ejbRemoteAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, "ejb3")
            .append("service", "remote");

    private static PathAddress httpAuthenticationAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, ElytronExtension.SUBSYSTEM_NAME)
            .append("http-authentication-factory", "ejb3-tests-auth-fac");

    private static PathAddress undertowDomainAddress = PathAddress.pathAddress()
            .append(SUBSYSTEM, "undertow")
            .append("application-security-domain", "ejb3-tests");


    @Override
    public void setup(final ManagementClient managementClient, final String containerId) throws Exception {
        System.out.println("elytron setup...");

        final ModelNode compositeOp = new ModelNode();
        compositeOp.get(OP).set(ModelDescriptionConstants.COMPOSITE);
        compositeOp.get(OP_ADDR).setEmptyList();

        ModelNode steps = compositeOp.get(STEPS);

        // /subsystem=elytron/properties-realm=UsersRoles:add(users-properties={path=users.properties},groups-properties={path=roles.properties})
        ModelNode addRealm = Util.createAddOperation(realmAddress);
        String usersFile = new File(EjbSecurityDomainSetup.class.getResource("users.properties").getFile()).getAbsolutePath();
        String groupsFile = new File(EjbSecurityDomainSetup.class.getResource("roles.properties").getFile()).getAbsolutePath();
        addRealm.get("users-properties").get("path").set(usersFile);
        addRealm.get("groups-properties").get("path").set(groupsFile);
        addRealm.get("plain-text").set(true); // not hashed
        steps.add(addRealm);

        // /subsystem=elytron/security-domain=EjbDomain:add(default-realm=UsersRoles, realms=[{realm=UsersRoles}])
        ModelNode addDomain = Util.createAddOperation(domainAddress);
        addDomain.get("permission-mapper").set("login-permission-mapper"); // LoginPermission for everyone (defined in standalone-elytron.xml)
        addDomain.get("default-realm").set("UsersRoles");
        addDomain.get("realms").get(0).get("realm").set("UsersRoles");
        addDomain.get("realms").get(0).get("role-decoder").set("groups-to-roles"); // use attribute "groups" as roles (defined in standalone-elytron.xml)
        steps.add(addDomain);

        // /subsystem=elytron/sasl-authentication-factory=ejb3-tests-auth-fac:add(sasl-server-factory=configured,security-domain=EjbDomain,mechanism-configurations=[{mechanism-name=BASIC}])
        ModelNode addSaslAuthentication = Util.createAddOperation(saslAuthenticationAddress);
        addSaslAuthentication.get("sasl-server-factory").set("configured");
        addSaslAuthentication.get("security-domain").set("EjbDomain");
        addSaslAuthentication.get("mechanism-configurations").get(0).get("mechanism-name").set("BASIC");
        steps.add(addSaslAuthentication);

        // remoting connection with sasl-authentication-factory
        ModelNode addRemotingConnector = Util.createAddOperation(remotingConnectorAddress);
        addRemotingConnector.get("sasl-authentication-factory").set("ejb3-tests-auth-fac");
        addRemotingConnector.get("connector-ref").set("default");
        // authentication-provider  sasl-protocol  security-realm  server-name
        steps.add(addRemotingConnector);

        // /subsystem=ejb3/application-security-domain=ejb3-tests:add(security-domain=ApplicationDomain)
        ModelNode addEjbDomain = Util.createAddOperation(ejbDomainAddress);
        addEjbDomain.get("security-domain").set("EjbDomain");
        steps.add(addEjbDomain);

        steps.add(Util.getWriteAttributeOperation(ejbRemoteAddress, "connector-ref", "ejb3-tests-connector"));

        ModelNode addHttpAuthentication = Util.createAddOperation(httpAuthenticationAddress);
        addHttpAuthentication.get("security-domain").set("EjbDomain");
        addHttpAuthentication.get("http-server-mechanism-factory").set("global");
        addHttpAuthentication.get("mechanism-configurations").get(0).get("mechanism-name").set("BASIC");
        addHttpAuthentication.get("mechanism-configurations").get(0).get("mechanism-realm-configurations").get(0).get("realm-name").set("TestingRealm");
        steps.add(addHttpAuthentication);

        ModelNode addUndertowDomain = Util.createAddOperation(undertowDomainAddress);
        addUndertowDomain.get("http-authentication-factory").set("ejb3-tests-auth-fac");
        steps.add(addUndertowDomain);

        applyUpdate(managementClient.getControllerClient(), compositeOp, false);
        System.out.println("...elytron setup");
        throw new RuntimeException("DEBUG");
    }

    @Override
    public void tearDown(final ManagementClient managementClient, final String containerId) {
        System.out.println("tearing down...");

        List<ModelNode> updates = new LinkedList<>();
        updates.add(createRemoveIgnoring(undertowDomainAddress));
        updates.add(createRemoveIgnoring(httpAuthenticationAddress));
        updates.add(createRemoveIgnoring(ejbDomainAddress));
        updates.add(createRemoveIgnoring(remotingConnectorAddress));
        updates.add(createRemoveIgnoring(saslAuthenticationAddress));
        updates.add(createRemoveIgnoring(domainAddress));
        updates.add(createRemoveIgnoring(realmAddress));

        try {
            applyUpdates(managementClient.getControllerClient(), updates, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("...tearing down");
    }

    protected static void applyUpdate(final ModelControllerClient client, ModelNode update, boolean allowFailure) throws Exception {
        ModelNode result = client.execute(new OperationBuilder(update).build());
        if (result.hasDefined("outcome") && (allowFailure || "success".equals(result.get("outcome").asString()))) {
            if (result.hasDefined("result")) {
                LOGGER.trace(result.get("result"));
            }
        } else if (result.hasDefined("failure-description")) {
            throw new RuntimeException(result.get("failure-description").toString());
        } else {
            throw new RuntimeException("Operation not successful; outcome = " + result.get("outcome"));
        }
    }

    private static ModelNode createRemoveIgnoring(PathAddress address) {
        ModelNode remove = Util.createRemoveOperation(address);
        // Don't rollback when the AS detects the war needs the module
        remove.get(OPERATION_HEADERS, ROLLBACK_ON_RUNTIME_FAILURE).set(false);
        remove.get(OPERATION_HEADERS, ALLOW_RESOURCE_SERVICE_RESTART).set(true);
        return remove;
    }

    protected static void applyUpdates(final ModelControllerClient client, final List<ModelNode> updates, boolean allowFailure) {
        for (ModelNode update : updates) {
            try {
                applyUpdate(client, update, allowFailure);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
