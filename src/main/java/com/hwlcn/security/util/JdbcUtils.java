package com.hwlcn.security.util;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class JdbcUtils {

    private static final Logger log = LoggerFactory.getLogger(JdbcUtils.class);

    private JdbcUtils() {
    }

    public static void closeConnection(Connection connection) {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not close JDBC Connection", ex);
                }
            } catch (Throwable ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Unexpected exception on closing JDBC Connection", ex);
                }
            }
        }
    }

    public static void closeStatement(Statement statement) {
        if (statement != null) {
            try {
                statement.close();
            } catch (SQLException ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not close JDBC Statement", ex);
                }
            } catch (Throwable ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Unexpected exception on closing JDBC Statement", ex);
                }
            }
        }
    }


    public static void closeResultSet(ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not close JDBC ResultSet", ex);
                }
            } catch (Throwable ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Unexpected exception on closing JDBC ResultSet", ex);
                }
            }
        }
    }

}
