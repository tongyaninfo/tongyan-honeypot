import java.sql.*;
import java.util.Properties;

/** 使用 IBM 官方 JCC 验证正常认证拒绝，输入均为固定隔离样本。 */
public final class Db2Probe {
    public static void main(String[] args) throws Exception {
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        Properties properties = new Properties();
        properties.setProperty("user", "isolated_user");
        properties.setProperty("password", "isolated-test-secret");
        if (args.length > 1) properties.setProperty("securityMechanism", args[1]);
        try {
            DriverManager.getConnection("jdbc:db2://127.0.0.1:" + args[0] + "/SAMPLE", properties);
            throw new IllegalStateException("Unexpected successful authentication");
        } catch (SQLException error) {
            if (error.getErrorCode() != -4214 || !"28000".equals(error.getSQLState())) throw error;
            System.out.println("JCC: invalid user ID or password (-4214 / 28000)");
        }
    }
}
