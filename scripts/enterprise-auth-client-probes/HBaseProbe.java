import java.io.*;
import java.net.*;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.security.HBaseSaslRpcClient;
import org.apache.hadoop.hbase.security.SecurityInfo;
import org.apache.hadoop.hbase.security.provider.DigestSaslClientAuthenticationProvider;
import org.apache.hadoop.hbase.security.token.AuthenticationTokenIdentifier;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.ipc.RemoteException;

/** 使用官方 HBase RPC/SASL 客户端，合成 delegation token，不连接 KDC 或真实集群。 */
public final class HBaseProbe {
    public static void main(String[] args) throws Exception {
        AuthenticationTokenIdentifier identity = new AuthenticationTokenIdentifier("isolated_user");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        identity.write(new DataOutputStream(bytes));
        Token<AuthenticationTokenIdentifier> token = new Token<>(bytes.toByteArray(),
            "isolated-token-secret".getBytes("UTF-8"), AuthenticationTokenIdentifier.AUTH_TOKEN_TYPE, new Text("isolated-cluster"));
        Configuration configuration = new Configuration(false);
        configuration.set("hbase.security.authentication", "kerberos");
        try (Socket socket = new Socket("127.0.0.1", Integer.parseInt(args[0]))) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(new byte[] { 'H', 'B', 'a', 's', 0, 82 });
            HBaseSaslRpcClient client = new HBaseSaslRpcClient(configuration,
                new DigestSaslClientAuthenticationProvider(), token, InetAddress.getByName("127.0.0.1"),
                SecurityInfo.getInfo("ClientService"), false);
            try {
                client.saslConnect(socket.getInputStream(), socket.getOutputStream());
                throw new IllegalStateException("Unexpected successful authentication");
            } catch (RemoteException error) {
                if (!error.getClassName().equals("org.apache.hadoop.security.token.SecretManager$InvalidToken")) throw error;
                System.out.println("HBase: InvalidToken / Token authentication failed");
            }
        }
    }
}
