package com.rasp.hooks;

import com.rasp.utils.RASPUtils;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import javassist.*;

import java.io.*;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.ProtectionDomain;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import javax.naming.*;
import javax.naming.directory.*;
import java.util.Hashtable;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;



public class SsrfHook implements ClassFileTransformer {
    // 目录穿越黑名单
    private static String[] travelPath = new String[]{"../", "..\\", ".."};
    // 危险目录黑名单
    private static Set<String> dangerPathList = new HashSet<String>(Arrays.asList(
            "/", "/home", "/etc",
            "/usr", "/usr/local",
            "/var/log", "/proc",
            "/sys", "/root",
            "C:\\", "D:\\", "E:\\")
    );



    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (className.equals("sun.net.www.protocol.file.Handler")) {
            try {
                String loadName = className.replace("/", ".");
                ClassPool pool = ClassPool.getDefault();
                ClassClassPath classPath = new ClassClassPath(this.getClass());
                pool.insertClassPath(classPath);

                System.out.println("Into the SsrfHook");
                CtClass clz = pool.get(loadName);
                CtMethod method = clz.getDeclaredMethod("handle", new CtClass[]{
                        pool.get(loadName)
                });



                System.out.println("Finish the SsrfHook");

                return clz.toBytecode();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return classfileBuffer;
    }


    // 路径检测算法
    public static void checkFilePath(String filePath) throws Exception {
        // 判断是否为空
        if(filePath == null){
            return;
        }
        // 判断是否存在目录穿越
        if (isPathTraversal(filePath)) {
            RASPUtils.getLogAndAlert("FileRead");
            throw new SecurityException("PathTraversal is not allowed: " + filePath);
        }
        // 是否为危险目录
        if(isDangerPath(filePath)){
            RASPUtils.getLogAndAlert("FileRead");
            throw new SecurityException("DangerPath is not allowed: " + filePath);
        }
        // 是否为允许的文件后缀

    }

    public static void checkFilePath(File file) throws Exception{
        String filePath = file.getPath();
        checkFilePath(filePath);

    }


    public static void main(String[] args) throws Exception {
        disableSslVerification();
        // LDAP server details
        String ldapUrl = "ldaps://v-ldap01.vivo.xyz:636";  // LDAP URL, specify the port if non-default (389)
        String bindDN = "CN=v_userCenter_new,OU=vApps,DC=vivo,DC=xyz";  // DN of the service account
        String bindPassword = "=2Acs2NvZ3d6K1jLuwyX";  // Password of the service account
        String userDN = "CN=72136408,OU=vApps,DC=vivo,DC=xyz";  // DN of the user whose password to change
        String newPassword = "chenlvtang";  // New password for the user

        // Set up the environment for the LDAP connection
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_PRINCIPAL, bindDN);  // Bind DN (service account DN)
        env.put(Context.SECURITY_CREDENTIALS, bindPassword);  // Service account password
        env.put(Context.SECURITY_AUTHENTICATION, "simple");  // Simple authentication method

        try {
            // Create the initial context to connect to the LDAP server
            DirContext ctx = new InitialDirContext(env);

            // Prepare the modification operation to change the password
            ModificationItem[] mods = new ModificationItem[1];
            // Modify the password attribute
            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute("userPassword", newPassword));

            // Perform the modification
            ctx.modifyAttributes(userDN, mods);

            System.out.println("Password for user " + userDN + " has been successfully changed.");

            // Close the connection to the LDAP server
            ctx.close();

        } catch (NamingException e) {
            e.printStackTrace();
            System.err.println("LDAP error: " + e.getMessage());
        }

    }


    private static void disableSslVerification() {
        try {
            TrustManager[] trustAllCertificates = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };

            // Set up the SSL context to use the trust-all manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCertificates, new java.security.SecureRandom());

            // Set the default SSL context to the one with no validation
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Set the default hostname verifier to accept all hostnames
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
            System.err.println("Error disabling SSL verification: " + e.getMessage());
        }
    }



    // 参考JRASP检测算法
    // 目录穿越检测
    public static boolean isPathTraversal(String filePath) {
        for (String item : travelPath) {
            if (filePath.contains(item)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isDangerPath(String filePath){
        File file = new File(filePath);
        String realpath = "";
        try {
            realpath = file.getCanonicalPath();
        } catch (IOException e) {
            realpath = file.getAbsolutePath();
        }
        if (dangerPathList.contains(realpath)) {
            return true;
        }
        return false;
    }

}