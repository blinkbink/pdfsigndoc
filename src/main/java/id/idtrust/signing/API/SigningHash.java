//package id.idtrust.signing.API;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import id.idtrust.signing.util.Description;
//import org.apache.http.HttpEntity;
//import org.apache.http.HttpResponse;
//import org.apache.http.client.HttpClient;
//import org.apache.http.client.methods.HttpPost;
//import org.apache.http.entity.StringEntity;
//import org.apache.http.util.EntityUtils;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//import org.bouncycastle.util.encoders.Base64;
//import org.json.JSONObject;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Service;
//
//import java.io.InputStream;
//import java.security.MessageDigest;
//import java.util.Map;
//
//@Service
//public class SigningHash {
//
//    private static final Logger logger = LogManager.getLogger();
//    @Autowired
//    HttpClient httpClient;
//    public String signingProcess(byte[] data, String keyAlias) throws Exception {
//        Description ds = new Description();
//        try {
//            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Signing Hash");
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] hash = digest.digest(data);
//
//            String query = "http://"+ds.EXTERNAL_SIGNING_URL+":"+ds.EXTERNAL_SIGNING_PORT+"/sign/hash";
//
//            String base64Data = Base64.toBase64String(hash);
//            String input = "{\"keyAlias\":\"" + keyAlias + "\", \"data\":\"" + base64Data + "\"}";
//
//            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Input " + input);
//
//            HttpPost httpPost = new HttpPost(query);
//            httpPost.setHeader("Content-Type", "application/json; charset=UTF-8");
//
//            StringEntity stringEntity = new StringEntity(input);
//            httpPost.setEntity(stringEntity);
//            HttpResponse response = httpClient.execute(httpPost);
//            JSONObject resp;
//
//            HttpEntity entity = response.getEntity();
//            InputStream inputStream = entity.getContent();
//            ObjectMapper mapper = new ObjectMapper();
//            Map<String, String> jsonMap = mapper.readValue(inputStream, Map.class);
//            String jsonString = new ObjectMapper().writeValueAsString(jsonMap);
//
//            resp = new JSONObject(jsonString);
//            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Signing External Response : " + resp);
//
//            EntityUtils.consume(entity);
//            return resp.getString("signature");
//
//        } catch (Exception e) {
//
//            e.printStackTrace();
//            throw new Exception(e);
//        }
//    }
//}
