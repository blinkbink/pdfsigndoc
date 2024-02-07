package id.idtrust.signing.util;


import id.idtrust.signing.config.FilterIdConfig;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
//import org.slf4j.MDC;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.UUID;

@Component
@Data
@EqualsAndHashCode(callSuper=false)

public class LogSystem extends OncePerRequestFilter {

    private static final Logger logger = LogManager.getLogger();

    private final String responseHeader;
    private final String mdcKey;
    private final String requestHeader;
    private static String logId;

    static Description ds = new Description();

    public static String getLogId()
    {
        return logId;
    }

    public LogSystem()
    {
        responseHeader = FilterIdConfig.DEFAULT_HEADER_TOKEN;
        mdcKey = FilterIdConfig.DEFAULT_MDC;
        requestHeader = FilterIdConfig.DEFAULT_HEADER_TOKEN;
    }

    public LogSystem(final String responseHeader, final String mdcKey, final String requestHeader)
    {
        this.responseHeader = responseHeader;
        this.mdcKey = mdcKey;
        this.requestHeader = requestHeader;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        try
        {
            final String token = extractToken(httpServletRequest);
            logId=token;
            MDC.put(mdcKey, token);
            if(StringUtils.hasText(responseHeader))
            {
                httpServletResponse.addHeader(responseHeader, token);
            }
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }catch(Exception e)
        {
            e.printStackTrace();
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }finally {
            MDC.remove(mdcKey);
        }
    }

    private String extractToken(final HttpServletRequest request)
    {
        final String token;
        if(StringUtils.hasText(requestHeader) && StringUtils.hasText(request.getHeader(requestHeader)))
        {
            token = request.getHeader(requestHeader) + "-" + UUID.randomUUID().toString().toUpperCase().replace("-", "");
        }
        else
        {
            token = UUID.randomUUID().toString().toUpperCase().replace("-", "");
        }
        return token;
    }

    @Override
    protected boolean isAsyncDispatch(HttpServletRequest request) {
        return super.isAsyncDispatch(request);
    }

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return super.shouldNotFilterErrorDispatch();
    }

    public static void info(String message)
    {
        logger.info("["+ds.VERSION+"]-[KMS/INFO] : " + message);
    }

    public static void request(String message)
    {
        logger.info("["+ds.VERSION+"]-[KMS/REQUEST] : " + message);
    }

    public static void response(String message)
    {
        logger.info("["+ds.VERSION+"]-[KMS/RESPONSE] : " + message);
    }

    public static void error(String message)
    {
        logger.error("["+ds.VERSION+"]-[KMS/ERROR] : " + message);
    }


    public static String getLogTag(String process,String timestamp,String log) {
        String tag="["+ds.VERSION+"]-[KMS/INFO]"+ ":"+ "["+log+"]";
        return tag;
    }

    public static String getSGNLog(HttpServletRequest request, String respData, Date tsp, String LOG) {
        String logData=null;
        long diffInMillies = Math.abs(new Date().getTime() - tsp.getTime());

        if(logData!=null)
            logData=getLogTag("KMS-SGN", String.valueOf(tsp.getTime()), LOG) + request.getRemoteAddr()+" "+request.getRequestURI();
        else
            logData=getLogTag("KMS-SGN", String.valueOf(tsp.getTime()), LOG);

        logData+= " "+respData+"       , "+diffInMillies+" ms";

        return logData;
    }

    public static String getLog(String respData, Date tsp, String LOG) {
        String logData=null;
        long diffInMillies = Math.abs(new Date().getTime() - tsp.getTime());

        logData=getLogTag("KMS",String.valueOf(tsp.getTime()), LOG);

        logData+= " "+respData+"       , "+diffInMillies+" ms";

        return logData;
    }

    public static String getGENCRTLog(HttpServletRequest request, String respData, Date tsp, String LOG) {
        String logData=getLogTag("KMS-GEN", String.valueOf(tsp.getTime()), LOG) + request.getRemoteAddr()+" "+request.getRequestURI();
        long diffInMillies = Math.abs(new Date().getTime() - tsp.getTime());


        logData+= " "+respData+"       , "+diffInMillies+" ms";

        return logData;
    }
    public static String getRVKLog(HttpServletRequest request, String respData, Date tsp, String LOG) {
        String logData=getLogTag("KMS-RVK", String.valueOf(tsp.getTime()), LOG) + request.getRemoteAddr()+" "+request.getRequestURI();
        long diffInMillies = Math.abs(new Date().getTime() - tsp.getTime());


        logData+= " "+respData+"       , "+diffInMillies+" ms";

        return logData;
    }
}