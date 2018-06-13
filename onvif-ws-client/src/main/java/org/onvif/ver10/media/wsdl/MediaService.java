package org.onvif.ver10.media.wsdl;

import java.net.URL;
import javax.xml.namespace.QName;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;
import javax.xml.ws.Service;

/**
 * This class was generated by Apache CXF 3.1.10
 * 2018-06-10T15:01:34.567-07:00
 * Generated source version: 3.1.10
 * 
 */
@WebServiceClient(name = "MediaService", 
                  targetNamespace = "http://www.onvif.org/ver10/media/wsdl") 
public class MediaService extends Service {

    public final static URL WSDL_LOCATION;

    public final static QName SERVICE = new QName("http://www.onvif.org/ver10/media/wsdl", "MediaService");
    public final static QName MediaPort = new QName("http://www.onvif.org/ver10/media/wsdl", "MediaPort");
    static {
        WSDL_LOCATION = null;
    }

    public MediaService(URL wsdlLocation) {
        super(wsdlLocation, SERVICE);
    }

    public MediaService(URL wsdlLocation, QName serviceName) {
        super(wsdlLocation, serviceName);
    }

    public MediaService() {
        super(WSDL_LOCATION, SERVICE);
    }
    
    public MediaService(WebServiceFeature ... features) {
        super(WSDL_LOCATION, SERVICE, features);
    }

    public MediaService(URL wsdlLocation, WebServiceFeature ... features) {
        super(wsdlLocation, SERVICE, features);
    }

    public MediaService(URL wsdlLocation, QName serviceName, WebServiceFeature ... features) {
        super(wsdlLocation, serviceName, features);
    }    




    /**
     *
     * @return
     *     returns Media
     */
    @WebEndpoint(name = "MediaPort")
    public Media getMediaPort() {
        return super.getPort(MediaPort, Media.class);
    }

    /**
     * 
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns Media
     */
    @WebEndpoint(name = "MediaPort")
    public Media getMediaPort(WebServiceFeature... features) {
        return super.getPort(MediaPort, Media.class, features);
    }

}
