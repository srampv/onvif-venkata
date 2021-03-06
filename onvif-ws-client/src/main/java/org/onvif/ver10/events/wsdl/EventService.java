package org.onvif.ver10.events.wsdl;

import java.net.URL;
import javax.xml.namespace.QName;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;
import javax.xml.ws.Service;

/**
 * This class was generated by Apache CXF 3.1.10
 * 2018-06-10T15:01:26.702-07:00
 * Generated source version: 3.1.10
 * 
 */
@WebServiceClient(name = "EventService", 
                  targetNamespace = "http://www.onvif.org/ver10/events/wsdl") 
public class EventService extends Service {

    public final static URL WSDL_LOCATION;

    public final static QName SERVICE = new QName("http://www.onvif.org/ver10/events/wsdl", "EventService");
    public final static QName EventPort = new QName("http://www.onvif.org/ver10/events/wsdl", "EventPort");
    static {
        WSDL_LOCATION = null;
    }

    public EventService(URL wsdlLocation) {
        super(wsdlLocation, SERVICE);
    }

    public EventService(URL wsdlLocation, QName serviceName) {
        super(wsdlLocation, serviceName);
    }

    public EventService() {
        super(WSDL_LOCATION, SERVICE);
    }
    
    public EventService(WebServiceFeature ... features) {
        super(WSDL_LOCATION, SERVICE, features);
    }

    public EventService(URL wsdlLocation, WebServiceFeature ... features) {
        super(wsdlLocation, SERVICE, features);
    }

    public EventService(URL wsdlLocation, QName serviceName, WebServiceFeature ... features) {
        super(wsdlLocation, serviceName, features);
    }    




    /**
     *
     * @return
     *     returns EventPortType
     */
    @WebEndpoint(name = "EventPort")
    public EventPortType getEventPort() {
        return super.getPort(EventPort, EventPortType.class);
    }

    /**
     * 
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns EventPortType
     */
    @WebEndpoint(name = "EventPort")
    public EventPortType getEventPort(WebServiceFeature... features) {
        return super.getPort(EventPort, EventPortType.class, features);
    }

}
