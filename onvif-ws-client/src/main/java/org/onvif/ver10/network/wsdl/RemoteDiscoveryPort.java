package org.onvif.ver10.network.wsdl;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.bind.annotation.XmlSeeAlso;

/**
 * This class was generated by Apache CXF 3.1.10
 * 2018-06-10T15:01:44.002-07:00
 * Generated source version: 3.1.10
 * 
 */
@WebService(targetNamespace = "http://www.onvif.org/ver10/network/wsdl", name = "RemoteDiscoveryPort")
@XmlSeeAlso({org.xmlsoap.schemas.ws._2005._04.discovery.ObjectFactory.class, ObjectFactory.class, org.xmlsoap.schemas.ws._2004._08.addressing.ObjectFactory.class})
@SOAPBinding(parameterStyle = SOAPBinding.ParameterStyle.BARE)
public interface RemoteDiscoveryPort {

    @WebMethod(operationName = "Bye", action = "http://www.onvif.org/ver10/network/wsdl/Bye")
    @WebResult(name = "ByeResponse", targetNamespace = "http://www.onvif.org/ver10/network/wsdl", partName = "parameters")
    public org.xmlsoap.schemas.ws._2005._04.discovery.ResolveType bye(
        @WebParam(partName = "parameters", name = "Bye", targetNamespace = "http://www.onvif.org/ver10/network/wsdl")
        org.xmlsoap.schemas.ws._2005._04.discovery.ByeType parameters
    );

    @WebMethod(operationName = "Hello", action = "http://www.onvif.org/ver10/network/wsdl/Hello")
    @WebResult(name = "HelloResponse", targetNamespace = "http://www.onvif.org/ver10/network/wsdl", partName = "parameters")
    public org.xmlsoap.schemas.ws._2005._04.discovery.ResolveType hello(
        @WebParam(partName = "parameters", name = "Hello", targetNamespace = "http://www.onvif.org/ver10/network/wsdl")
        org.xmlsoap.schemas.ws._2005._04.discovery.HelloType parameters
    );
}
