
package org.oasis_open.docs.wsn.bw_2;

import javax.xml.ws.WebFault;


/**
 * This class was generated by Apache CXF 3.1.10
 * 2018-06-10T15:01:26.604-07:00
 * Generated source version: 3.1.10
 */

@WebFault(name = "InvalidProducerPropertiesExpressionFault", targetNamespace = "http://docs.oasis-open.org/wsn/b-2")
public class InvalidProducerPropertiesExpressionFault extends Exception {
    
    private org.oasis_open.docs.wsn.b_2.InvalidProducerPropertiesExpressionFaultType invalidProducerPropertiesExpressionFault;

    public InvalidProducerPropertiesExpressionFault() {
        super();
    }
    
    public InvalidProducerPropertiesExpressionFault(String message) {
        super(message);
    }
    
    public InvalidProducerPropertiesExpressionFault(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidProducerPropertiesExpressionFault(String message, org.oasis_open.docs.wsn.b_2.InvalidProducerPropertiesExpressionFaultType invalidProducerPropertiesExpressionFault) {
        super(message);
        this.invalidProducerPropertiesExpressionFault = invalidProducerPropertiesExpressionFault;
    }

    public InvalidProducerPropertiesExpressionFault(String message, org.oasis_open.docs.wsn.b_2.InvalidProducerPropertiesExpressionFaultType invalidProducerPropertiesExpressionFault, Throwable cause) {
        super(message, cause);
        this.invalidProducerPropertiesExpressionFault = invalidProducerPropertiesExpressionFault;
    }

    public org.oasis_open.docs.wsn.b_2.InvalidProducerPropertiesExpressionFaultType getFaultInfo() {
        return this.invalidProducerPropertiesExpressionFault;
    }
}
