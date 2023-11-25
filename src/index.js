import * as asn1js from 'asn1js'
import { getRandomValues, Certificate, Extension, OCSPRequest, OCSPResponse,  GeneralName, BasicOCSPResponse } from 'pkijs';

export default {
  async fetch(request, env, ctx) {
    
    //https://gist.github.com/robincher/5c73e8ccb53fad9b611778ab363a416a
    
    function base64StringToArrayBuffer(b64str) {
      let byteStr = atob(b64str);
      let bytes = new Uint8Array(byteStr.length);
      for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i);
      }
      return bytes.buffer;
    }
    
    function printCertificate (certificateBuffer) {
      let asn1 = asn1js.fromBER(certificateBuffer);
      if(asn1.offset === (-1)) {
        console.log("Can not parse binary data");
      } 
      return new Certificate({ schema: asn1.result });
    }
  
  // Prepare Certs
  
  const b64Cl = request.headers.get('cf-client-cert-der-base64');
  const berCl = base64StringToArrayBuffer(b64Cl);
  const certCl = printCertificate(berCl);
  
  const b64Is = `${env.CA_CLIENT_ISSUER}`;
  const berIs = base64StringToArrayBuffer(b64Is);
  const certIs = printCertificate(berIs);
  
  const b64Ro = `${env.CA_OCSP_ROOT}`;
  const berRo = base64StringToArrayBuffer(b64Ro);
  const certRo = printCertificate(berRo);
  
  // Create OCSP request
  //https://pkijs.org/docs/classes/OCSPRequest.html

  const ocspReq = new OCSPRequest();
  ocspReq.tbsRequest.requestorName = new GeneralName({
    type: 4,
    value: certCl.subject,
  });
  
  await ocspReq.createForCertificate(certCl, {
    hashAlgorithm: "SHA-256",
    issuerCertificate: certIs,
  });
  
  const nonce = getRandomValues(new Uint8Array(10));
  ocspReq.tbsRequest.requestExtensions = [
    new Extension({
      extnID: "1.3.6.1.5.5.7.48.1.2", // nonce
      extnValue: new asn1js.OctetString({ valueHex: nonce.buffer }).toBER(),
    })
  ];
  
  // Encode OCSP request
  
  const ocspReqRaw = ocspReq.toSchema(true).toBER();
  
  // Get OCSP responder URL
  
  const extAIA = certCl.extensions.find((extension) => extension.extnID === '1.3.6.1.5.5.7.1.1');
  const parsedOcspValue = extAIA.parsedValue.accessDescriptions.find((parsedValue) => parsedValue.accessMethod === '1.3.6.1.5.5.7.48.1');
  const ocspUrl = parsedOcspValue.accessLocation.value;

  const oRequest = new Request(ocspUrl, { method: 'POST', body: ocspReqRaw });
  oRequest.headers.set('content-type', 'application/ocsp-request');
  const oResponce = await fetch(oRequest);

  // Parse OCSP response

  const ocspRespRaw = await oResponce.arrayBuffer();
  const asnOcspResp = asn1js.fromBER(ocspRespRaw);
  const ocspResp = new OCSPResponse({ schema: asnOcspResp.result });
  if (!ocspResp.responseBytes) {
    throw new Error("No \"ResponseBytes\" in the OCSP Response - nothing to verify");
  }

  // Check certificate status

  const certstatus = await ocspResp.getCertificateStatus(certCl, certIs);
  console.log(certstatus.status);

  // Varidate OCSP responder
  //https://pkijs.org/docs/classes/ResponseData.html#responses
  
  const asnOcspRespBasic = asn1js.fromBER(ocspResp.responseBytes.response.valueBlock.valueHex);
  const ocspBasicResp = new BasicOCSPResponse({ schema: asnOcspRespBasic.result });
  
  const ok = await ocspBasicResp.verify({ trustedCerts: [certRo] });
  console.log(ok);
  
  // Send response
  //https://datatracker.ietf.org/doc/html/rfc6960
  const oStat = certstatus.status;
    switch (oStat) {
    case 0:
      return new Response("OCSP Good");
      break;
    case 1:
      return new Response("OCSP Revoked");
      break;
    case 2:
      return new Response("OCSP Unknown");
      break;
    default:
      return new Response("Baaaaaad");
    }
  }
};
