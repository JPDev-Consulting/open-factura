import * as forge from "node-forge";
import { readFileSync } from "fs";
import axios from "axios";
import { signInvoiceXml } from "ec-sri-invoice-signer";
/**
 * Load a .p12 (PKCS#12) file from disk and return its raw ArrayBuffer.
 */
export function getP12FromLocalFile(path: string): ArrayBuffer {
  const file = readFileSync(path);
  // Slice out the underlying ArrayBuffer
  return file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength);
}

/**
 * Download a .p12 file from a URL and return its raw ArrayBuffer.
 */
export async function getP12FromUrl(url: string): Promise<ArrayBuffer> {
  const response = await axios.get<ArrayBuffer>(url, {
    responseType: "arraybuffer",
  });
  return response.data;
}

/**
 * Load an XML file from disk and return it as a string.
 */
export function getXMLFromLocalFile(path: string): string {
  return readFileSync(path, "utf8");
}

/**
 * Download an XML file from a URL and return it as a string.
 */
export async function getXMLFromLocalUrl(url: string): Promise<string> {
  const response = await axios.get<string>(url, {
    responseType: "text",
  });
  return response.data;
}

/** Helper: SHA‑256 digest of a string, base64‑encoded */
function sha256Base64(text: string, encoding: forge.Encoding = "utf8"): string {
  const md = forge.md.sha256.create();
  md.update(text, encoding);
  const hashHex = md.digest().toHex();
  return Buffer.from(hashHex, "hex").toString("base64");
}

/** Helper: Convert hex string to base64 */
function hexToBase64(hex: string): string {
  hex = hex.padStart(hex.length + (hex.length % 2), "0");
  const bytes = hex.match(/.{2}/g)!.map((byte) => parseInt(byte, 16));
  return Buffer.from(bytes).toString("base64");
}

/** Helper: Convert a big integer to base64 PEM‑style chunks */
function bigIntToBase64(bigInt: number): string {
  const hex = bigInt.toString(16);
  const bytes = hex.match(/\w{2}/g)!.map((pair) => parseInt(pair, 16));
  const byteString = String.fromCharCode(...bytes);
  const base64 = Buffer.from(byteString, "binary").toString("base64");
  // wrap at 76 characters per PEM spec
  return base64.match(/.{1,76}/g)!.join("\n");
}

/** Helper: random integer between min and max */
function getRandomNumber(min = 990, max = 9999): number {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

/**
 * Sign an XML string using a PKCS#12 certificate.
 * Returns the XML with an embedded ds:Signature element.
 */
export async function signXml(
  p12Data: ArrayBuffer,
  p12Password: string,
  xmlData: string
): Promise<string> {
  // Normalize whitespace
  let xml = xmlData.replace(/\s+/g, " ").trim();
  xml = xml.replace(/(?<=\>)(\r?\n)|(\r?\n)(?=\<\/)/g, "").trim();
  xml = xml.replace(/(?<=\>)(\s*)/g, "");

  // Decode the P12
  const arrayUint8 = new Uint8Array(p12Data);
  const b64 = forge.util.binary.base64.encode(arrayUint8);
  const derBytes = forge.util.decode64(b64);
  const asn1 = forge.asn1.fromDer(derBytes);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, p12Password);

  const signedInvoice = signInvoiceXml(xmlData, Buffer.from(p12Data), {
    pkcs12Password: p12Password,
  });

  return signedInvoice;
  // // Extract key and certificate bags
  // const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  // const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  // const certBagArray = certBags[(forge as any).oids.certBag]!;
  // // Pick the leaf certificate
  // const cert = certBagArray.reduce((prev, curr) =>
  //   curr.cert!.extensions.length > prev.cert!.extensions.length ? curr : prev
  // );

  // // Check validity dates
  // const notBefore = cert.cert!.validity.notBefore;
  // const notAfter = cert.cert!.validity.notAfter;
  // const now = new Date();
  // if (now < notBefore || now > notAfter) {
  //   throw new Error("Expired certificate");
  // }

  // // Prepare certificate PEM (stripped headers)
  // let pem = forge.pki.certificateToPem(cert.cert!);
  // pem = pem.replace(/-----BEGIN CERTIFICATE-----[\r\n]?/, "");
  // pem = pem.replace(/[\r\n]?-----END CERTIFICATE-----/, "");
  // pem = pem.replace(/\r?\n|\r/g, "").replace(/(.{76})/g, "$1\n");

  // // Compute certificate digest
  // const derCert = forge.asn1
  //   .toDer(forge.pki.certificateToAsn1(cert.cert!))
  //   .getBytes();
  // const certDigest = sha256Base64(derCert, "utf8");

  // // Prepare the SignedProperties XML fragment
  // const getSigningTime = (): string => {
  //   const dt = new Date();
  //   const pad = (n: number, z = 2) => ("00" + n).slice(-z);
  //   const ms = pad(dt.getMilliseconds(), 3);
  //   const offset = -dt.getTimezoneOffset();
  //   const sign = offset >= 0 ? "+" : "-";
  //   const h = pad(Math.floor(Math.abs(offset) / 60));
  //   const m = pad(Math.abs(offset) % 60);
  //   return (
  //     `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}` +
  //     `T${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}` +
  //     `.${ms}${sign}${h}:${m}`
  //   );
  // };

  // const signingTime = getSigningTime();
  // const ds = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';
  // const xades = 'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"';

  // const sigNum = getRandomNumber();
  // let signedProps = `<xades:SignedProperties Id="Signature${sigNum}-SignedProperties${sigNum}">`;
  // signedProps += `<xades:SignedSignatureProperties>`;
  // signedProps += `<xades:SigningTime>${signingTime}</xades:SigningTime>`;
  // signedProps += `<xades:SigningCertificate><xades:Cert>`;
  // signedProps += `<xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`;
  // signedProps += `<ds:DigestValue>${certDigest}</ds:DigestValue></xades:CertDigest>`;
  // signedProps += `</xades:Cert></xades:SigningCertificate>`;
  // signedProps += `</xades:SignedSignatureProperties>`;
  // signedProps += `</xades:SignedProperties>`;

  // // Digest of the XML to sign
  // const xmlToSign = xml.replace('<?xml version="1.0" encoding="UTF-8"?>', "");
  // const xmlDigest = sha256Base64(xmlToSign, "utf8");

  // // Build SignedInfo
  // let signedInfo = `<ds:SignedInfo>`;
  // signedInfo += `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>`;
  // signedInfo += `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`;
  // signedInfo += `<ds:Reference Id="Reference-ID${sigNum}" URI="#comprobante">`;
  // signedInfo += `<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>`;
  // signedInfo += `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`;
  // signedInfo += `<ds:DigestValue>${xmlDigest}</ds:DigestValue>`;
  // signedInfo += `</ds:Reference>`;
  // signedInfo += `<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature${sigNum}-SignedProperties${sigNum}">`;
  // signedInfo += `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`;
  // // Digest of SignedProperties
  // const signedPropsDigest = sha256Base64(
  //   signedProps.replace(
  //     "<xades:SignedProperties",
  //     `<xades:SignedProperties ${ds} ${xades}`
  //   ),
  //   "utf8"
  // );
  // signedInfo += `<ds:DigestValue>${signedPropsDigest}</ds:DigestValue>`;
  // signedInfo += `</ds:Reference>`;
  // signedInfo += `</ds:SignedInfo>`;

  // // Sign the SignedInfo
  // const privateKeyBag = keyBags[
  //   (forge as any).oids.pkcs8ShroudedKeyBag
  // ]![0] as any;
  // const privateKey = privateKeyBag.key;
  // const md = forge.md.sha256.create();
  // md.update(
  //   signedInfo.replace("<ds:SignedInfo", `<ds:SignedInfo ${ds} ${xades}`),
  //   "utf8"
  // );
  // const signatureValue = Buffer.from(privateKey.sign(md), "binary").toString(
  //   "base64"
  // );

  // // Build the full Signature element
  // let signatureXml = `<ds:Signature ${ds} ${xades} Id="Signature${sigNum}">`;
  // signatureXml += signedInfo;
  // signatureXml += `<ds:SignatureValue>${signatureValue}</ds:SignatureValue>`;
  // signatureXml += `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${pem}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`;
  // signatureXml += `<ds:Object><xades:QualifyingProperties Target="#Signature${sigNum}">${signedProps}</xades:QualifyingProperties></ds:Object>`;
  // signatureXml += `</ds:Signature>`;

  // // Inject the Signature before the closing root tag
  // return xml.replace(/(<\/[^>]+>)$/, signatureXml + "$1");
}
