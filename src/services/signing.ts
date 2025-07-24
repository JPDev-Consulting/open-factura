import * as forge from "node-forge";
import { readFileSync } from "fs";
import fetch from "node-fetch";

export function getP12FromLocalFile(path: string) {
  const file = readFileSync(path);
  const buffer = file.buffer.slice(
    file.byteOffset,
    file.byteOffset + file.byteLength
  );
  return buffer;
}

export async function getP12FromUrl(url: string) {
  const file = await fetch(url)
    .then((response) => response.arrayBuffer())
    .then((data) => data);
  return file;
}

export function getXMLFromLocalFile(path: string) {
  const file = readFileSync(path, "utf8");
  return file;
}

export async function getXMLFromLocalUrl(url: string) {
  const file = await fetch(url)
    .then((response) => response.text())
    .then((data) => data);
  return file;
}

function sha256Base64(text: string, encoding: forge.Encoding = "utf8") {
  const md = forge.md.sha256.create();
  md.update(text, encoding);
  const hashHex = md.digest().toHex();
  return Buffer.from(hashHex, "hex").toString("base64");
}

function hexToBase64(hex: string) {
  hex = hex.padStart(hex.length + (hex.length % 2), "0");
  const bytes = hex.match(/.{2}/g)!.map((byte) => parseInt(byte, 16));
  return btoa(String.fromCharCode(...bytes));
}

function bigIntToBase64(bigInt: number) {
  const hex = bigInt.toString(16);
  const hexPairs = hex.match(/\w{2}/g);
  const bytes = hexPairs!.map((pair) => parseInt(pair, 16));
  const byteString = String.fromCharCode(...bytes);
  const base64 = btoa(byteString);
  const formatedBase64 = base64.match(/.{1,76}/g)!.join("\n");
  return formatedBase64;
}

function getRandomNumber(min = 990, max = 9999) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

export async function signXml(
  p12Data: ArrayBuffer,
  p12Password: string,
  xmlData: string
) {
  const arrayBuffer = p12Data;
  let xml = xmlData;
  xml = xml.replace(/\s+/g, " ");
  xml = xml.trim();
  xml = xml.replace(/(?<=\>)(\r?\n)|(\r?\n)(?=\<\/)/g, "");
  xml = xml.trim();
  xml = xml.replace(/(?<=\>)(\s*)/g, "");

  const arrayUint8 = new Uint8Array(arrayBuffer);
  const base64 = forge.util.binary.base64.encode(arrayUint8);
  const der = forge.util.decode64(base64);

  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, p12Password);
  const pkcs8Bags = p12.getBags({
    bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
  });
  const certBags = p12.getBags({
    bagType: forge.pki.oids.certBag,
  });
  const certBag = certBags[(forge as any).oids.certBag];

  const friendlyName = certBag![1].attributes.friendlyName[0];

  let certificate;
  let pkcs8;
  let issuerName = "";

  const cert = certBag!.reduce((prev, curr) => {
    const attributes = curr.cert!.extensions;
    return attributes.length > prev.cert!.extensions.length ? curr : prev;
  });

  const issueAttributes = cert.cert!.issuer.attributes;

  issuerName = issueAttributes
    .reverse()
    .map((attribute) => {
      return `${attribute.shortName}=${attribute.value}`;
    })
    .join(", ");

  if (/BANCO CENTRAL/i.test(friendlyName)) {
    let keys = pkcs8Bags[(forge as any).oids.pkcs8ShroudedKeyBag];
    for (let i = 0; i < keys!.length; i++) {
      const element = keys![i];
      let name = element.attributes.friendlyName[0];
      if (/Signing Key/i.test(name)) {
        pkcs8 = pkcs8Bags[(forge as any).oids.pkcs8ShroudedKeyBag[i]];
      }
    }
  }

  if (/SECURITY DATA/i.test(friendlyName)) {
    pkcs8 = pkcs8Bags[(forge as any).oids.pkcs8ShroudedKeyBag]![0];
  }

  certificate = cert.cert;

  const notBefore = certificate!.validity["notBefore"];
  const notAfter = certificate!.validity["notAfter"];
  const date = new Date();

  if (date < notBefore || date > notAfter) {
    throw new Error("Expired certificate");
  }

  const key = (pkcs8 as any).key ?? (pkcs8 as any).asn1;
  const certificateX509_pem = forge.pki.certificateToPem(certificate!);

  let certificateX509 = certificateX509_pem;
  certificateX509 = certificateX509.substr(certificateX509.indexOf("\n"));
  certificateX509 = certificateX509.substr(
    0,
    certificateX509.indexOf("\n-----END CERTIFICATE-----")
  );

  certificateX509 = certificateX509
    .replace(/\r?\n|\r/g, "")
    .replace(/([^\0]{76})/g, "$1\n");

  const certificateX509_asn1 = forge.pki.certificateToAsn1(certificate!);
  const certificateX509_der = forge.asn1.toDer(certificateX509_asn1).getBytes();
  const hash_certificateX509_der = sha256Base64(certificateX509_der, "utf8");
  const certificateX509_serialNumber = parseInt(certificate!.serialNumber, 16);

  const exponent = hexToBase64(key.e.data[0].toString(16));
  const modulus = bigIntToBase64(key.n);

  xml = xml.replace(/\t|\r/g, "");

  const sha1_xml = sha256Base64(
    xml.replace('<?xml version="1.0" encoding="UTF-8"?>', ""),
    "utf8"
  );

  const nameSpaces =
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"';

  const certificateNumber = getRandomNumber();
  const signatureNumber = getRandomNumber();
  const signedPropertiesNumber = getRandomNumber();
  const signedInfoNumber = getRandomNumber();
  const signedPropertiesIdNumber = getRandomNumber();
  const referenceIdNumber = getRandomNumber();
  const signatureValueNumber = getRandomNumber();
  const objectNumber = getRandomNumber();

  function getSigningTime(): string {
    const dt = new Date();
    const pad = (n: number, z = 2) => ("00" + n).slice(-z);
    const ms = ("00" + dt.getMilliseconds()).slice(-3);
    const offset = -dt.getTimezoneOffset();
    const sign = offset >= 0 ? "+" : "-";
    const h = pad(Math.floor(Math.abs(offset) / 60));
    const m = pad(Math.abs(offset) % 60);
    return (
      `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}` +
      `T${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}` +
      `.${ms}${sign}${h}:${m}`
    );
  }

  const isoDateTime = getSigningTime();

  let signedProperties = "";
  signedProperties +=
    '<xades:SignedProperties Id="Signature' +
    signatureNumber +
    "-SignedProperties" +
    signedPropertiesNumber +
    '">';

  signedProperties += "<xades:SignedSignatureProperties>";
  signedProperties += "<xades:SigningTime>";
  signedProperties += isoDateTime;
  signedProperties += "</xades:SigningTime>";
  signedProperties += "<xades:SigningCertificate>";
  signedProperties += "<xades:Cert>";
  signedProperties += "<xades:CertDigest>";
  signedProperties +=
    '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>';
  signedProperties += "<ds:DigestValue>";
  signedProperties += hash_certificateX509_der;
  signedProperties += "</ds:DigestValue>";
  signedProperties += "</xades:CertDigest>";
  signedProperties += "<xades:IssuerSerial>";
  signedProperties += "<ds:X509IssuerName>";
  signedProperties += issuerName;
  signedProperties += "</ds:X509IssuerName>";
  signedProperties += "<ds:X509SerialNumber>";
  signedProperties += certificateX509_serialNumber;
  signedProperties += "</ds:X509SerialNumber>";
  signedProperties += "</xades:IssuerSerial>";
  signedProperties += "</xades:Cert>";
  signedProperties += "</xades:SigningCertificate>";
  signedProperties += "</xades:SignedSignatureProperties>";

  signedProperties += "<xades:SignedDataObjectProperties>";
  signedProperties +=
    '<xades:DataObjectFormat ObjectReference="#Reference-ID=' +
    referenceIdNumber +
    '">';
  signedProperties += "<xades:Description>";
  signedProperties += "FIRMA DIGITAL SRI";
  signedProperties += "</xades:Description>";
  signedProperties += "<xades:MimeType>";
  signedProperties += "text/xml";
  signedProperties += "</xades:MimeType>";
  // <xades:Encoding>UTF-8</xades:Encoding>
  signedProperties += "<xades:Encoding>";
  signedProperties += "UTF-8";
  signedProperties += "</xades:Encoding>";
  signedProperties += "</xades:DataObjectFormat>";
  signedProperties += "</xades:SignedDataObjectProperties>";
  signedProperties += "</xades:SignedProperties>";

  const sha1SignedProperties = sha256Base64(
    signedProperties.replace(
      "<xades:SignedProperties",
      "<xades:SignedProperties " + nameSpaces
    ),
    "utf8"
  );

  let keyInfo = "";
  keyInfo += '<ds:KeyInfo Id="Certificate' + certificateNumber + '">';
  keyInfo += "\n<ds:X509Data>";
  keyInfo += "\n<ds:X509Certificate>\n";
  keyInfo += certificateX509;
  keyInfo += "\n</ds:X509Certificate>";
  keyInfo += "\n</ds:X509Data>";
  keyInfo += "\n</ds:KeyInfo>";

  let signedInfo = "";
  signedInfo += "<ds:SignedInfo>";
  signedInfo +=
    '\n<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>';
  signedInfo +=
    '\n<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>';

  // 1️⃣ Referencia al comprobante
  signedInfo +=
    '\n<ds:Reference Id="Reference-ID' +
    referenceIdNumber +
    '" URI="#comprobante">';
  signedInfo += "\n<ds:Transforms>";
  signedInfo +=
    '\n<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>';
  signedInfo += "\n</ds:Transforms>";
  signedInfo +=
    '\n<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>';
  signedInfo += "\n<ds:DigestValue>";
  signedInfo += sha1_xml;
  signedInfo += "</ds:DigestValue>";
  signedInfo += "\n</ds:Reference>";

  // 2️⃣ Referencia a SignedProperties
  signedInfo +=
    '\n<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature' +
    signatureNumber +
    "-SignedProperties" +
    signedPropertiesNumber +
    '">';
  signedInfo +=
    '\n<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>';
  signedInfo += "\n<ds:DigestValue>";
  signedInfo += sha1SignedProperties;
  signedInfo += "</ds:DigestValue>";
  signedInfo += "\n</ds:Reference>";

  signedInfo += "\n</ds:SignedInfo>";

  const canonicalizedSignedInfo = signedInfo.replace(
    "<ds:SignedInfo",
    "<ds:SignedInfo " + nameSpaces
  );

  const md = forge.md.sha256.create();
  md.update(canonicalizedSignedInfo, "utf8");
  const signature = Buffer.from(key.sign(md), "binary")
    .toString("base64")
    .match(/.{1,76}/g)!
    .join("\n");

  let xadesBes = "";
  xadesBes +=
    "<ds:Signature " + nameSpaces + ' Id="Signature' + signatureNumber + '">';
  xadesBes += "\n" + signedInfo;

  xadesBes +=
    '\n<ds:SignatureValue Id="SignatureValue' + signatureValueNumber + '">\n';

  xadesBes += signature;
  xadesBes += "\n</ds:SignatureValue>";
  xadesBes += "\n" + keyInfo;
  xadesBes += "\n<ds:Object>";

  xadesBes +=
    "<xades:QualifyingProperties " +
    'Target="#Signature' +
    signatureNumber +
    '" ' +
    'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" ' +
    'xmlns:xades141="http://uri.etsi.org/01903/v1.4.1#">';
  xadesBes += signedProperties;

  xadesBes += "</xades:QualifyingProperties>";
  xadesBes += "</ds:Object>";
  xadesBes += "</ds:Signature>";

  return xml.replace(/(<[^<]+)$/, xadesBes + "$1");
}
