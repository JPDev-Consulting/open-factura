import { create } from "xmlbuilder2";
import { Invoice, InvoiceInput } from "../baseData/invoice/invoice";
import { generateAccessKey } from "../utils/utils";

export function generateInvoiceXml(invoice: Invoice) {
  const document = create({ version: "1.0", encoding: "UTF-8" }, invoice);
  const xml = document.end({ prettyPrint: false });
  return xml;
}

export function generateInvoice(invoiceData: InvoiceInput) {
  // Parse fechaEmision as DD/MM/YYYY into a Date object
  const [day, month, year] = invoiceData.infoFactura.fechaEmision
    .split("/")
    .map(Number);
  const dateObj = new Date(year, month - 1, day);

  const accessKey = generateAccessKey({
    date: dateObj,
    codDoc: invoiceData.infoTributaria.codDoc,
    ruc: invoiceData.infoTributaria.ruc,
    environment: invoiceData.infoTributaria.ambiente,
    establishment: invoiceData.infoTributaria.estab,
    emissionPoint: invoiceData.infoTributaria.ptoEmi,
    sequential: invoiceData.infoTributaria.secuencial,
  });

  const invoice: Invoice = {
    factura: {
      "@id": "comprobante",
      "@version": "1.1.0",
      infoTributaria: {
        ambiente: invoiceData.infoTributaria.ambiente,
        tipoEmision: invoiceData.infoTributaria.tipoEmision,
        razonSocial: invoiceData.infoTributaria.razonSocial,
        nombreComercial: invoiceData.infoTributaria.nombreComercial,
        ruc: invoiceData.infoTributaria.ruc,
        claveAcceso: accessKey,
        codDoc: invoiceData.infoTributaria.codDoc,
        estab: invoiceData.infoTributaria.estab,
        ptoEmi: invoiceData.infoTributaria.ptoEmi,
        secuencial: invoiceData.infoTributaria.secuencial,
        dirMatriz: invoiceData.infoTributaria.dirMatriz,
      },
      infoFactura: invoiceData.infoFactura,
      detalles: invoiceData.detalles,
    },
  };

  return { invoice, accessKey };
}
