/**
 * pdfGenerator.js
 * Generate PDF invoices for billing
 * Uses PDFKit library
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

/**
 * Generate hospital invoice PDF
 * @param {Object} billingData - Billing record with patient, items, amounts
 * @param {String} outputPath - Where to save the PDF
 * @returns {Promise<String>} - Path to generated PDF
 */
async function generateInvoicePDF(billingData, outputPath) {
  return new Promise((resolve, reject) => {
    try {
      // Create output directory if not exists
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      // Create PDF document
      const doc = new PDFDocument({
        size: 'A4',
        margin: 40,
        buffered: false
      });

      const stream = fs.createWriteStream(outputPath);
      doc.pipe(stream);

      // Header
      doc
        .fontSize(20)
        .font('Helvetica-Bold')
        .text('HOSPITAL INVOICE', { align: 'center' })
        .moveDown(0.3);

      doc
        .fontSize(10)
        .font('Helvetica')
        .text('HealthCare Center Hospital', { align: 'center' })
        .text('Emergency: +1-234-567-8900 | Web: www.hospital.com', { align: 'center' })
        .moveDown(0.5);

      // Invoice info
      const invoiceNo = `INV-${billingData.id}`;
      const invoiceDate = new Date(billingData.created_at || Date.now()).toLocaleDateString();

      doc
        .fontSize(9)
        .font('Helvetica')
        .text(`Invoice No: ${invoiceNo}`)
        .text(`Date: ${invoiceDate}`)
        .text(`Status: ${billingData.status || 'Pending'}`);

      // Horizontal line
      doc.moveTo(40, doc.y + 10).lineTo(555, doc.y + 10).stroke();
      doc.moveDown(1);

      // Patient & Doctor Info
      doc
        .fontSize(10)
        .font('Helvetica-Bold')
        .text('PATIENT INFORMATION', { underline: true })
        .moveDown(0.2);

      doc
        .fontSize(9)
        .font('Helvetica')
        .text(`Patient Name: ${billingData.patient_name || 'N/A'}`)
        .text(`Patient ID: ${billingData.patient_id || 'N/A'}`)
        .text(`Department: ${billingData.department || 'N/A'}`)
        .text(`Doctor: ${billingData.doctor_name || 'N/A'}`)
        .text(`Admission Date: ${formatDate(billingData.admitted_date)}`)
        .text(`Discharge Date: ${formatDate(billingData.discharged_date)}`)
        .moveDown(0.5);

      // Horizontal line
      doc.moveTo(40, doc.y).lineTo(555, doc.y).stroke();
      doc.moveDown(0.5);

      // Charge Items Table Header
      doc
        .fontSize(10)
        .font('Helvetica-Bold')
        .text('CHARGES', { underline: true })
        .moveDown(0.3);

      // Table header
      const tableTop = doc.y;
      const col1 = 40;
      const col2 = 200;
      const col3 = 350;
      const col4 = 430;
      const col5 = 520;

      doc
        .fontSize(9)
        .font('Helvetica-Bold');

      doc.text('Description', col1, tableTop);
      doc.text('Category', col2, tableTop);
      doc.text('Qty', col3, tableTop);
      doc.text('Unit Price', col4, tableTop);
      doc.text('Total', col5, tableTop, { align: 'right' });

      // Table body
      let currentY = tableTop + 25;
      doc.fontSize(9).font('Helvetica');

      const services = billingData.billing_services || [];
      services.forEach((service, idx) => {
        const lineHeight = 20;

        if (currentY > 700) {
          doc.addPage();
          currentY = 40;
        }

        doc.text(
          service.description || service.service_name || 'Service',
          col1,
          currentY,
          { width: 150, height: lineHeight }
        );
        doc.text(service.category || 'General', col2, currentY);
        doc.text((service.quantity || 1).toString(), col3, currentY);
        doc.text(`$${(service.unit_price || 0).toFixed(2)}`, col4, currentY);
        doc.text(`$${(service.total || 0).toFixed(2)}`, col5, currentY, { align: 'right' });

        currentY += lineHeight;
      });

      // Spacing before totals
      currentY += 10;

      // Totals Section
      const subtotal = billingData.subtotal || calculateSubtotal(services);
      const discount = billingData.discount || 0;
      const tax = billingData.tax || (subtotal * 0.05);
      const insurance = billingData.insurance_deduction || 0;
      const totalAmount = billingData.total_amount || (subtotal - discount + tax - insurance);
      const amountPaid = billingData.amount_paid || 0;
      const balanceDue = totalAmount - amountPaid;

      if (currentY > 700) {
        doc.addPage();
        currentY = 40;
      }

      doc.moveTo(40, currentY).lineTo(555, currentY).stroke();
      currentY += 15;

      doc
        .fontSize(10)
        .font('Helvetica-Bold')
        .text('SUMMARY', 40, currentY);

      currentY += 25;
      doc.fontSize(9).font('Helvetica');

      const summaryLines = [
        { label: 'Subtotal:', amount: subtotal },
        { label: 'Discount:', amount: -discount },
        { label: 'Tax (5%):', amount: tax },
        { label: 'Insurance Deduction:', amount: -insurance }
      ];

      summaryLines.forEach(line => {
        if (currentY > 720) {
          doc.addPage();
          currentY = 40;
        }
        doc.text(line.label, 350, currentY);
        doc.text(`$${Math.abs(line.amount).toFixed(2)}`, 500, currentY);
        currentY += 20;
      });

      // Total amount
      doc.moveTo(340, currentY).lineTo(555, currentY).stroke();
      currentY += 15;

      doc
        .fontSize(11)
        .font('Helvetica-Bold')
        .text('TOTAL AMOUNT DUE:', 350, currentY)
        .text(`$${totalAmount.toFixed(2)}`, 500, currentY, { align: 'right' });

      currentY += 30;

      // Payment Info
      doc
        .fontSize(10)
        .font('Helvetica-Bold')
        .text('PAYMENT DETAILS', 40, currentY);

      currentY += 25;
      doc.fontSize(9).font('Helvetica');

      doc.text(`Amount Paid: $${amountPaid.toFixed(2)}`, 40, currentY);
      currentY += 20;
      doc.text(
        `Balance Due: $${Math.max(0, balanceDue).toFixed(2)}`,
        40,
        currentY,
        { textColor: balanceDue > 0 ? '#DC2626' : '#059669' }
      );

      if (billingData.payment_method) {
        currentY += 20;
        doc.text(`Payment Method: ${billingData.payment_method}`, 40, currentY);
      }

      if (billingData.notes) {
        currentY += 25;
        doc
          .fontSize(10)
          .font('Helvetica-Bold')
          .text('NOTES:', 40, currentY);
        currentY += 20;
        doc
          .fontSize(9)
          .font('Helvetica')
          .text(billingData.notes, 40, currentY, { width: 475 });
      }

      // Footer
      doc.moveTo(40, 760).lineTo(555, 760).stroke();
      doc
        .fontSize(8)
        .font('Helvetica')
        .text(
          'Thank you for using our services. For inquiries, please contact billing@hospital.com',
          40,
          770,
          { align: 'center' }
        );

      doc.text(
        `Generated on: ${new Date().toLocaleString()}`,
        40,
        785,
        { align: 'center' }
      );

      // Finalize
      doc.end();

      stream.on('finish', () => {
        console.log(`[PDF] Invoice generated successfully: ${outputPath}`);
        resolve(outputPath);
      });

      stream.on('error', (err) => {
        console.error(`[PDF] Stream error: ${err.message}`);
        reject(err);
      });

      doc.on('error', (err) => {
        console.error(`[PDF] Document error: ${err.message}`);
        reject(err);
      });

    } catch (err) {
      console.error(`[PDF] Error: ${err.message}`);
      reject(err);
    }
  });
}

/**
 * Calculate subtotal from services array
 */
function calculateSubtotal(services) {
  return services.reduce((sum, service) => sum + (service.total || 0), 0);
}

/**
 * Format date for display
 */
function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  try {
    return new Date(dateStr).toLocaleDateString();
  } catch {
    return dateStr;
  }
}

/**
 * Generate lab report PDF
 * @param {Object} labData - Lab test data with results
 * @param {String} outputPath - Where to save the PDF
 * @returns {Promise<String>} - Path to generated PDF
 */
async function generateLabReportPDF(labData, outputPath) {
  return new Promise((resolve, reject) => {
    try {
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const doc = new PDFDocument({
        size: 'A4',
        margin: 40,
        buffered: false
      });

      const stream = fs.createWriteStream(outputPath);
      doc.pipe(stream);

      // Header
      doc
        .fontSize(20)
        .font('Helvetica-Bold')
        .text('LABORATORY TEST REPORT', { align: 'center' })
        .moveDown(0.3);

      doc
        .fontSize(10)
        .font('Helvetica')
        .text('HealthCare Center Laboratory', { align: 'center' })
        .text('Accredited Medical Laboratory', { align: 'center' })
        .moveDown(0.5);

      // Report ID and Date
      doc
        .fontSize(9)
        .text(`Report ID: LAB-${labData.id}`, { align: 'left' })
        .text(`Date: ${new Date(labData.completed_at || Date.now()).toLocaleDateString()}`, { align: 'left' })
        .text(`Status: ${labData.result_status || 'Completed'}`, { align: 'left' });

      doc.moveTo(40, doc.y + 10).lineTo(555, doc.y + 10).stroke();
      doc.moveDown(1);

      // Patient Info
      doc
        .fontSize(10)
        .font('Helvetica-Bold')
        .text('PATIENT INFORMATION', { underline: true })
        .moveDown(0.2);

      doc
        .font('Helvetica')
        .fontSize(9)
        .text(`Name: ${labData.patient_name || 'N/A'}`)
        .text(`Test: ${labData.test_name}`)
        .text(`Ordered By: ${labData.requested_by || 'N/A'}`)
        .text(`Date Ordered: ${formatDate(labData.created_at)}`)
        .moveDown(1);

      // Test Results
      doc
        .fontSize(10)
        .font('Helvetica-Bold')
        .text('TEST RESULTS', { underline: true })
        .moveDown(0.5);

      // Results table header
      const tableTop = doc.y;
      const col1 = 50;
      const col2 = 200;
      const col3 = 320;
      const col4 = 420;

      doc
        .fontSize(9)
        .font('Helvetica-Bold')
        .text('Parameter', col1, tableTop)
        .text('Result', col2, tableTop)
        .text('Unit', col3, tableTop)
        .text('Reference', col4, tableTop);

      doc.moveTo(40, doc.y + 5).lineTo(555, doc.y + 5).stroke();
      doc.moveDown(0.5);

      // Results rows
      const resultData = labData.result_data || {};
      let yPosition = doc.y;

      doc.font('Helvetica').fontSize(9);

      Object.entries(resultData).forEach(([key, value]) => {
        if (key !== 'result_status' && key !== 'technician_notes' && key !== 'entered_by' && key !== 'entered_at') {
          const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          doc
            .text(displayKey, col1, yPosition)
            .text(String(value), col2, yPosition);
          yPosition = doc.y + 5;
        }
      });

      doc.moveDown(1);

      // Result Status Box
      const statusColor = resultData.result_status === 'Normal' ? '#22c55e' :
                          resultData.result_status === 'Abnormal' ? '#eab308' : '#ef4444';

      doc
        .fontSize(10)
        .font('Helvetica-Bold')
        .text(`Overall Result: ${resultData.result_status || 'Normal'}`, {
          continued: false
        });

      doc.moveDown(1);

      // Technician Notes
      if (resultData.technician_notes) {
        doc
          .fontSize(10)
          .font('Helvetica-Bold')
          .text('TECHNICIAN NOTES', { underline: true })
          .moveDown(0.2);

        doc
          .font('Helvetica')
          .fontSize(9)
          .text(resultData.technician_notes);

        doc.moveDown(1);
      }

      // Footer
      doc.moveTo(40, 720).lineTo(555, 720).stroke();
      doc
        .fontSize(8)
        .font('Helvetica')
        .text('This report is electronically generated and does not require a signature.', 40, 730, { align: 'center' })
        .text(`Generated on: ${new Date().toLocaleString()}`, 40, 745, { align: 'center' })
        .text(`Technician: ${resultData.entered_by || 'Lab Technician'}`, 40, 760, { align: 'center' });

      doc.end();

      stream.on('finish', () => {
        console.log(`[PDF] Lab report generated: ${outputPath}`);
        resolve(outputPath);
      });

      stream.on('error', reject);
      doc.on('error', reject);

    } catch (err) {
      reject(err);
    }
  });
}

module.exports = {
  generateInvoicePDF,
  generateLabReportPDF
};
