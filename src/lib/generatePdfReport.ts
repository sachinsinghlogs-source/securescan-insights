import jsPDF from 'jspdf';
import type { Scan } from '@/types/database';

export function generatePdfReport(scan: Scan) {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  
  // Colors
  const primaryColor: [number, number, number] = [0, 255, 136];
  const dangerColor: [number, number, number] = [255, 71, 87];
  const warningColor: [number, number, number] = [255, 193, 7];
  const successColor: [number, number, number] = [0, 255, 136];
  const darkBg: [number, number, number] = [10, 15, 20];
  const textColor: [number, number, number] = [255, 255, 255];
  const mutedColor: [number, number, number] = [140, 140, 140];

  // Background
  doc.setFillColor(...darkBg);
  doc.rect(0, 0, pageWidth, doc.internal.pageSize.getHeight(), 'F');

  let yPos = 20;

  // Header
  doc.setFillColor(15, 20, 30);
  doc.rect(0, 0, pageWidth, 45, 'F');
  
  doc.setTextColor(...primaryColor);
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text('SecureScan', 20, yPos + 5);
  
  doc.setTextColor(...mutedColor);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text('Security Assessment Report', 20, yPos + 15);
  
  // Report date
  doc.setTextColor(...textColor);
  doc.setFontSize(9);
  doc.text(`Generated: ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}`, pageWidth - 20, yPos + 5, { align: 'right' });

  yPos = 55;

  // Target URL Section
  doc.setFillColor(20, 25, 35);
  doc.roundedRect(15, yPos, pageWidth - 30, 30, 3, 3, 'F');
  
  doc.setTextColor(...mutedColor);
  doc.setFontSize(9);
  doc.text('TARGET URL', 22, yPos + 10);
  
  doc.setTextColor(...textColor);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  
  const hostname = (() => {
    try {
      return new URL(scan.target_url).hostname;
    } catch {
      return scan.target_url;
    }
  })();
  doc.text(hostname, 22, yPos + 22);

  yPos += 40;

  // Risk Assessment Section
  doc.setFillColor(20, 25, 35);
  doc.roundedRect(15, yPos, pageWidth - 30, 55, 3, 3, 'F');

  doc.setTextColor(...mutedColor);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('RISK ASSESSMENT', 22, yPos + 12);

  // Risk Level Badge
  const riskColor = scan.risk_level === 'low' ? successColor :
                    scan.risk_level === 'medium' ? warningColor : dangerColor;
  
  doc.setFillColor(...riskColor);
  const riskText = (scan.risk_level || 'Unknown').toUpperCase();
  const riskWidth = doc.getTextWidth(riskText) + 16;
  doc.roundedRect(22, yPos + 18, riskWidth, 10, 2, 2, 'F');
  
  doc.setTextColor(...darkBg);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text(riskText, 30, yPos + 25);

  // Risk Score
  doc.setTextColor(...textColor);
  doc.setFontSize(32);
  doc.text(`${scan.risk_score ?? 0}`, pageWidth - 50, yPos + 32, { align: 'center' });
  
  doc.setTextColor(...mutedColor);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('/100', pageWidth - 28, yPos + 32);
  doc.text('Risk Score', pageWidth - 50, yPos + 42, { align: 'center' });

  // Risk score bar
  doc.setFillColor(30, 35, 45);
  doc.roundedRect(22, yPos + 40, 100, 6, 2, 2, 'F');
  doc.setFillColor(...riskColor);
  doc.roundedRect(22, yPos + 40, Math.max((scan.risk_score ?? 0), 2), 6, 2, 2, 'F');

  yPos += 65;

  // SSL Certificate Section
  doc.setFillColor(20, 25, 35);
  doc.roundedRect(15, yPos, (pageWidth - 35) / 2, 55, 3, 3, 'F');

  doc.setTextColor(...mutedColor);
  doc.setFontSize(9);
  doc.text('SSL CERTIFICATE', 22, yPos + 12);

  const sslColor = scan.ssl_valid ? successColor : dangerColor;
  doc.setTextColor(...sslColor);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text(scan.ssl_valid ? '✓ Valid' : '✗ Invalid', 22, yPos + 26);

  doc.setTextColor(...mutedColor);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  
  if (scan.ssl_issuer) {
    doc.text(`Issuer: ${scan.ssl_issuer}`, 22, yPos + 38);
  }
  if (scan.ssl_expiry_date) {
    doc.text(`Expires: ${new Date(scan.ssl_expiry_date).toLocaleDateString()}`, 22, yPos + 48);
  }

  // Headers Score Section
  const headersX = 20 + (pageWidth - 35) / 2;
  doc.setFillColor(20, 25, 35);
  doc.roundedRect(headersX, yPos, (pageWidth - 35) / 2, 55, 3, 3, 'F');

  doc.setTextColor(...mutedColor);
  doc.setFontSize(9);
  doc.text('SECURITY HEADERS', headersX + 7, yPos + 12);

  const headersScore = scan.headers_score ?? 0;
  const headersColor = headersScore >= 70 ? successColor :
                       headersScore >= 40 ? warningColor : dangerColor;
  
  doc.setTextColor(...headersColor);
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text(`${headersScore}`, headersX + 7, yPos + 35);
  
  doc.setTextColor(...mutedColor);
  doc.setFontSize(12);
  doc.text('/100', headersX + 35, yPos + 35);

  yPos += 65;

  // Present Headers
  if (scan.present_headers && scan.present_headers.length > 0) {
    doc.setFillColor(20, 25, 35);
    const presentHeight = Math.ceil(scan.present_headers.length / 2) * 12 + 25;
    doc.roundedRect(15, yPos, pageWidth - 30, presentHeight, 3, 3, 'F');

    doc.setTextColor(...successColor);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text('✓ PRESENT HEADERS', 22, yPos + 12);

    doc.setTextColor(...textColor);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    
    let headerY = yPos + 22;
    scan.present_headers.forEach((header, i) => {
      const xOffset = i % 2 === 0 ? 22 : pageWidth / 2;
      if (i % 2 === 0 && i > 0) headerY += 12;
      doc.text(`• ${header}`, xOffset, headerY);
    });

    yPos += presentHeight + 5;
  }

  // Missing Headers
  if (scan.missing_headers && scan.missing_headers.length > 0) {
    doc.setFillColor(20, 25, 35);
    const missingHeight = Math.ceil(scan.missing_headers.length / 2) * 12 + 25;
    doc.roundedRect(15, yPos, pageWidth - 30, missingHeight, 3, 3, 'F');

    doc.setTextColor(...warningColor);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text('⚠ MISSING HEADERS', 22, yPos + 12);

    doc.setTextColor(...textColor);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    
    let headerY = yPos + 22;
    scan.missing_headers.forEach((header, i) => {
      const xOffset = i % 2 === 0 ? 22 : pageWidth / 2;
      if (i % 2 === 0 && i > 0) headerY += 12;
      doc.text(`• ${header}`, xOffset, headerY);
    });

    yPos += missingHeight + 5;
  }

  // Detected Technologies
  if (scan.detected_technologies && scan.detected_technologies.length > 0) {
    doc.setFillColor(20, 25, 35);
    const techHeight = Math.ceil(scan.detected_technologies.length / 3) * 12 + 25;
    doc.roundedRect(15, yPos, pageWidth - 30, techHeight, 3, 3, 'F');

    doc.setTextColor(...mutedColor);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text('DETECTED TECHNOLOGIES', 22, yPos + 12);

    doc.setTextColor(...textColor);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    
    let techY = yPos + 22;
    scan.detected_technologies.forEach((tech, i) => {
      const col = i % 3;
      const xOffset = 22 + col * 60;
      if (col === 0 && i > 0) techY += 12;
      doc.text(`• ${tech}`, xOffset, techY);
    });

    yPos += techHeight + 5;
  }

  // Footer
  const footerY = doc.internal.pageSize.getHeight() - 15;
  doc.setDrawColor(30, 35, 45);
  doc.line(15, footerY - 5, pageWidth - 15, footerY - 5);
  
  doc.setTextColor(...mutedColor);
  doc.setFontSize(7);
  doc.setFont('helvetica', 'normal');
  doc.text('This report was generated by SecureScan. For informational purposes only.', pageWidth / 2, footerY, { align: 'center' });
  doc.text(`Scan ID: ${scan.id}`, pageWidth / 2, footerY + 5, { align: 'center' });

  // Save
  const filename = `securescan-report-${hostname}-${new Date().toISOString().split('T')[0]}.pdf`;
  doc.save(filename);
}
